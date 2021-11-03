from datetime import datetime, timedelta
from logging import currentframe

from flask import Flask, request, jsonify, current_app, g
from flask.json import JSONEncoder
from flask.wrappers import Response
from sqlalchemy import create_engine, text
from functools import wraps
import ast
import bcrypt
import jwt


class SetEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return JSONEncoder.default(self, obj)

def create_app(test_config = None):
    app = Flask(__name__)

    if test_config is None:
        app.config.from_pyfile("config.py")
    else:
        app.config.update(test_config)

    database = create_engine(app.config['DB_URL'], encoding='utf-8', max_overflow=0)
    app.database = database
    app.json_encoder = SetEncoder
    
    def masterLoginRequired(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            accessToken = request.headers.get('Authorization')
            if accessToken is None:
                return Response(status=401)
            try:
                payload = jwt.decode(accessToken, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            except jwt.InvalidTokenError:
                payload = None
            
            if payload and payload['role'] == 'master':
                g.user_role = payload['role']
                g.user_id = payload['id']
                g.user = current_app.database.execute(text("SELECT * FROM users WHERE id = :id"), {'id': g.user_id}).fetchone()
                return f(*args, **kwargs)
            else:
                return Response(status=401)
        return decorator

    
    def loginRequired(f):
        @wraps(f)
        def decorater(*args, **kwargs):
            accessToken = request.headers.get('Authorization')
            if accessToken is None:
                return Response(status=401)
            try:
                payload = jwt.decode(accessToken, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            except jwt.InvalidTokenError:
                payload = None
            
            if payload is None:
                return Response(status=401)

            user_id = payload['id']
            g.user_id = user_id
            if user_id:
                g.user = current_app.database.execute(text('SELECT id, name, email, profile FROM users WHERE id = :id'), {'id': user_id}).fetchone()
            else:
                g.user = None
            
            return f(*args, **kwargs)
        return decorater


    @app.route('/signUp', methods=['POST'])
    def signUp():
        newUser = request.json
        newUser['password'] = bcrypt.hashpw(newUser['password'].encode('UTF-8'), bcrypt.gensalt())
        userId = app.database.execute(text("""
        INSERT INTO users (
            name,
            email,
            profile,
            hashed_password
        ) VALUES (
            :name,
            :email,
            :profile,
            :password
        )"""), newUser).lastrowid

        row = current_app.database.execute(text("""
        SELECT 
            id,
            name,
            email,
            profile
        FROM users WHERE id = :userId
        """), {'userId': userId}).fetchone()

        createdUser = {
            'id': row['id'],
            'name': row['name'],
            'email': row['email'],
            'profile': row['profile']
        } if row else None

        return jsonify(createdUser)

    @app.route('/signIn', methods=['POST'])
    def signIn():
        contents = request.json
        email = contents['email']
        password = contents['password']
        
        if 'roleKey' in contents.keys():
            roleKey = contents['roleKey']
        else:
            roleKey = 'userDefault'

        row = current_app.database.execute(text("""
        SELECT 
            id,
            hashed_password
        FROM users
        WHERE email = :email
        """), {'email' : email}).fetchone()

        if row and bcrypt.checkpw(password.encode('UTF-8'), row['hashed_password'].encode('UTF-8')):
            userId = row['id']
            load = {
                'id' : userId,
                'role' : 'user',
                'exp' : datetime.utcnow() + timedelta(seconds = 60 * 60 * 24)
            } if roleKey != app.config['MASTER_KEY'] else {
                'id' : userId,
                'role' : 'master',
                'exp' : datetime.utcnow() + timedelta(seconds = 60 * 60 * 24 * 7)
            }
            token = jwt.encode(load, app.config['JWT_SECRET_KEY'], 'HS256')
            return jsonify({
                'accessToken' : token
            })
        else:
            return '', 401



    @app.route('/follow', methods=['POST'])
    @loginRequired
    def follow():
        contents = request.json
        userId = g.user_id
        follows = ast.literal_eval(contents['follow'])
        for id in follows:
            current_app.database.execute(text("""
            INSERT INTO follows (
                id,
                follows
            ) VALUES (
                :userId,
                :follow
            )"""), {'userId':userId, 'follow':id.__str__()})

        row = current_app.database.execute(text("""
        SELECT *
        FROM follows WHERE id = :userId
        """), {'userId':userId}).fetchall()
        followLst = [x['follows'] for x in row]
        return f'Now you are following {followLst}', 200

    @app.route('/unfollow', methods=['POST'])
    @loginRequired
    def unfollow():
        contents = request.json
        userId = g.user_id
        unfollows = ast.literal_eval(contents['unfollow'])
        for id in unfollows:
            current_app.database.execute(text("""
            DELETE FROM follows 
            WHERE 
                id = :userId
                AND follows = :follow
            """), {'userId':userId, 'follow':id.__str__()})

        row = current_app.database.execute(text("""
        SELECT *
        FROM follows WHERE id = :userId
        """), {'userId':userId}).fetchall()
        followLst = [x['follows'] for x in row]

        if len(followLst) == 0:
            return 'You follow no one.', 200

        return f'Now you are following {followLst}', 200

    @app.route('/tweet', methods=['POST'])
    @loginRequired
    def tweet():
        contents = request.json
        id = g.user_id
        tweet = contents['tweet']
        var = current_app.database.execute(text("""
        INSERT INTO tweets (
            userId,
            tweet
        ) VALUES (
            :id,
            :tweet
        )
        """), {'id': id, 'tweet': tweet}).lastrowid

        return 'You have tweeted !', 200

    @app.route('/timeline', methods=['GET'])
    @loginRequired
    def timeline():
        contents = request.json
        id = g.user_id

        row = current_app.database.execute(text("""
                        SELECT *
                        FROM follows WHERE id = :userId
                        """), {'userId': id}).fetchall()
        followLst = [x['follows'] for x in row]

        row2 = current_app.database.execute(text("""
                            SELECT *
                            FROM tweets
                            """), {}).fetchall()
        timelineLst = [(x['userId'], x['created_at'], x['tweet']) for x in row2 if x['userId'] in followLst]

        return jsonify(timelineLst)


    @app.route('/logs', methods=['GET'])
    def logs():
        contents = request.json

        if 'database' in contents.keys() and contents['database'] == 't':
            return app.database.__str__()

        elif 'config' in contents.keys() and contents['config'] == 't':
            return app.config.__str__()

        elif 'global' in contents.keys() and contents['global'] == 't':
            row = current_app.database.execute(text("""
                    SELECT *
                    FROM tweets
                    """), {}).fetchall()
            tweetLst = [(x['userId'], x['tweet']) for x in row]
            return tweetLst.__str__()

        elif 'users' in contents.keys() and contents['users'] == 't':
            row = current_app.database.execute(text("""
            SELECT * 
            FROM users 
            """), {}).fetchall()
            usersLst = [(x['id'], x['name'], x['email'], x['created_at']) for x in row]
            return f"{usersLst}"

        return 'Wrong Input', 400

    @app.route('/search', methods=['GET'])
    def search():
        searchId = request.json['id']
        row = current_app.database.execute(text("""
                SELECT *
                FROM follows WHERE id = :userId
                """), {'userId': searchId}).fetchall()
        followLst = [x['follows'] for x in row]
        return f"id : {searchId} is following {followLst}", 200


    # an endpoint that deletes the tweet with given id by a user whose id is the userId of the tweet
    @app.route('/deleteTweet', methods=['POST'])
    @loginRequired
    def deleteTweet():
        contents = request.json
        userId = g.user_id
        tweetId = contents['tweetId']
        current_app.database.execute(text("""
        DELETE FROM tweets
        WHERE userId = :userId
        AND id = :tweetId
        """), {'userId': userId, 'tweetId': tweetId})
        return 'Tweet deleted.', 200
    
    # an endpoint that updates user informations when the user's current email and hashed password match the given information
    @app.route('/updateUser', methods=['POST'])
    @loginRequired
    def updateUser():  
        contents = request.json
        id = g.user_id
        email = contents['email']
        password = contents['password']
        newName = contents['newName']
        newEmail = contents['newEmail']
        newPassword = contents['newPassword']

        row = current_app.database.execute(text("""
        SELECT *
        FROM users
        WHERE id = :id AND email = :email
        """), {'id': id, 'email': email}).fetchone()

        if row and bcrypt.checkpw(password.encode('utf-8'), row['hashed_password'].encode('utf-8')):
            current_app.database.execute(text("""
            UPDATE users
            SET email = :NewEmail AND hashed_password = :newHashedPassword AND name = :newName
            WHERE id = :id AND email = :email
            """), 
            {'id': id, 
            'NewEmail': newEmail, 
            'newHashedPassword': bcrypt.hashedpw(newPassword.encode('utf-8'), bcrypt.gensalt()), 
            'newName': newName,
            'email': email})
            return 'User updated.', 200
        else:
            return 'Wrong Input', 400
        
    # an endpoint that updates the tweet with given id by a user whose id is the userId of the tweet
    @app.route('/updateTweet', methods=['POST'])
    @loginRequired
    def updateTweet():
        contents = request.json
        userId = g.user_id
        tweetId = contents['tweetId']
        newTweet = contents['newTweet']
        current_app.database.execute(text("""
        UPDATE tweets
        SET tweet = :newTweet
        WHERE userId = :userId
        AND id = :tweetId
        """), {'userId': userId, 'tweetId': tweetId, 'newTweet': newTweet})
        return 'Tweet updated.', 200

    # an endpoint that shows the mutual followers of the followers of the user with the given id
    @app.route('/mutualFollowers', methods=['GET'])
    @loginRequired
    def mutualFollowers():
        contents = request.json
        id = g.user_id

        row = current_app.database.execute(text("""
                        SELECT *
                        FROM follows WHERE id = :userId
                        """), {'userId': id}).fetchall()
        followLst = [x['follows'] for x in row]

        row2 = current_app.database.execute(text("""
                            SELECT *
                            FROM follows
                            """), {}).fetchall()
        mutualLst = [(x['id'], x['follows']) for x in row2 if x['follows'] in followLst]

        return jsonify(mutualLst)


    # an endpoint that shows how many followers the user with the given id has
    @app.route('/followers', methods=['GET'])
    def followers():
        contents = request.json
        id = contents['id']

        row = current_app.database.execute(text("""
                        SELECT *
                        FROM follows WHERE follows = :userId
                        """), {'userId': id}).fetchall()
        followersLst = [x['follows'] for x in row]

        return f"{id} has {len(followersLst)} followers.", 200
    
    # an endpoint that shows how many users the user with the given id is following
    @app.route('/following', methods=['GET'])
    def following():
        contents = request.json
        id = contents['id']

        row = current_app.database.execute(text("""
                        SELECT *
                        FROM follows WHERE id = :userId
                        """), {'userId': id}).fetchall()
        followingLst = [x['follows'] for x in row]

        return f"{id} is following {len(followingLst)} users.", 200
    
    # an endpoint that shows the tweets of the user with the given id
    @app.route('/tweetsHistroy', methods=['GET'])
    def tweetsHistory():
        contents = request.json
        id = contents['id']

        row = current_app.database.execute(text("""
                        SELECT *
                        FROM tweets
                        WHERE userId = :userId
                        """), {'userId': id}).fetchall()
        tweetsLst = [(x['id'], x['tweet']) for x in row]

        return jsonify(tweetsLst)

    # an endpoint that groups the tweets with similar hashtags
    @app.route('/hashtag', methods=['GET'])
    def hashtag():
        contents = request.json
        id = contents['id']

        row = current_app.database.execute(text("""
                        SELECT *
                        FROM tweets
                        WHERE userId = :userId
                        """), {'userId': id}).fetchall()
        tweetsLst = [(x['id'], x['tweet']) for x in row]

        hashtags = []
        for tweet in tweetsLst:
            for word in tweet[1].split():
                if word.startswith('#'):
                    hashtags.append(word)
        hashtags = list(set(hashtags))
        hashtagLst = []
        for hashtag in hashtags:
            hashtagLst.append([hashtag, [x[0] for x in tweetsLst if hashtag in x[1]]])
        return jsonify(hashtagLst)

    # an endpoint that deletes a user, his tweets, and his followers with given id after authentifying the user's role is 'master'
    @app.route('/deleteUser', methods=['POST'])
    @masterLoginRequired
    def deleteUser():
        contents = request.json
        id = contents['id']

        current_app.database.execute(text("""
        DELETE FROM tweets
        WHERE userId = :id
        """), {'id': id})
        current_app.database.execute(text("""
        DELETE FROM follows
        WHERE id = :id
        """), {'id': id})
        current_app.database.execute(text("""
        DELETE FROM follows
        WHERE follows = :id
        """), {'id': id})
        current_app.database.execute(text("""
        DELETE FROM users
        WHERE id = :id
        """), {'id': id})
        return 'User deleted.', 200

    # an endpoint that deletes a user after authentifying the user is himself
    @app.route('/deleteUserSelf', methods=['POST'])
    @loginRequired
    def deleteUserSelf():
        contents = request.json
        id = g.user_id

        current_app.database.execute(text("""
        DELETE FROM tweets
        WHERE userId = :id
        """), {'id': id})
        current_app.database.execute(text("""
        DELETE FROM follows
        WHERE id = :id
        """), {'id': id})
        current_app.database.execute(text("""
        DELETE FROM follows
        WHERE follows = :id
        """), {'id': id})
        current_app.database.execute(text("""
        DELETE FROM users
        WHERE id = :id
        """), {'id': id})
        return 'User deleted.', 200

    return app


