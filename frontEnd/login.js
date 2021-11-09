function createCookie(value) {
  var now = new Date();
  var expirationDate = new Date(now.getFullYear(), now.getMonth(), now.getDate()+7, 0, 0, 0);

  document.cookie = 'token='+value+'; expires='+expirationDate+'; path=/';
};

$(document).ready(function() {
  $("#loginForm").submit(function(e) {
    e.preventDefault();

    var email = $("#email").val();
    var password = $("#password").val();
    var roleKey = $("#roleKey").val();

    $.ajax({
      method: "POST",
      url: "http://localhost:5000/signIn",
      data: JSON.stringify({
        "email"    : email,
        "password" : password,
        "roleKey"  : roleKey
      }),
      contentType: 'application/json'
    })
    .done(function(msg) {
      if (msg.accessToken) {
        createCookie(msg.accessToken);
        window.location.href = './tweets.html?userid='+msg.user_id;
      }
    });
  });
});
