//connection to socket.io
var socket = io.connect();


//Join a room for username.
function joinRoom(username) {
    socket.emit('join', {username: username});
}

//When a new message is recieved, send a notification to the correct user.
socket.on('new_message_notification', function(data) {
    alert(`New message from ${data.sender}: ${data.content}`);
});


//Let a user leave a room when the page unloads
function leaveRoom(username) {
    window.onbeforeunload = function() {
        socket.emit('leave', {username: username});
    };
}

//Join the room when the page is loaded.
document.addEventListener("DOMContentLoaded", function() {
    var username = document.querySelector("h1").textContent.split(",")[1].trim();
    console.log(username);
    joinRoom(username);
    leaveRoom(username);
});

//Verify the email when the user clciks the correct fbutton for sign in.
document.getElementById("verify-email-btn")?.addEventListener("click", function() {
    var username = document.querySelector("h1").textContent.split(",")[1].trim();
    fetch("/verify-email", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ "username": username })
    })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error(error));
});