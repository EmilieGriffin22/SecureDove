from mailbox import Message
import secrets
import string
from flask_mail import Mail, Message
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from urllib import request
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import SocketIO, join_room, emit, leave_room
import mysql.connector # type: ignore
import os
import hashlib
import random

app = Flask(__name__)
app.secret_key = str(random.random() * 1000)
socketio = SocketIO(app)

#Mail configuration for email verification feature.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

#Reuse spam email from CSE 312.
app.config['MAIL_USERNAME'] = ""    
#Temp                    
app.config['MAIL_PASSWORD'] = ""                                      
app.config['MAIL_DEFAULT_SENDER'] = ''
mail = Mail(app)

#IF PORT ERROR OCCURS, CHANGE THIS VARIABLE
PORT = 5000

#Get a connector to the SQL database (there's only one for this).
#Note: Use this function when connecting to the database, don't do it manually.
def get_db_connection():
    return mysql.connector.connect(host=os.getenv('DB_HOST', 'db'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'secure_dove')
    )

#User table.
def create_users_table():
    connection = get_db_connection()
    cursor = connection.cursor()
    #This query creates a users table with ID, username, email
    #hashpassword, public key, private key, verification token, and verified columns.
    query = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                hashed_password VARCHAR(255) NOT NULL,
                public_key TEXT NOT NULL,     
                private_key TEXT NOT NULL,      
                PRIMARY KEY (id),
                verificationToken VARCHAR(255),
                verified BOOLEAN DEFAULT FALSE
            );
        """
    cursor.execute(query)
    #Commit the changes and close the connection.
    connection.commit()
    cursor.close()
    connection.close()

#Message table, automatically deletes messages for a user on user deletion.
def create_messages_table():
    connection = get_db_connection()
    cursor = connection.cursor()
    #Table with columns for ID, sender/recipient IDs, timestamp, encrypted content, and user ID linking to the user table.
    #Note that the message content must be encrypted for both the sender and recipient otherwise it will not work in
    #The chat room function.
    query = """
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT,
                sender_id INT NOT NULL,
                recipient_id INT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                content TEXT NOT NULL,
                sender_encrypted_content TEXT NOT NULL,
                PRIMARY KEY (id),
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """
    cursor.execute(query)
    #Commit and close the query.
    connection.commit()
    cursor.close()
    connection.close()

#Get random link on our localhost.
def generateVerificationLink():
    charaters = string.ascii_letters + string.digits
    verification_code = ''.join(secrets.choice(charaters) for _ in range(120)) #Use secrets library to generate randomness and add to link.
    return verification_code

#Enter verification info.
def inputVerificationInDatabase(username):
    cnx = get_db_connection()
    cursor = cnx.cursor()

    #Get a verification link that can be stored.
    unique_link = generateVerificationLink()
    #Update the users table with the verification link to be expected.
    query = "UPDATE users SET verificationToken = %s, verified = %s WHERE username = %s"
    cursor.execute(query, (unique_link, False, username))

    #Commit and close database changes.
    cnx.commit()
    cursor.close()
    cnx.close()
    return unique_link

#Generate the email.
def emailVerificationLink(username, user_mail):
    #Get the verification link for the user.
    unique_token = inputVerificationInDatabase(username)
    #Build the email Message.
    email = Message(
        subject="SecureDove: Email Verification Link",
        recipients=[user_mail],
        html="Click on this verification link to verify your SecureDove Email: http://localhost:" + str(PORT) + "/verification/" + unique_token,
        sender="312endingfromtheback@gmail.com"
    )
    return email

#Find the email.
def getEmail(username):
    cnx = get_db_connection()
    cursor = cnx.cursor()

    #Get the users
    query = ("SELECT email FROM users WHERE username = %s")
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result:
        email = result[0]
    else:
        email = None #Handle the case where an email was not found.

    #Don't need to commit has nothing was changed.
    cursor.close()
    cnx.close()
    return email

#Default webpage (root).
@app.route("/")
def hello():
    return render_template("home.html")

#Serve the login page.
@app.route("/loginpage")
def login_page():
    #No specific error message on default route to login page.
    error = ""
    return render_template("login.html", error = error)

#Login action.
@app.route('/login', methods=['POST'])
def login():
    #Get the username and password submitted in the form and hash them.
    username = request.form['username']
    password = request.form['password']
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()


    connection = get_db_connection()
    cursor = connection.cursor()
    #Try and find an entry where username = the entered username and password = the hash.
    query = "SELECT id, username, verified FROM users WHERE username = %s AND hashed_password = %s"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()

    cursor.close()
    connection.close()

    #why is python syntax like this?
    if user is not None: #Make sure a user was found.
        if(not user[2]): #Don't let not verified users login.
            error = "You are not verified. Please verify your email and try again."
            return render_template("login.html", error=error)

    if user: #A user was found with the right information.
        session['logged_in'] = True #Set the session variables.
        session['username'] = username
        session['user_id'] = user[0]  #EMILIE DON'T FORGET THIS
        return redirect(url_for("welcome_page", username=username))

    error = "Invalid credentials. Please try again!"
    #Redirect to login page, now with an appropriae error message.
    return render_template("login.html", error=error)

#NOTE: Auto-Sends verification email, departs from requirements as it is a link.
#ALSO: Auto-generates and stores key, departing from requirements.
@app.route("/signup", methods=["POST"])
def signup():
    #Get the desired username and password from the form.
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    #Hash the password (no salt for now, will add in later).
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    connection = get_db_connection()
    cursor = connection.cursor()

    #Generate a public and private RSA key for the new user.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    #Reformat the keys so they can be stored.
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption() #Keep things simple for now, no encryption on key.
                                                          #Might add encryption in later.
    ).decode('utf-8')

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    #Put the new user into the database.
    query = "INSERT INTO users (username, email, hashed_password, public_key, private_key) VALUES (%s, %s, %s, %s, %s)"
    try:
        cursor.execute(query, (username, email, hashed_password, pem_public_key, pem_private_key))
    except mysql.connector.Error as err: #If the user could not be inserted (likely because they are not unique).
        message = "Account creation failed. Please make sure your credentials are not in use!"
        connection.commit()
        cursor.close()
        connection.close()
        return render_template("signup.html", error=message) #Return to sign-in if failure.

    #Commit and close the connection.
    connection.commit()
    cursor.close()
    connection.close()

    #Send an email verification link.
    email = emailVerificationLink(username, email)
    mail.send(email)
    #Send user to email verification page.
    return render_template("email_verification.html")

#Serve sign-up page.
@app.route("/signuppage")
def signup_page():
    #No error message on first serving of page.
    return render_template("signup.html", error = "")

#Serve the user's welcome page.
#Should only let "good" users in.
@app.route('/welcome/<username>')
def welcome_page(username):
    if 'logged_in' not in session or username != session.get('username'): #Check that the user has authenticated. No direct URL access.
        error = "You are not logged in. Please log in."
        return render_template("login.html", error=error) #Send an error if the user is not logged in.

    #Get the database connection to load chats.
    connection = get_db_connection()
    cursor = connection.cursor()

    #Find the user id for the current user to load their chats.
    query = "SELECT id FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    user_id = result[0]

    #Gather the liist of users which the current user has sent messages to.
    query = """
        SELECT DISTINCT users.username
        FROM messages
        JOIN users ON users.id = messages.sender_id OR users.id = messages.recipient_id
        WHERE (messages.sender_id = %s OR messages.recipient_id = %s) AND users.username != %s
    """
    cursor.execute(query, (user_id, user_id, username))
    chat_users = cursor.fetchall()

    #Close the connection (no commit needed as DB was not changed).
    cursor.close()
    connection.close()

    return render_template('welcome.html', username=username, chat_users=chat_users)

#Let the user join the chat page with user2.
@app.route('/chat/<username1>/<username2>')
def chat_page(username1, username2):
    if 'logged_in' not in session or username1 != session.get('username'): #Check that the user is authenticated.
        error = "You are not logged in. Please log in."
        return render_template("login.html", error=error)

    connection = get_db_connection()
    cursor = connection.cursor()

    #Get the User ID an their private key so they can read their messages.
    query = "SELECT id, private_key FROM users WHERE username = %s"
    cursor.execute(query, (username1,))
    result = cursor.fetchone()
    user1_id = result[0]
    private_key_pem = result[1]
    #Undo PEM from stording.
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)

    #Find the user id for the second user. Do not get their private key, it is not needed.
    query = "SELECT id FROM users WHERE username = %s"
    cursor.execute(query, (username2,))
    user2_id = cursor.fetchone()[0]

    #Obtain all of the messages between user 1 and user 2 in order of most recent.
    query = """
        SELECT messages.id, users.username AS sender, messages.content, messages.sender_encrypted_content, messages.timestamp 
        FROM messages 
        JOIN users ON users.id = messages.sender_id
        WHERE (messages.sender_id = %s AND messages.recipient_id = %s) 
           OR (messages.sender_id = %s AND messages.recipient_id = %s)
        ORDER BY messages.timestamp ASC
    """
    cursor.execute(query, (user1_id, user2_id, user2_id, user1_id))
    messages = cursor.fetchall()

    #Close the connection (commit not needed as bnothing changed).
    cursor.close()
    connection.close()

    #Decrypt the messages.
    decrypted_messages = []
    for message in messages:
        if message[1] == username1:  #Determine which version of the message the current user should decrypt (the sender or recip).
            encrypted_content = message[3]
        else:
            encrypted_content = message[2]

        #Decrypt the content.
        decrypted_content = private_key.decrypt(
            bytes.fromhex(encrypted_content),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')

        #Append to the list of messages and send to the chatpage.
        decrypted_messages.append({
            'id': message[0],
            'sender': message[1],
            'content': decrypted_content,
            'timestamp': message[4]
        })

    return render_template('chatpage.html', username=username1, chat_partner=username2, messages=decrypted_messages)

#Self explanatory
@app.route("/settings")
def settings_page():
    #Get any error message the user should have.
    message = request.args.get('message', '')
    username = session.get('username')
    #Note in the future: Make a method for this authentication check.
    if 'logged_in' not in session or session.get('username') != username: #**grabs spray bottle**
        return redirect("/")
    return render_template("settings.html", username=username, message=message)

#Self explanatory
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'logged_in' not in session: #Verify that the user is authentic.
        return redirect(url_for('login', error="You are not logged in. Please log in and try again!"))

    #Get the username from the session and theh password entries from the form.
    username = session['username']
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    #hash the password
    #Later, add in salting.
    hashed_current_password = hashlib.sha256(current_password.encode('utf-8')).hexdigest()

    connection = get_db_connection()
    cursor = connection.cursor()
    #Get the needed user information.
    query = "SELECT * FROM users WHERE username = %s AND hashed_password = %s"
    cursor.execute(query, (username, hashed_current_password))
    user = cursor.fetchone()

    #If a user was found, let them change their password.
    if user:
        #Hash the password. Will need to change if/when salting is added.
        hashed_new_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
        update_query = "UPDATE users SET hashed_password = %s WHERE username = %s"
        cursor.execute(update_query, (hashed_new_password, username))
        #Commit and close, as changes were made.
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for("settings_page", message="Password changed successfully!"))
    else:
        #Return an error message.
        cursor.close()
        connection.close()
        return redirect(url_for("settings_page", message="Failed to change password. Please try again!"))

#Self explanatory
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'logged_in' not in session: #Check if an authentic user.
        return redirect(url_for('login', error="You are not logged in. Please log in to delete your account."))
    username = session['username']

    connection = get_db_connection()
    cursor = connection.cursor()

    #Delete the user with the username from the session.
    delete_query = "DELETE FROM users WHERE username = %s"
    cursor.execute(delete_query, (username,))

    #Commit the changes that were made and close.
    connection.commit()
    cursor.close()
    connection.close()
    session.clear() #Clear the session associated with the now deleted user.
    return redirect(url_for('hello'))

#I want to break free
@app.route('/logout', methods=["GET"])
def logout():
    session.clear() #Clear the session when the user logs on.
    return redirect("/")

#Let a user send a message in the 1-1 fashion  (not in the global chat room).
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'logged_in' not in session: #Check that the user is authentic.
        return redirect(url_for('login', error="You are not logged in. Please log in to send messages."))

    #Get the sender username from the session and the recipient/content from the form.
    sender_username = session['username']
    recipient_username = request.form['recipient']
    content = request.form['content']

    connection = get_db_connection()
    cursor = connection.cursor()

    #Get the recipients public key and id for encryption.
    query = "SELECT id, public_key FROM users WHERE username = %s"
    cursor.execute(query, (recipient_username,))
    recipient = cursor.fetchone()

    #Redirect to the home page if an invalid recipient.
    if not recipient:
        connection.close()
        return redirect(url_for('welcome_page', username=sender_username, message="Recipient not found!"))

    #Get the recipient id and un-pem their public key.
    recipient_id = recipient[0]
    recipient_public_key = serialization.load_pem_public_key(recipient[1].encode('utf-8'))

    # Get the sender id and un-pem their public key.
    query = "SELECT id, public_key FROM users WHERE username = %s"
    cursor.execute(query, (sender_username,))
    sender = cursor.fetchone()

    #Send the sender back to their welcome page if an error occured with their username.
    if not sender:
        connection.close()
        return redirect(url_for('welcome_page', username=sender_username, message="Sender not found!"))

    #Set the sender ID and um-pem their public key.
    sender_id = sender[0]
    sender_public_key = serialization.load_pem_public_key(sender[1].encode('utf-8'))

    #Encrypt the message for the recipient using their public key.
    encrypted_message_for_recipient = recipient_public_key.encrypt(
        content.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Encrypt the message for the sender using their public key.
    encrypted_message_for_sender = sender_public_key.encrypt(
        content.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Store the encrypted message in the database for future use.
    query = """
        INSERT INTO messages (sender_id, recipient_id, content, sender_encrypted_content) 
        VALUES (%s, %s, %s, %s)
    """
    cursor.execute(query, (sender_id, recipient_id, encrypted_message_for_recipient.hex(), encrypted_message_for_sender.hex()))

    #Commit and close the connection.
    connection.commit()
    cursor.close()
    connection.close()

    #Send a notification to the user who recieved the message if they are on the home page.
    socketio.emit('new_message_notification', {
    'sender': sender_username,
    'content': content
    }, room=recipient_username)

    #Redirect to the chat page once a message is sent.
    return redirect(url_for('chat_page', username1=sender_username, username2=recipient_username))

@app.route('/delete_message_from_chat/<int:message_id>/<username1>/<username2>', methods=['POST'])
def delete_message_from_chat(message_id, username1, username2):
    if 'logged_in' not in session or username1 != session.get('username'): #Verify the user is authenticated.
        return redirect(url_for('login', error="You are not logged in. Please log in to delete messages."))


    connection = get_db_connection()
    cursor = connection.cursor()

    #Get the sender id for the message.
    query = "SELECT sender_id FROM messages WHERE id = %s"
    cursor.execute(query, (message_id,))
    result = cursor.fetchone()

    #if the user logged in was the sender, execute and commit the delete query.
    if result and result[0] == session['user_id']:
        delete_query = "DELETE FROM messages WHERE id = %s"
        cursor.execute(delete_query, (message_id,))
        connection.commit()

    #Close the connection when no changes were made. Redirect to chat page.
    cursor.close()
    connection.close()
    return redirect(url_for('chat_page', username1=username1, username2=username2))

#Join the socket.io room.
@socketio.on('join')
def on_join(data):
    username = session['username'] #Get username from session.
    join_room(username)
    emit('message', {'msg': f'{username} has joined the room.'}, room=username) #Let user know a new person has joined the room.

#Leave the socket io room.
@socketio.on('leave')
def on_leave(data):
    username = data['username']
    leave_room(username)
    emit('message', {'msg': f'{username} has left the room.'}, room=username)

#Allow a user to verify their email.
@app.route("/verify-email", methods=["POST"])
def verify_email():
    #Get the username from the request.
    username = request.json.get("username")

    cnx = get_db_connection()
    cursor = cnx.cursor()

    #Determine if the user has verified already.
    query = "SELECT verified FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    #If they are not verified, send the verification email.
    if result:
        if result[0] == 0:  # 0 means False
            user_email = getEmail(username)
            email = emailVerificationLink(username, user_email)
            mail.send(email)
            cnx.close()
            return render_template("email_verification.html")
        else:
            #If they are already verified, let them know.
            cnx.close()
            return render_template("already_verified.html")
    else: #Close the connection otheerwise and return an error.
        cnx.close()
        return "User not found", 404
@app.route('/verification/<verificationToken>')
def verify_email_confirm(verificationToken):
    connection = get_db_connection()
    cursor = connection.cursor()

    #Determine if the user has a verification token in the DB.
    query = "SELECT * FROM users WHERE verificationToken = %s"
    cursor.execute(query, (verificationToken,))
    result = cursor.fetchone()

    #If the user correctly followed thier verification link, verify them in the DB.
    if result:
        query = "UPDATE users SET verified = True WHERE verificationToken = %s"
        cursor.execute(query, (verificationToken,))

        #Commit and close the connection.
        connection.commit()
        cursor.close()
        connection.close()
        return render_template("verified.html")
    else:
        #Otherwise, return an error to the user and close the connection.
        cursor.close()
        connection.close()
        return 'Verification token not found', 404

#Note: can we figure out how to encrypt this in the future?
# Chat room code below  
@app.route('/chatroom/<username>')
def chatroom(username):
    if 'logged_in' not in session or username != session.get('username'): #Verify that the user is authenticated.
        error = "You are not logged in. Please log in."
        return render_template("login.html", error=error)
    return render_template('chat.html', username=username) #Send them to the chat room.

@socketio.on('handle_chatroom_join')  # Renamed join functionality
def handle_chatroom_join(data):
    username = data['username'] #Send the chat joining message below on join.
    emit('new_message', {'sender': 'Server', 'content': f'{username} has joined the chat!'}, broadcast=True)

#Send a global chat room message: unencrypted.
@socketio.on('send_message')
def handle_send_message(data):
    username = data.get('username') #get the user.
    message_content = data.get('content')
    #send the message.
    emit('new_message', {'sender': username, 'content': message_content}, broadcast=True)
# Chat room code above
if __name__ == '__main__':
    create_users_table() #Create users table if not exists.
    create_messages_table() #Create messages table if not exists.
    socketio.run(app, host='0.0.0.0', port=PORT, allow_unsafe_werkzeug=True)
