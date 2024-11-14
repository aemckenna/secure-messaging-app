from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from db import get_db_connection
from encryption import encrypt_message, decrypt_message
import hashlib
import re
import random
import string
from datetime import datetime, timezone
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

auth_bp = Blueprint('auth', __name__)

def generate_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def generate_shared_key(password, salt):
    # PBKDF2 with HMAC-SHA-256 to derive a key from the password and salt
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

@auth_bp.route('/')
def home():
    return render_template('embed.html')

@auth_bp.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # Query the database to get the stored user data
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        account = cursor.fetchone()

        if account:
            # Retrieve the stored hashed password and salt
            stored_hashed_password = account[2]  # Assuming password is in index 2
            salt = account[6]  # Assuming salt is in index 6
            session['connection_id'] = account[5]
            # Debugging: Print the account and salt values
            print(f"Account from DB: {account}")
            print(f"Stored salt: {salt}")
            
            # Generate the shared key for comparison using PBKDF2
            generated_key = generate_shared_key(password, salt)

            # Hash the generated key and compare it to the stored hash
            generated_hashed_password = hashlib.sha256(generated_key).hexdigest()

            # Debugging: Print the generated key and the final hash
            print(f"Generated hashed password: {generated_hashed_password}")
            
            # Compare the generated shared key with the stored one
            if stored_hashed_password == generated_hashed_password:
                # Store the shared key in the session for encryption/decryption
                session['loggedin'] = True
                session['id'] = account[0]  # Assuming user ID is at index 0
                session['username'] = account[1]  # Assuming username is at index 1
                session['shared_key'] = generated_key  # Store the shared key in session
                
                flash("Login successful!")
                return redirect(url_for('messaging.view_messages'))
            else:
                msg = 'Incorrect username/password!'
        else:
            msg = 'Account does not exist!'
    return render_template('index.html', msg=msg)

@auth_bp.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('auth.login'))

@auth_bp.route('/register/', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        account = cursor.fetchone()

        if account:
            msg = 'Account with this username already exists!'
        else:
            # Check if email already exists
            cursor.execute('SELECT * FROM accounts WHERE email = ?', (email,))
            account_by_email = cursor.fetchone()

            if account_by_email:
                msg = 'An account with this email already exists!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only letters and numbers!'
            elif not username or not password or not email:
                msg = 'Please fill out the form!'
            else:
                # Generate a salt for password hashing
                salt = os.urandom(16)

                # Generate the shared AES key from the password and salt (AES-256)
                shared_key = generate_shared_key(password, salt)

                # Hash the shared key and store it
                hashed_password = hashlib.sha256(shared_key).hexdigest()

                # Generate a unique connection ID for the user
                connection_id = generate_code()
                
                # Generate current timestamp
                created_at = datetime.now(timezone.utc)

                # Insert new account data into the database
                try:
                    cursor.execute('''INSERT INTO accounts (username, password, email, created_at, connection_id, salt)
                                      VALUES (?, ?, ?, ?, ?, ?)''',
                                   (username, hashed_password, email, created_at, connection_id, salt))
                    conn.commit()
                    print(f"Inserting account: {username}, {hashed_password}, {email}, {created_at}, {connection_id}, {salt}")

                    msg = 'You have successfully registered! Your account is ready for use.'
                except Exception as e:
                    print(f"Error committing to database: {e}")
                    msg = 'There was an issue with registration. Please try again.'

    elif request.method == 'POST':
        msg = 'Please fill out the form!'

    return render_template('register.html', msg=msg)