from flask import Blueprint, render_template, request, redirect, url_for, session
from db import get_db_connection
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from encryption import encrypt_private_key
import hashlib
import re
import random
import string
from datetime import datetime, timezone
import os

auth_bp = Blueprint('auth', __name__)

def generate_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

@auth_bp.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # Hash password for secure comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Query database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, private_key, password FROM accounts WHERE username = ? AND password = ?', (username, hashed_password))
        account = cursor.fetchone()

        if account:
            session['loggedin'] = True
            session['id'] = account[0]  # id
            session['username'] = account[1]  # username
            session['private_key'] = account[2]  # private_key
            session['password'] = password  # Store the password in session
            
            return redirect(url_for('messaging.messages'))
        else:
            msg = 'Incorrect username/password!'

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
        
        cursor.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        account = cursor.fetchone()
        
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only letters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash password securely
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # Generate Diffie-Hellman key pair
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Serialize public key to store in database
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Encrypt private key with password-based encryption
            encrypted_private_key = encrypt_private_key(private_key, password.encode())  # Encrypt private key with passphrase            
            # Generate a unique connection ID for the user
            connection_id = generate_code()
            
            # Generate current timestamp
            created_at = datetime.now(timezone.utc)

            # Insert new account data into the database
            cursor.execute('''INSERT INTO accounts (username, password, email, public_key, private_key, created_at, connection_id)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (username, hashed_password, email, public_key_pem, encrypted_private_key, created_at, connection_id))
            conn.commit()
            
            msg = 'You have successfully registered! Your account is ready for use.'
        
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
        
    return render_template('register.html', msg=msg)