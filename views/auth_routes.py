from flask import Blueprint, sendfile, render_template, request, redirect, url_for, session
from db import get_db_connection
from encryption import generate_key_pair
import hashlib
import re

auth_bp = Blueprint('auth', __name__)

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
        cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, hashed_password))
        account = cursor.fetchone()

        if account:
            session['loggedin'] = True
            session['id'] = account[0] 
            session['username'] = account[1]
            return redirect(url_for('messaging.messages'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html')

@auth_bp.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@auth_bp.route('/register/', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
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

            # Generate key pair with a passphrase
            passphrase = password.encode()
            encrypted_private_key, public_key_pem = generate_key_pair(passphrase)
            
            # Store public key in database
            cursor.execute('INSERT INTO accounts (username, password, email, public_key) VALUES (%s, %s, %s, %s)',
                           (username, hashed_password, email, public_key_pem))
            conn.commit()

            # Save private key to a file for download
            private_key_filename = f"{username}_private_key.pem"
            with open(private_key_filename, 'wb') as private_key_file:
                private_key_file.write(encrypted_private_key)
            
            msg = 'You have successfully registered! Your private key file is ready for download.'
            return send_file(private_key_filename, as_attachment=True)
        
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
        
    return render_template('register.html', msg=msg)