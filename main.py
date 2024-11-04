from flask import Flask, render_template, request, redirect, url_for, session, g, send_file
import psycopg2
import re
import hashlib
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.secret_key = 'secure_messaging'

secret_password = os.environ.get('postgresDbPassword')

# Database connection function for PostgreSQL
def get_db_connection():
    if 'db' not in g:
        g.db = psycopg2.connect(
            dbname='messaging-app',
            user='ashermckenna',
            password=secret_password,
            host='localhost',
            port='6000'
        )
    return g.db

# Close the database connection after each request
@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Helper function to generate key pair
def generate_key_pair(passphrase: bytes):
    # Generate RSA Key Pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Encrypt Private Key with a passphrase
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    
    # Public key in PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return encrypted_private_key, public_key_pem

# Login route
@app.route('/login/', methods=['GET', 'POST'])
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
            return redirect(url_for('messaging'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html')

# Logout route
@app.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Registration route
@app.route('/register/', methods=['GET', 'POST'])
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

@app.route('/messaging/')
def messaging():
    msg = ''
    return render_template('messaging.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)