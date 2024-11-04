from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import re
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = 'secure_messaging'

# Database connection function for SQLite
def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect('secure_messaging.db', timeout=60)
        g.db.row_factory = sqlite3.Row
    return g.db

# Close the database connection after each request
@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Generate and return public/private keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Export public and private keys as PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

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
        cursor.execute('SELECT * FROM accounts WHERE username = ? AND password = ?', (username, hashed_password))
        account = cursor.fetchone()

        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return redirect(url_for('messaging'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

# Logout route
@app.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Registration route with public key storage
@app.route('/register/', methods=['GET', 'POST'])
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
            
            # Generate and store public/private keys
            private_key, public_key = generate_keys()
            
            # Store only the public key in the database for secure communication
            cursor.execute('INSERT INTO accounts (username, password, email, public_key) VALUES (?, ?, ?, ?)',
                           (username, hashed_password, email, public_key.decode('utf-8')))
            conn.commit()
            msg = 'You have successfully registered!'
            # Save private key to a file for the user (or handle securely as needed)
            with open(f"{username}_private_key.pem", "wb") as private_file:
                private_file.write(private_key)
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

# Messaging route
@app.route('/messaging/')
def messaging():
    if 'loggedin' in session:
        # Code to retrieve messages, encrypt, and decrypt as needed
        return render_template('messaging.html')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)