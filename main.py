from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import re
import hashlib

app = Flask(__name__)

# Secret key for session management
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

# Login route
@app.route('/', methods=['GET', 'POST'])
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
            return redirect(url_for('workout'))
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
            
            cursor.execute('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email,))
            conn.commit()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)
