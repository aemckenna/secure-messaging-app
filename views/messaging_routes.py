from flask import Blueprint, session, redirect, url_for, request, render_template, flash
from db import get_db_connection
from encryption import encrypt_message, decrypt_message

messaging_bp = Blueprint('messaging', __name__)

@messaging_bp.route('/messages/')
def view_messages():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['id']
    shared_key = session.get('shared_key')

    # Retrieve user's contacts
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.username
        FROM accounts a
        JOIN contacts c ON c.client_id = a.id
        WHERE c.user_id = ?
    ''', (user_id,))
    contacts = cursor.fetchall()

    # Retrieve messages from the database
    cursor.execute('SELECT sender_id, message FROM messages WHERE recipient_id = ?', (user_id,))
    messages = cursor.fetchall()

    # Decrypt each message
    decrypted_messages = []
    for sender_id, encrypted_message in messages:
        decrypted_result = decrypt_message(shared_key, encrypted_message)
        decrypted_message = decrypted_result.get('decrypted_message', '[Error decrypting message]')
        
        decrypted_messages.append({
            'sender_id': sender_id,
            'message': decrypted_message
        })

    cursor.close()
    return render_template('messages.html', messages=decrypted_messages, contacts=contacts)

@messaging_bp.route('/send_message', methods=['POST'])
def send_message():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch sender's ID
    cursor.execute('SELECT id FROM accounts WHERE username = ?', (session['username'],))
    sender_result = cursor.fetchone()
    if not sender_result:
        flash("User not found.")
        return redirect(url_for('auth.login'))
    sender_id = sender_result[0]
    
    recipient_username = request.form['recipient']
    message = request.form['message']
    
    # Fetch the recipient's ID
    cursor.execute('SELECT id FROM accounts WHERE username = ?', (recipient_username,))
    result = cursor.fetchone()
    if not result:
        flash("Recipient not found.")
        return redirect(url_for('messaging.messages'))
    
    recipient_id = result[0]
    
    # Define a shared AES key (for testing purposes, this can be hardcoded, but in production, securely store and retrieve it)
    shared_key = b'16byteslongkey!!16byteslongkey!!'  # Example key (must be 32 bytes for AES-256)

    # Encrypt the message
    encrypted_message_data = encrypt_message(shared_key, message)
    
    if encrypted_message_data.get('status') == 'error':
        flash("Encryption failed: " + encrypted_message_data.get('message', 'Unknown error'))
        return redirect(url_for('messaging.messages'))
    
    encrypted_message = encrypted_message_data['encrypted_message']
    
    # Insert the encrypted message into the database
    try:
        cursor.execute('INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)',
                       (sender_id, recipient_id, encrypted_message))
        conn.commit()  # Save changes to the database
        flash("Message sent successfully.")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to send message: {e}")
    
    cursor.close()
    return redirect(url_for('messaging.messages', contact=recipient_username))

@messaging_bp.route('/add_client', methods=['POST'])
def add_client():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['id']
    connection_id = request.form['connection_id']

    # Ensure the connection_id exists in the accounts table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM accounts WHERE username = ?', (connection_id,))
    client = cursor.fetchone()

    if not client:
        flash("Client not found.")
        return redirect(url_for('messaging.view_messages'))

    client_id, client_username = client

    # Insert the new client into the user's contact list
    try:
        cursor.execute('INSERT INTO contacts (user_id, client_id) VALUES (?, ?)', (user_id, client_id))
        conn.commit()
        flash(f"Client {client_username} added successfully.")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to add client: {e}")

    cursor.close()
    return redirect(url_for('messaging.messages'))
