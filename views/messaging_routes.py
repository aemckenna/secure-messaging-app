from flask import Blueprint, session, redirect, url_for, request, render_template, flash
from db import get_db_connection
from encryption import encrypt_message, decrypt_message

messaging_bp = Blueprint('messaging', __name__)

@messaging_bp.route('/messages')
def messages():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch contacts for the logged-in user
    cursor.execute('SELECT username FROM accounts WHERE username != ?', (session['username'],))
    contacts = [{'username': row[0]} for row in cursor.fetchall()]

    # Fetch the logged-in user's ID
    cursor.execute('SELECT id FROM accounts WHERE username = ?', (session['username'],))
    sender_result = cursor.fetchone()
    if not sender_result:
        flash("User not found.")
        return redirect(url_for('auth.login'))
    sender_id = sender_result[0]

    # Fetch messages with a selected contact
    selected_contact_username = request.args.get('contact')
    if selected_contact_username:
        cursor.execute('SELECT id FROM accounts WHERE username = ?', (selected_contact_username,))
        result = cursor.fetchone()
        if result:
            selected_contact_id = result[0]
            # Fetch messages exchanged between the logged-in user and selected contact
            cursor.execute('''
                SELECT sender_id, message, timestamp FROM messages 
                WHERE (sender_id = ? AND recipient_id = ?) 
                OR (sender_id = ? AND recipient_id = ?) 
                ORDER BY timestamp
            ''', (sender_id, selected_contact_id, selected_contact_id, sender_id))
            messages = [{'sender': row[0], 'message': row[1], 'timestamp': row[2]} for row in cursor.fetchall()]
        else:
            messages = []  # No messages if contact not found
    else:
        messages = []

    cursor.close()
    return render_template('messages.html', contacts=contacts, selected_contact=selected_contact_username, messages=messages)

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
    
    # Fetch the recipient's ID and public key
    cursor.execute('SELECT id, public_key FROM accounts WHERE username = ?', (recipient_username,))
    result = cursor.fetchone()
    if not result:
        flash("Recipient not found.")
        return redirect(url_for('messaging.messages'))
    
    recipient_id, recipient_public_key = result
    print(f"Recipient ID: {recipient_id}")  # Debugging line
    
    encrypted_message_data = encrypt_message(recipient_public_key, message)
    
    if encrypted_message_data.get('status') == 'error':
        flash("Encryption failed: " + encrypted_message_data.get('message', 'Unknown error'))
        return redirect(url_for('messaging.messages'))
    
    encrypted_message = encrypted_message_data['encrypted_message']
    print(f"Inserting message: Sender ID: {sender_id}, Recipient ID: {recipient_id}, Encrypted Message: {encrypted_message}")  # Debugging line
    
    try:
        cursor.execute('INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)',
                       (sender_id, recipient_id, encrypted_message))
        conn.commit()  # Ensure changes are saved in the database
        flash("Message sent successfully.")
    except Exception as e:
        conn.rollback()
        print(f"SQL Error: {e}")  # Print the SQL error to console for debugging
        flash(f"Failed to send message: {e}")
    
    cursor.close()
    return redirect(url_for('messaging.messages', contact=recipient_username))

@messaging_bp.route('/retrieve_messages', methods=['GET'])
def retrieve_messages():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))
    
    # Fetch user ID
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch the user's encrypted private key and their passphrase (password)
    cursor.execute('SELECT private_key, password FROM accounts WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("User not found.")
        return redirect(url_for('messaging.messages'))
    
    private_key_pem, password = user
    
    # Fetch encrypted messages for this user
    cursor.execute('SELECT sender_id, message, timestamp FROM messages WHERE recipient_id = ?', (user_id,))
    encrypted_messages = cursor.fetchall()
    
    decrypted_messages = []
    for sender_id, encrypted_message, timestamp in encrypted_messages:
        try:
            decrypted_message_data = decrypt_message(encrypted_message, private_key_pem, password.encode())
            if decrypted_message_data.get('status') == 'success':
                decrypted_messages.append({
                    'sender': sender_id,
                    'message': decrypted_message_data['decrypted_message'],
                    'timestamp': timestamp
                })
            else:
                decrypted_messages.append({'sender': sender_id, 'message': 'Could not decrypt message', 'timestamp': timestamp})
        except Exception as e:
            decrypted_messages.append({'sender': sender_id, 'message': 'Could not decrypt message', 'timestamp': timestamp})
    
    cursor.close()
    return render_template('messages.html', messages=decrypted_messages)