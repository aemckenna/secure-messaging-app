from flask import Blueprint, session, redirect, url_for, request, render_template
from db import get_db_connection
from encryption import encrypt_message, decrypt_message

messaging_bp = Blueprint('messaging', __name__)

@messaging_bp.route('/messages')
def messages():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch contacts
    cursor.execute('SELECT username FROM accounts WHERE username != %s', (session['username'],))
    contacts = [{'username': row[0]} for row in cursor.fetchall()]

    # Fetch messages with a selected contact
    selected_contact = request.args.get('contact')
    if selected_contact:
        cursor.execute('''
            SELECT sender_id, message, timestamp FROM messages 
            WHERE (sender_id = %s AND recipient_id = %s) 
            OR (sender_id = %s AND recipient_id = %s) 
            ORDER BY timestamp
        ''', (session['username'], selected_contact, selected_contact, session['username']))
        messages = [{'sender': row[0], 'message': row[1], 'timestamp': row[2]} for row in cursor.fetchall()]
    else:
        messages = []

    cursor.close()
    return render_template('messages.html', contacts=contacts, selected_contact=selected_contact, messages=messages)

@messaging_bp.route('/send_message', methods=['POST'])
def send_message():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    sender_id = session['id']
    recipient_username = request.form['recipient']
    message = request.form['message']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch the recipient's public key
    cursor.execute('SELECT public_key FROM accounts WHERE username = %s', (recipient_username,))
    result = cursor.fetchone()
    if not result:
        return "Recipient not found", 404
    
    recipient_public_key = result[0]
    encrypted_message = encrypt_message(recipient_public_key, message)
    
    # Store the encrypted message in the messages table
    cursor.execute('INSERT INTO messages (sender_id, recipient_id, message) VALUES (%s, %s, %s)',
                   (sender_id, recipient_username, encrypted_message))
    conn.commit()
    cursor.close()
    
    return "Message sent successfully"

@messaging_bp.route('/retrieve_messages', methods=['GET'])
def retrieve_messages():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch the user's encrypted private key and their passphrase (password)
    cursor.execute('SELECT private_key, password FROM accounts WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    private_key_pem, password = user
    
    # Fetch encrypted messages for this user
    cursor.execute('SELECT sender_id, message FROM messages WHERE recipient_id = %s', (user_id,))
    encrypted_messages = cursor.fetchall()
    
    decrypted_messages = []
    for sender_id, encrypted_message in encrypted_messages:
        try:
            decrypted_message = decrypt_message(encrypted_message, private_key_pem, password.encode())
            decrypted_messages.append({'sender': sender_id, 'message': decrypted_message})
        except Exception as e:
            decrypted_messages.append({'sender': sender_id, 'message': 'Could not decrypt message'})
    
    cursor.close()
    return render_template('messages.html', messages=decrypted_messages)