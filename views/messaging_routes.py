from flask import Blueprint, session, redirect, url_for, request, render_template, flash
from db import get_db_connection
from encryption import derive_shared_key, aes_encrypt, generate_hmac, load_private_key, aes_decrypt, verify_hmac
from cryptography.hazmat.primitives import serialization

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

    # Fetch the user's ID, encrypted private key, and password from the database
    cursor.execute('SELECT id, private_key, password FROM accounts WHERE username = ?', (session['username'],))
    user = cursor.fetchone()

    if not user:
        flash("User not found.")
        return redirect(url_for('auth.login'))

    user_id, private_key_pem, password = user

    # Retrieve the passphrase from the session
    passphrase = session.get('password')  # This should be the password stored in the session during login
    if not passphrase:
        flash("No passphrase found. Please log in again.")
        return redirect(url_for('auth.login'))

    # Load the private key using the passphrase
    private_key = load_private_key(private_key_pem, password=passphrase.encode())  # Ensure passphrase is provided
    print(f"Private key loaded successfully.")

    # Retrieve the recipient's username and message content from the form
    recipient_username = request.form['recipient']
    message = request.form['message']

    if not message:
        flash("Message cannot be empty.")
        return redirect(url_for('messaging.messages'))

    print(f"Message content: {message}, recipient: {recipient_username}")

    # Fetch the recipient's ID and public key
    cursor.execute('SELECT id, public_key FROM accounts WHERE username = ?', (recipient_username,))
    result = cursor.fetchone()
    if not result:
        flash("Recipient not found.")
        return redirect(url_for('messaging.messages'))

    recipient_id, recipient_public_key_bytes = result
    print(f"Recipient ID: {recipient_id}")

    # Load recipient's public key
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_bytes)
    print("Recipient public key loaded.")

    # Derive shared AES key using Diffie-Hellman (or similar mechanism)
# Assuming private_key is a DHPrivateKey object
    private_key_bytes = private_key.private_numbers().x.to_bytes((private_key.private_numbers().x.bit_length() + 7) // 8, 'big')

# Now pass the correct bytes to the derive_shared_key function
    aes_key = derive_shared_key(private_key_bytes=private_key_bytes, peer_public_key=recipient_public_key)    
    print(f"AES key derived successfully.")

    # Encrypt the message using AES
    encrypted_message = aes_encrypt(aes_key, message)
    print(f"Encrypted message: {encrypted_message}")

    message_hmac = generate_hmac(aes_key, encrypted_message)
    print(f"Message HMAC generated: {message_hmac}")

    # Debugging: Print values before database insertion
    print(f"Inserting message to DB: Sender ID: {user_id}, Recipient ID: {recipient_id}, Encrypted Message: {encrypted_message}, HMAC: {message_hmac}")

    cursor.execute(
        'INSERT INTO messages (sender_id, recipient_id, message, hmac) VALUES (?, ?, ?, ?)',
        (user_id, recipient_id, encrypted_message, message_hmac)
    )
    conn.commit()  # Ensure changes are saved in the database
    print("Message inserted into database.")
    flash("Message sent successfully.")

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

    encrypted_private_key_pem, password = user

    # Decrypt the user's private key using their password
    private_key = load_private_key(encrypted_private_key_pem, password=password.encode())

    if not private_key:
        flash("Failed to decrypt private key.")
        return redirect(url_for('messaging.messages'))

    # Fetch encrypted messages and HMACs for this user
    cursor.execute('SELECT sender_id, message, hmac, timestamp FROM messages WHERE recipient_id = ?', (user_id,))
    encrypted_messages = cursor.fetchall()

    decrypted_messages = []
    for sender_id, encrypted_message, message_hmac, timestamp in encrypted_messages:
        # Retrieve sender's public key
        cursor.execute('SELECT public_key FROM accounts WHERE id = ?', (sender_id,))
        sender = cursor.fetchone()
        if not sender:
            decrypted_messages.append({'sender': sender_id, 'message': 'Sender not found', 'timestamp': timestamp})
            continue

        sender_public_key_pem = sender[0]
        sender_public_key = serialization.load_pem_public_key(sender_public_key_pem)

# Assuming private_key is a DHPrivateKey object
        private_key_bytes = private_key.private_numbers().x.to_bytes((private_key.private_numbers().x.bit_length() + 7) // 8, 'big')

# Now pass the correct bytes to the derive_shared_key function
        aes_key = derive_shared_key(private_key_bytes=private_key_bytes, peer_public_key=recipient_public_key)
        # Decrypt the message
        decrypted_message_data = aes_decrypt(aes_key, encrypted_message)
        
        if decrypted_message_data.get('status') == 'success':
            decrypted_message = decrypted_message_data['decrypted_message']
            # Verify HMAC to ensure integrity
            if verify_hmac(aes_key, encrypted_message, message_hmac):
                decrypted_messages.append({
                    'sender': sender_id,
                    'message': decrypted_message,
                    'timestamp': timestamp
                })
            else:
                decrypted_messages.append({
                    'sender': sender_id,
                    'message': 'Message integrity verification failed',
                    'timestamp': timestamp
                })
        else:
            decrypted_messages.append({
                'sender': sender_id,
                'message': 'Could not decrypt message',
                'timestamp': timestamp
            })

    cursor.close()
    return render_template('messages.html', messages=decrypted_messages)