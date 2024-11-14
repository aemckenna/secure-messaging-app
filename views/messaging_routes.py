from flask import Blueprint, session, redirect, url_for, request, render_template, flash
from db import get_db_connection
from encryption import encrypt_message, decrypt_message

messaging_bp = Blueprint('messaging', __name__)

@messaging_bp.route('/messages/', methods=['GET', 'POST'])
def view_messages():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['id']
    shared_key = session.get('shared_key')
    connection_id = session.get('connection_id')

    # Handle Add Client form submission
    if request.method == 'POST' and 'connection_id' in request.form:
        connection_id = request.form['connection_id']

        # Ensure the connection_id exists in the accounts table
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM accounts WHERE connection_id = ?', (connection_id,))
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

    # Retrieve user's contacts
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.id, a.username
        FROM accounts a
        JOIN contacts c ON c.client_id = a.id
        WHERE c.user_id = ?
    ''', (user_id,))
    contacts = cursor.fetchall()

    # Get the selected contact from the URL (if any)
    selected_contact = request.args.get('selected_contact')

    # Retrieve the selected contact's ID if selected_contact exists
    selected_contact_id = None
    if selected_contact:
        cursor.execute('SELECT id FROM accounts WHERE username = ?', (selected_contact,))
        contact = cursor.fetchone()
        if contact:
            selected_contact_id = contact[0]

    # Retrieve messages from the database if a contact is selected
    messages = []
    if selected_contact_id:
        cursor.execute('''
            SELECT sender_id, message, timestamp FROM messages
            WHERE (sender_id = ? AND recipient_id = ?)
            OR (sender_id = ? AND recipient_id = ?)
        ''', (user_id, selected_contact_id, selected_contact_id, user_id))
        messages = cursor.fetchall()

    # Decrypt each message
    decrypted_messages = []
    for sender_id, encrypted_message, timestamp in messages:
        decrypted_result = decrypt_message(shared_key, encrypted_message)
        decrypted_message = decrypted_result.get('decrypted_message', '[Error decrypting message]')
        
        decrypted_messages.append({
            'sender_id': sender_id,
            'message': decrypted_message,
            'timestamp': timestamp,
        })

    cursor.close()

    # Pass the selected_contact to the template for display
    return render_template('messages.html', messages=decrypted_messages, contacts=contacts, selected_contact=selected_contact)

@messaging_bp.route('/send_message', methods=['POST'])
def send_message():
    if 'loggedin' not in session:
        flash("You are not logged in.")
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
    print(f"Recipient: {recipient_username}, Message: {message}")
    
    if not recipient_username or not message:
        flash("Recipient or message is missing.")
        return redirect(url_for('messaging.view_messages'))
    
    # Fetch the recipient's ID
    cursor.execute('SELECT id FROM accounts WHERE username = ?', (recipient_username,))
    result = cursor.fetchone()
    if not result:
        flash("Recipient not found.")
        return redirect(url_for('messaging.view_messages'))
    
    recipient_id = result[0]
    
    # Check if shared key exists in session
    shared_key = session.get('shared_key')
    if not shared_key:
        flash("No shared key found. Please log in again.")
        return redirect(url_for('auth.login'))
    
    # Encrypt the message
    encrypted_message_data = encrypt_message(shared_key, message)
    
    if encrypted_message_data.get('status') == 'error':
        flash("Encryption failed: " + encrypted_message_data.get('message', 'Unknown error'))
        return redirect(url_for('messaging.view_messages'))
    
    encrypted_message = encrypted_message_data['encrypted_message']
    
    # Insert the encrypted message into the database
    try:
        cursor.execute('INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)',
                       (sender_id, recipient_id, encrypted_message))
        conn.commit()
        flash("Message sent successfully.")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to send message: {e}")
        print(f"Error: {e}")  # Debugging: print the error to the console
    
    cursor.close()
    return redirect(url_for('messaging.view_messages', selected_contact=recipient_username))