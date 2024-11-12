from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Encrypt message using AES symmetric encryption
def encrypt_message(shared_key, message):
    try:
        # Ensure shared_key is 32 bytes for AES-256
        iv = os.urandom(16)  # Initialization vector for AES
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the message to ensure block size compatibility
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        encrypted_message_base64 = base64.b64encode(iv + encrypted_message).decode('utf-8')
        
        return {'status': 'success', 'encrypted_message': encrypted_message_base64}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

# Decrypt message using AES symmetric encryption
def decrypt_message(shared_key, encrypted_message_base64):
    try:
        encrypted_message = base64.b64decode(encrypted_message_base64)
        iv = encrypted_message[:16]  # Extract the IV
        encrypted_data = encrypted_message[16:]
        
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding after decryption
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
        
        return {'status': 'success', 'decrypted_message': decrypted_message.decode('utf-8')}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}