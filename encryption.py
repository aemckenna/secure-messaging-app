from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Encrypt message using AES symmetric encryption in CBC mode
def encrypt_message(shared_key, message):
    # Ensure the shared_key is 256 bits (32 bytes)
    if len(shared_key) < 32:
        raise ValueError("Shared key must be at least 32 bytes (256 bits).")
    
    iv = os.urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad message to be a multiple of AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()  # 128-bit block size (AES)
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Combine IV with the encrypted message and encode in Base64
    encrypted_message_base64 = base64.b64encode(iv + encrypted_message).decode('utf-8')
    
    return {'status': 'success', 'encrypted_message': encrypted_message_base64}

# Decrypt message using AES symmetric encryption in CBC mode
def decrypt_message(shared_key, encrypted_message_base64):
    # Decode the Base64-encoded message
    encrypted_message = base64.b64decode(encrypted_message_base64)
    iv = encrypted_message[:16]  # Extract the IV (first 16 bytes)
    encrypted_data = encrypted_message[16:]  # The rest is the encrypted message

    # Ensure the shared_key is 256 bits (32 bytes)
    if len(shared_key) < 32:
        raise ValueError("Shared key must be at least 32 bytes (256 bits).")

    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_padded_message = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    return {'status': 'success', 'decrypted_message': decrypted_message.decode('utf-8')}