from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend  # Add this import
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import hmac, hashlib

def derive_shared_key(private_key_bytes, peer_public_key):
    private_key = load_private_key(private_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    # Use HKDF to derive a symmetric key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def encrypt_message(public_key_pem, message):
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    # Encrypt the message
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def load_private_key(private_key_bytes, password=None):
    if password:
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=password,  
            backend=default_backend()
        )
    else:
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,  # No password if key is unencrypted
            backend=default_backend()
        )
    return private_key

def encrypt_private_key(private_key, passphrase):
    if not isinstance(passphrase, bytes):
        passphrase = passphrase.encode('utf-8')  # Convert passphrase to bytes if it's a string

    # Encrypt the private key with the passphrase
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    return encrypted_key

def aes_encrypt(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()

def generate_hmac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key, message, expected_hmac):
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(message)
    computed_hmac = hmac.finalize()
    return computed_hmac == expected_hmac