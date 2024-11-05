from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair with passphrase encryption
def generate_key_pair(passphrase: bytes):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return encrypted_private_key, public_key_pem

# Encrypt message with recipient's public key
def encrypt_message(public_key_pem, message):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return {'status': 'success', 'encrypted_message': encrypted_message}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

# Decrypt message with user's private key
def decrypt_message(encrypted_message, private_key_pem, passphrase):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=passphrase, backend=default_backend()
        )
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return {'status': 'success', 'decrypted_message': decrypted_message.decode()}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}