"""
Cryptographic keys and utilities for the Anime Recommendations API.
Keys are loaded from environment variables. Required variables:
  AES_KEY              - Base64-encoded 32-byte AES-256 key
  AES_IV               - Base64-encoded 16-byte AES initialization vector
  RSA_PRIVATE_KEY_PEM  - PEM-encoded RSA private key (newlines as \\n or literal)
  RSA_PUBLIC_KEY_PEM   - PEM-encoded RSA public key (newlines as \\n or literal)
  JWT_SECRET           - Secret string for JWT signing
"""

import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
import jwt
from datetime import datetime, timedelta
import os

# AES-256 key loaded from environment (base64-encoded 32-byte key)
AES_KEY = base64.b64decode(os.environ["AES_KEY"])

# AES initialization vector loaded from environment (base64-encoded 16-byte IV)
AES_IV = base64.b64decode(os.environ["AES_IV"])

# RSA keys loaded from environment variables (supports literal newlines or \\n-escaped)
RSA_PRIVATE_KEY_PEM = os.environ["RSA_PRIVATE_KEY_PEM"].replace("\\n", "\n").encode()

RSA_PUBLIC_KEY_PEM = os.environ["RSA_PUBLIC_KEY_PEM"].replace("\\n", "\n").encode()

# Load RSA keys
RSA_PRIVATE_KEY = load_pem_private_key(
    RSA_PRIVATE_KEY_PEM,
    password=None,
    backend=default_backend()
)

RSA_PUBLIC_KEY = load_pem_public_key(
    RSA_PUBLIC_KEY_PEM,
    backend=default_backend()
)

# JWT secret loaded from environment
JWT_SECRET = os.environ["JWT_SECRET"]

def encrypt_aes(plaintext):
    """Encrypt data using AES-256 in CBC mode with PKCS7 padding"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Create a padder for PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Create an encryptor
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64 encoded ciphertext
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes(ciphertext):
    """Decrypt data using AES-256 in CBC mode with PKCS7 padding"""
    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(ciphertext)
    
    # Create a decryptor
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Create an unpadder for PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    # Return the plaintext as a string
    return plaintext.decode('utf-8')

def sign_data_rsa(data):
    """Sign data using RSA private key"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    # Sign the data
    signature = RSA_PRIVATE_KEY.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Return base64 encoded signature
    return base64.b64encode(signature).decode('utf-8')

def verify_signature_rsa(data, signature):
    """Verify signature using RSA public key"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    # Decode the base64 encoded signature
    signature = base64.b64decode(signature)
    
    try:
        # Verify the signature
        RSA_PUBLIC_KEY.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_jwt(user_id, premium=False, expiration_hours=24):
    """Generate a JWT token"""
    payload = {
        'user_id': user_id,
        'premium': premium,
        'exp': datetime.utcnow() + timedelta(hours=expiration_hours)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def validate_jwt(token):
    """Validate a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}