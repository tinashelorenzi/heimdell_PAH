# -*- coding: utf-8 -*-
#!/usr/bin/env python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os

def generate_keypair():
    """
    Generates a public and private key pair using RSA encryption.

    Returns:
        tuple: A tuple containing the private and public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def check_keypair(public_key, private_key):
    """
    Checks if a given public and private key pair are valid.

    Args:
        public_key: The public key to check.
        private_key: The private key to check.

    Returns:
        bool: True if the key pair is valid, False otherwise.
    """
    message = b"Hello, World!"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def sign_message(private_key, message):
    """
    Signs a message using a private key.

    Args:
        private_key: The private key to sign with.
        message: The message to sign.

    Returns:
        bytes: The signature.
    """
    # Ensure message is bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
        
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """
    Verifies a signature using a public key.

    Args:
        public_key: The public key to verify with.
        message: The message that was signed.
        signature: The signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    # Ensure message is bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
        
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def get_public_key_pem(public_key):
    """
    Returns a PEM encoded string of the given public key.

    Args:
        public_key: The public key to encode.

    Returns:
        str: The PEM encoded public key as a string.
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')

def get_private_key_pem(private_key, password=None):
    """
    Returns a PEM encoded string of the given private key.

    Args:
        private_key: The private key to encode.
        password: Optional password to encrypt the key.

    Returns:
        str: The PEM encoded private key as a string.
    """
    encryption_algorithm = serialization.NoEncryption()
    if password:
        if isinstance(password, str):
            password = password.encode('utf-8')
        encryption_algorithm = serialization.BestAvailableEncryption(password)
        
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    return pem_bytes.decode('utf-8')

def get_public_key_from_pem(pem):
    """
    Returns a public key object from a given PEM encoded string.

    Args:
        pem: The PEM encoded public key string.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: The public key object.
    """
    if isinstance(pem, str):
        pem = pem.encode('utf-8')
        
    return serialization.load_pem_public_key(pem)

def get_private_key_from_pem(pem, password=None):
    """
    Returns a private key object from a given PEM encoded string.

    Args:
        pem: The PEM encoded private key string.
        password: Optional password to decrypt the key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: The private key object.
    """
    if isinstance(pem, str):
        pem = pem.encode('utf-8')
        
    if password and isinstance(password, str):
        password = password.encode('utf-8')
        
    return serialization.load_pem_private_key(pem, password=password)