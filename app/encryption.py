from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64  


def derive_key(passphrase):
    salt = os.urandom(16) 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=48000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase))

def encrypt_Password(password, key):
    fernet = Fernet(key)
    encPassword = fernet.encrypt(password.encode())
    return encPassword

def decrypt_Password(encPassword, key):
    fernet = Fernet(key)
    return fernet.decrypt(encPassword).decode()
