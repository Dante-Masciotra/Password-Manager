from cryptography.fernet import Fernet
    
def generate_Key():
 return Fernet.generate_key()

def encrypt_Password(password, key):
    fernet = Fernet(key)
    encPassword = fernet.encrypt(password.encode())
    return encPassword

def decrypt_Password(encPassword, key):
    fernet = Fernet(key)
    return fernet.decrypt(encPassword).decode()

