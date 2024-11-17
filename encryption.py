from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os
import base64

def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_password(password, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode(), base64.b64encode(encryptor.tag).decode()

def decrypt_password(encrypted_password, iv, tag, key):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(base64.b64decode(iv), base64.b64decode(tag)), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()
    except InvalidTag:
        return "Invalid, Invalid, Invalid, Invalid".encode()
    
    

