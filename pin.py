from encryption import encrypt_password, decrypt_password, derive_key
from database import backup_database
import os
from utils import clear_cli
import time

# =========================================================================================================
# Fonctions pour gérer le code PIN
# Afin de pouvoir déchiffrer les mots de passe stockés, nous avons besoin du mot de passe principal. (master_password - derivekey)
# C'est pourquoi nous allons stocker la clé de chiffrement dans un fichier .key et la chiffrer à l'aide du code PIN.
# =========================================================================================================
def has_pin(conn):
    # Verify if the user has a key.key file
    if os.path.isfile("key.key"):
        return True
    return False

def set_pin(conn, key):
    # Generate salt
    salt = os.urandom(16)
    # Set a new pin code
    if has_pin(conn):
        print("Un code pin est déjà défini.")
        return
    # Encrypt master key with pincode
    pin = input("Entrez un code pin: ")
    # Derive key from pin
    derived_key = derive_key(pin, salt)
    # Encrypt the master key
    encrypted_key, iv, tag = encrypt_password(key, derived_key)
    # Write the encrypted key, salt, iv, and tag to a file
    with open("key.key", "wb") as file:
        file.write(salt + iv + tag + encrypted_key)
    print("Code pin défini avec succès.")
    backup_database(conn)

def auth_with_pin():
    # Authenticate with pin code
    pin = input("Entrez votre code pin: ")
    pin = pin.encode()
    # Read the encrypted key, salt, iv, and tag from the file
    with open("key.key", "rb") as file:
        data = file.read()
    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    encrypted_key = data[44:]
    # Derive key from pin
    derived_key = derive_key(pin, salt)
    # Decrypt the master key
    try:
        decrypted_key = decrypt_password(encrypted_key, iv, tag, derived_key)
    except Exception:
        print("Code pin incorrect.")
        return False
    return True

def auth_with_pin():
    # Authenticate with pin code
    pin = input("Entrez votre code pin: ")
    pin = pin.encode()
    # Read the encrypted key, salt, iv, and tag from the file
    with open("key.key", "rb") as file:
        data = file.read()
    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    encrypted_key = data[44:]
    # Derive key from pin
    derived_key = derive_key(pin, salt)
    # Decrypt the master key
    try:
        decrypted_key = decrypt_password(encrypted_key, iv, tag, derived_key)
    except Exception:
        print("Code pin incorrect.")
        return False
    return True

def auth_with_pin():
    # Authenticate with pin code
    pin = input("Entrez votre code pin: ")
    pin = pin.encode()
    # Read the encrypted key, salt, iv, and tag from the file
    with open("key.key", "rb") as file:
        data = file.read()
    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    encrypted_key = data[44:]
    # Derive key from pin
    derived_key = derive_key(pin, salt)
    # Decrypt the master key
    try:
        decrypted_key = decrypt_password(encrypted_key, iv, tag, derived_key)
    except Exception:
        print("Code pin incorrect.")
        return False
    return True

def auth_with_pin():
    # Authenticate with pin code
    pin = input("Entrez votre code pin: ")
    pin = pin.encode()
    # Derive key from pin
    derived_key = derive_key(pin)
    # Decrypt the master key
    with open("key.key", "rb") as file:
        encrypted_key = file.read()
    try:
        decrypted_key = decrypt_password(derived_key, encrypted_key)
    except:
        print("Code pin incorrect.")
        return False
    return True
    

def show_pin_interface(conn, key):
    clear_cli()
    print("Gestion du code pin")
    print("1. Définir un code pin")
    if has_pin(conn):
        print("1. Changer le code pin")
        print("2. Supprimer le code pin")
        print("3. Obtenir le code pin")
        print("4. DEBUG: Vérifier le code pin")
    print("9. Retour au menu principal")
    choice = input("Entrez votre choix: ")
    if choice == "1":
        set_pin(conn, key)
    elif choice == "4":
        auth_with_pin(conn, key)
    elif choice == "9":
        return
    else:
        print("Choix invalide.")
        time.sleep(1)
    show_pin_interface(conn, key)

