import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ==================================================================================================
# Ce code fournit des fonctions pour dériver une clé à partir d'un mot de passe, chiffrer un mot de
# passe et déchiffrer un mot de passe chiffré en utilisant la bibliothèque cryptography en Python.
# ==================================================================================================


# ==================================================================================================
# La fonction derive_key prend un mot de passe et un sel (salt) en entrée et utilise la fonction de 
# dérivation de clé Scrypt pour générer une clé de 32 octets. Scrypt est conçu pour être intensif en
# calcul afin de résister aux attaques par force brute.
# ==================================================================================================
def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ==================================================================================================
# INFOS :
# # Le "salt" (sel) est une donnée aléatoire ajoutée au mot de passe avant la dérivation de la clé. 
# Il permet de rendre chaque dérivation de clé unique, même si le même mot de passe est utilisé. 
# Cela empêche les attaques par table de hachage pré-calculée (rainbow tables).

# L'"iv" (vecteur d'initialisation) est une donnée aléatoire utilisée lors du chiffrement pour garantir 
# que le même texte en clair chiffré plusieurs fois avec la même clé produira des textes chiffrés différents. 
# Cela ajoute une couche de sécurité en rendant les attaques par analyse statistique plus difficiles.

# Le "tag" (étiquette d'authentification) est utilisé en mode GCM pour assurer l'intégrité et l'authenticité 
# des données chiffrées. Il permet de vérifier que les données n'ont pas été modifiées ou falsifiées pendant 
# le transport ou le stockage. Si le tag ne correspond pas lors du déchiffrement, une erreur est levée.
# ==================================================================================================

# ==================================================================================================
# Ici, la fonction encrypt_password prend un mot de passe en clair et une clé en entrée, puis chiffre
# le mot de passe en utilisant l'algorithme AES
# ==================================================================================================
def encrypt_password(password, key):
    iv = os.urandom(12)  # IV pour AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(iv).decode(),
        base64.b64encode(encryptor.tag).decode()
    )


# ==================================================================================================
# La fonction decrypt_password permet de déchiffrer un mot de passe chiffré en utilisant la clé de
# chiffrement. Si le tag ne correspond pas, une exception InvalidTag est levée.
# ==================================================================================================
def decrypt_password(encrypted_password, iv, tag, key):
    try:
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(base64.b64decode(iv), base64.b64decode(tag)),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()
        return plaintext.decode("utf-8")
    except Exception as e:
        return f"Erreur de déchiffrement : {str(e)}"