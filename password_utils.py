import re
import string
import random
from encryption import encrypt_password
from database import backup_database

def add_password(conn, site, username, password, key):
    cursor = conn.cursor()
    encrypted_password, iv, tag = encrypt_password(password, key)
    username, iv, tag = encrypt_password(username, key)
    cursor.execute("INSERT INTO passwords (site, username, encrypted_password, iv, tag) VALUES (?, ?, ?, ?, ?)",
                   (site, username, encrypted_password, iv, tag))
    conn.commit()
    print("Mot de passe ajouté avec succès.")
    backup_database()

def remove_password(conn, site, username):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE site = ? AND username = ?", (site, username))
    conn.commit()
    if cursor.rowcount > 0:
        print("Mot de passe supprimé avec succès.")
        backup_database()
    else:
        print("Aucun mot de passe trouvé pour ce site et cet utilisateur.")

