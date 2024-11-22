import re
import string
import random
from encryption import encrypt_password, decrypt_password
from database import backup_database


# Ajoute un mot de passe à la base de données et le chiffre en utilisant la clé fournie
def add_password(conn, site, username, password, key):
    cursor = conn.cursor()
    encrypted_password, iv, tag = encrypt_password(password, key)
    username, iv, tag = encrypt_password(username, key)
    cursor.execute("INSERT INTO passwords (site, username, encrypted_password, iv, tag) VALUES (?, ?, ?, ?, ?)",
                   (site, username, encrypted_password, iv, tag))
    conn.commit()
    print("Mot de passe ajouté avec succès.")
    backup_database()

# Supprime un mot de passe de la base de données
def remove_password(conn, site, username):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE site = ? AND username = ?", (site, username))
    conn.commit()
    if cursor.rowcount > 0:
        print("Mot de passe supprimé avec succès.")
        backup_database()
    else:
        print("Aucun mot de passe trouvé pour ce site et cet utilisateur.")

def list_passwords(conn, key):
    cursor = conn.cursor()
    cursor.execute("SELECT site, username, encrypted_password, iv, tag FROM passwords")
    results = cursor.fetchall()
    for result in results:
        site, username, encrypted_password, iv, tag = result
        decrypted_password = decrypt_password(encrypted_password, iv, tag, key).decode()
        decrypted_username = decrypt_password(username, iv, tag, key).decode()
        print(f"Site : {site}, Utilisateur : {decrypted_username}, Mot de passe : {decrypted_password}")


