import re
import string
import random
from encryption import encrypt_password, decrypt_password
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

def analyze_password_strength(password):
    score = 0
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    if len(set(password)) > 7:
        score += 1
    strengths = ["Très faible", "Faible", "Moyen", "Fort", "Très fort"]
    return strengths[score]

## TODO : Ajouter plus de paramètres pour personnaliser la génération de mot de passe ##
def generate_password():
    length = 16
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def export_passwords(conn, key):
    cursor = conn.cursor()
    cursor.execute("SELECT site, username, encrypted_password, iv, tag FROM passwords")
    passwords = cursor.fetchall()
    exported_data = []
    for site, username, encrypted_password, iv, tag in passwords:
        decrypted_password = decrypt_password(encrypted_password, iv, tag, key).decode()
        exported_data.append(f"{site},{username},{decrypted_password}")
    with open("exported_passwords.csv", "w") as f:
        f.write("\n".join(exported_data))
    print("Mots de passe exportés avec succès.")

def import_passwords(conn, key):
    with open("imported_passwords.csv", "r") as f:
        for line in f:
            site, username, password = line.strip().split(",")
            add_password(conn, site, username, password, key)
    print("Mots de passe importés avec succès.")
