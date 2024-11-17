import sqlite3
import hashlib
import getpass
import sys
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import re
import qrcode
import pyotp
import requests
import shutil

def create_connection():
    conn = sqlite3.connect('passwords.db')
    return conn

def create_security_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security (
            id INTEGER PRIMARY KEY,
            login_attempts_hash TEXT,
            last_hash_time INTEGER
        )
    ''')
    conn.commit()

def create_attempts_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY,
            attempts INTEGER,
            last_attempt INTEGER
        )
    ''')
    cursor.execute('''
        INSERT OR IGNORE INTO login_attempts (id, attempts, last_attempt)
        VALUES (1, 0, 0)
    ''')
    conn.commit()

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_password
                      (id INTEGER PRIMARY KEY, hashed_password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (id INTEGER PRIMARY KEY, site TEXT, username TEXT, encrypted_password TEXT, iv TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS totp
                      (id INTEGER PRIMARY KEY, site TEXT, secret TEXT)''')
    conn.commit()

def backup_database():
    try:
        shutil.copyfile('passwords.db', 'passwords_backup.db')
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de la base de données : {e}")

def restore_database():
    try:
        shutil.copyfile('passwords_backup.db', 'passwords.db')
        print("Base de données restaurée avec succès.")
    except Exception as e:
        print(f"Erreur lors de la restauration de la base de données : {e}")

def get_online_time():
    try:
        response = requests.get('https://timeapi.io/api/time/current/zone?timeZone=Europe%2FParis', timeout=5)
        if response.status_code == 200:
            data = response.json()
            datetime_str = data['dateTime']
            online_time = int(time.mktime(time.strptime(datetime_str[:19], "%Y-%m-%dT%H:%M:%S")))
            return online_time
        else:
            print("Impossible de récupérer l'heure en ligne.")
            return None
    except:
        print("Impossible de récupérer l'heure en ligne.")
        return None

def update_security_hash(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE id = 1")
    attempts_data = cursor.fetchone()
    if attempts_data:
        data_str = f"{attempts_data[0]}:{attempts_data[1]}"
        hash_value = hashlib.sha256(data_str.encode()).hexdigest()
        current_time = int(time.time())
        cursor.execute("REPLACE INTO security (id, login_attempts_hash, last_hash_time) VALUES (1, ?, ?)",
                       (hash_value, current_time))
        conn.commit()
        backup_database()

def check_security_integrity(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT login_attempts_hash, last_hash_time FROM security WHERE id = 1")
    result = cursor.fetchone()
    if result:
        stored_hash, stored_time = result
        cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE id = 1")
        attempts_data = cursor.fetchone()
        if attempts_data:
            data_str = f"{attempts_data[0]}:{attempts_data[1]}"
            current_hash = hashlib.sha256(data_str.encode()).hexdigest()
            current_time = int(time.time())
            online_time = get_online_time()
            if stored_hash != current_hash:
                print("Sécurité compromise ! (Données de tentative de connexion modifiées).")
                restore = input("Voulez-vous restaurer la base de données à partir de la sauvegarde ? (Y/N) : ")
                if restore.upper() == 'Y':
                    conn.close()
                    restore_database()
                    sys.exit()
                else:
                    conn.close()
                    sys.exit()
            if online_time and abs(current_time - online_time) > 300:
                print("Sécurité compromise ! (Heure du système incorrecte).")
                print("Assurez-vous que l'heure de votre système est correcte.")
                conn.close()
                sys.exit()
            if current_time < stored_time:
                print("Sécurité compromise (Retour dans le temps détecté).")
                restore = input("Voulez-vous restaurer la base de données à partir de la sauvegarde ? (Y/N) : ")
                if restore.upper() == 'Y':
                    conn.close()
                    restore_database()
                    sys.exit()
                else:
                    conn.close()
                    sys.exit()
    else:
        update_security_hash(conn)

def set_master_password(conn):
    cursor = conn.cursor()
    while True:
        master_password = getpass.getpass("Créez votre mot de passe maître : ")
        if len(master_password) < 8:
            print("Le mot de passe maître doit contenir au moins 8 caractères.")
            continue
        confirm_password = getpass.getpass("Confirmez votre mot de passe maître : ")
        if master_password != confirm_password:
            print("Les mots de passe ne correspondent pas. Veuillez réessayer.")
            continue
        break
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    cursor.execute("INSERT INTO master_password (hashed_password) VALUES (?)", (hashed_password,))
    conn.commit()
    print("Mot de passe maître créé avec succès.")
    backup_database()
    return master_password

def check_master_password(conn):
    create_attempts_table(conn)
    create_security_table(conn)
    check_security_integrity(conn)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password FROM master_password")
    result = cursor.fetchone()
    cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE id = 1")
    attempts_data = cursor.fetchone()
    attempts, last_attempt = attempts_data
    current_time = int(time.time())

    print(f"Tentatives actuelles : {attempts}")
    print(f"Dernière tentative : {time.ctime(last_attempt)}")

    def get_wait_time(attempts):
        if attempts <= 3:
            return 5
        return 5 + (attempts - 3) * 5

    wait_time = get_wait_time(attempts)
    
    if current_time - last_attempt < wait_time:
        remaining_time = wait_time - (current_time - last_attempt)
        print(f"Accès temporairement bloqué. Veuillez réessayer dans {int(remaining_time)} secondes.")
        conn.close()
        sys.exit()

    if result:
        stored_hash = result[0]
        while True:
            master_password = getpass.getpass("Entrez votre mot de passe maître : ")
            print("Vérification du mot de passe...")
            if hashlib.sha256(master_password.encode()).hexdigest() == stored_hash:
                print("Mot de passe correct !")
                cursor.execute("UPDATE login_attempts SET attempts = 0, last_attempt = 0 WHERE id = 1")
                conn.commit()
                update_security_hash(conn)
                return master_password
            else:
                print("Mot de passe incorrect.")
                attempts += 1
                current_time = int(time.time())
                cursor.execute("UPDATE login_attempts SET attempts = ?, last_attempt = ? WHERE id = 1", (attempts, current_time))
                conn.commit()
                update_security_hash(conn)
                wait_time = get_wait_time(attempts)
                print(f"Nombre de tentatives : {attempts}")
                print(f"Prochaine tentative possible dans {wait_time} secondes.")
                time.sleep(wait_time)
    else:
        print("Aucun mot de passe maître trouvé. Création d'un nouveau mot de passe.")
        return set_master_password(conn)

def encrypt_password(password, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

def decrypt_password(encrypted_password, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(base64.b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()

def add_password(conn, site, username, password, key):
    cursor = conn.cursor()
    encrypted_password, iv = encrypt_password(password, key)
    cursor.execute("INSERT INTO passwords (site, username, encrypted_password, iv) VALUES (?, ?, ?, ?)",
                   (site, username, encrypted_password, iv))
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

def generate_password():
    import random
    import string
    length = 16
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def add_totp(conn, site, secret):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO totp (site, secret) VALUES (?, ?)", (site, secret))
    conn.commit()
    print("TOTP ajouté avec succès.")
    backup_database()

def get_totp(conn, site):
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM totp WHERE site = ?", (site,))
    result = cursor.fetchone()
    if result:
        totp = pyotp.TOTP(result[0])
        return totp.now()
    else:
        return "Aucun TOTP trouvé pour ce site."

def export_passwords(conn, key):
    cursor = conn.cursor()
    cursor.execute("SELECT site, username, encrypted_password, iv FROM passwords")
    passwords = cursor.fetchall()
    exported_data = []
    for site, username, encrypted_password, iv in passwords:
        decrypted_password = decrypt_password(encrypted_password, iv, key).decode()
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

def main():
    conn = create_connection()
    create_table(conn)
    master_password = check_master_password(conn)
    if master_password is None:
        print("ERREUR CRITIQUE : LE MOT DE PASSE MAÎTRE EST NULL.")
        sys.exit()
    key = hashlib.sha256(master_password.encode()).digest()
    while True:
        print("\n1. Ajouter un mot de passe")
        print("2. Supprimer un mot de passe")
        print("3. Analyser la force d'un mot de passe")
        print("4. Générer un mot de passe")
        print("5. Ajouter un TOTP")
        print("6. Obtenir un code TOTP")
        print("7. Exporter les mots de passe")
        print("8. Importer des mots de passe")
        print("9. Quitter")
        choice = input("Choisissez une option : ")
        if choice == '1':
            site = input("Entrez le nom du site : ")
            username = input("Entrez le nom d'utilisateur : ")
            password = getpass.getpass("Entrez le mot de passe : ")
            add_password(conn, site, username, password, key)
        elif choice == '2':
            site = input("Entrez le nom du site : ")
            username = input("Entrez le nom d'utilisateur : ")
            remove_password(conn, site, username)
        elif choice == '3':
            password = getpass.getpass("Entrez le mot de passe à analyser : ")
            strength = analyze_password_strength(password)
            print(f"Force du mot de passe : {strength}")
        elif choice == '4':
            generated_password = generate_password()
            print(f"Mot de passe généré : {generated_password}")
        elif choice == '5':
            site = input("Entrez le nom du site pour le TOTP : ")
            secret = input("Entrez le secret TOTP : ")
            add_totp(conn, site, secret)
        elif choice == '6':
            site = input("Entrez le nom du site pour obtenir le code TOTP : ")
            totp_code = get_totp(conn, site)
            print(f"Code TOTP : {totp_code}")
        elif choice == '7':
            export_passwords(conn, key)
        elif choice == '8':
            import_passwords(conn, key)
        elif choice == '9':
            print("Au revoir !")
            conn.close()
            sys.exit()
        else:
            print("Option invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()