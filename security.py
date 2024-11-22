import time
import hashlib
import getpass
import sys
import base64
import os
import re
from database import create_connection
from encryption import derive_key, encrypt_password, decrypt_password
from database import backup_database, restore_database

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

def update_security_hash(conn):
    '''Fonction pour mettre à jour le hachage de sécurité'''
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
    '''Fonction pour vérifier l'intégrité de la base de données'''
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
            if stored_hash != current_hash or current_time < stored_time:
                print("Sécurité compromise.")
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
    '''Fonction pour définir le mot de passe maître'''
    # Connexion à la base de données et création du mot de passe maître
    cursor = conn.cursor()
    while True:
        master_password = getpass.getpass("Créez votre mot de passe maître : ")
        if len(master_password) < 12:
            print("Le mot de passe maître doit contenir au moins 12 caractères.")
            continue
        confirm_password = getpass.getpass("Confirmez votre mot de passe maître : ")
        if master_password != confirm_password:
            print("Les mots de passe ne correspondent pas. Veuillez réessayer.")
            continue
        break
    
    # Génération des clés de chiffrement
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    encrypted_password, iv, tag = encrypt_password(master_password, key)
    
    # Insertion du mot de passe maître dans la base de données
    cursor.execute("INSERT INTO master_password (encrypted_password, iv, salt, tag) VALUES (?, ?, ?, ?)",
                   (encrypted_password, iv, base64.b64encode(salt).decode(), tag))
    conn.commit()
    print("Mot de passe maître créé avec succès.")
    backup_database()
    return master_password, base64.b64encode(salt).decode()

def check_master_password(conn):
    '''Fonction pour vérifier le mot de passe maître'''
    create_attempts_table(conn)
    check_security_integrity(conn)
    
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password, iv, salt, tag FROM master_password")
    result = cursor.fetchone()
    
    cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE id = 1")
    attempts_data = cursor.fetchone()
    attempts, last_attempt = attempts_data
    current_time = int(time.time())
    
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

    # Vérification de l'existence du mot de passe maître
    if result:
        encrypted_password, iv, salt, tag = result
        salt = base64.b64decode(salt)
        while True:
            master_password = getpass.getpass("Entrez votre mot de passe maître : ")
            key = derive_key(master_password, salt)
            decrypted_password = decrypt_password(encrypted_password, iv, tag, key).decode()
            if decrypted_password == master_password:
                print("Mot de passe correct !")
                cursor.execute("UPDATE login_attempts SET attempts = 0, last_attempt = 0 WHERE id = 1")
                conn.commit()
                update_security_hash(conn)
                return master_password, salt
            else:
                print("Mot de passe incorrect.")
                attempts += 1
                current_time = int(time.time())
                cursor.execute("UPDATE login_attempts SET attempts = ?, last_attempt = ? WHERE id = 1", (attempts, current_time))
                conn.commit()
                update_security_hash(conn)
                wait_time = get_wait_time(attempts)
                print(f"Prochaine tentative possible dans {wait_time} secondes.")
                time.sleep(wait_time)
    else:
        return set_master_password(conn)


def reset_login_attempts(conn):
    '''Fonction pour réinitialiser les tentatives de connexion'''
    cursor = conn.cursor()
    cursor.execute("UPDATE login_attempts SET attempts = 0, last_attempt = 0 WHERE id = 1")
    conn.commit()
    update_security_hash(conn)








