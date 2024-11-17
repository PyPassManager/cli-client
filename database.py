import sqlite3
import os
import getpass
from encryption import encrypt_password, derive_key
import shutil

def create_connection():
    conn = sqlite3.connect('passwords.db')
    return conn

def create_tables(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_password
                      (id INTEGER PRIMARY KEY, encrypted_password BLOB, iv BLOB, salt BLOB, tag BLOB)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (id INTEGER PRIMARY KEY, site TEXT, username TEXT, encrypted_password BLOB, iv BLOB, tag BLOB)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS totp
                      (id INTEGER PRIMARY KEY, site TEXT, secret TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                      (id INTEGER PRIMARY KEY, attempts INTEGER, last_attempt INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS security
                      (id INTEGER PRIMARY KEY, login_attempts_hash TEXT, master_password_hash TEXT, last_hash_time INTEGER)''')
    conn.commit()

def backup_database():
    try:
        shutil.copyfile('passwords.db', 'passwords_backup.db')
        print("Base de données sauvegardée avec succès.")
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de la base de données : {e}")

def restore_database():
    try:
        shutil.copyfile('passwords_backup.db', 'passwords.db')
        print("Base de données restaurée avec succès.")
    except Exception as e:
        print(f"Erreur lors de la restauration de la base de données : {e}")

def set_master_password(conn):
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
    
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    encrypted_password, iv, tag = encrypt_password(master_password, key)
    
    cursor.execute("INSERT INTO master_password (encrypted_password, iv, salt, tag) VALUES (?, ?, ?, ?)",
                   (encrypted_password, iv, salt, tag))
    conn.commit()
    print("Mot de passe maître créé avec succès.")
    backup_database()
    return master_password

def get_master_password_data(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password, iv, salt, tag FROM master_password")
    return cursor.fetchone()

def get_login_attempts(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE id = 1")
    return cursor.fetchone()

def update_login_attempts(conn, attempts, last_attempt):
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO login_attempts (id, attempts, last_attempt) VALUES (1, ?, ?)",
                   (attempts, last_attempt))
    conn.commit()

