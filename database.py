import sqlite3
import shutil

def create_connection():
    '''Fonction pour créer une connexion à la base de données'''
    conn = sqlite3.connect('passwords.db')
    return conn

def create_tables(conn):
    '''Fonction pour créer les tables de la base de données lors de la première exécution'''
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
    '''Fonction pour sauvegarder la base de données'''
    try:
        shutil.copyfile('passwords.db', 'passwords_backup.db')
        print("Base de données sauvegardée avec succès.")
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de la base de données : {e}")

def restore_database():
    '''Sauvegarde la base de données à partir du fichier de sauvegarde'''
    try:
        shutil.copyfile('passwords_backup.db', 'passwords.db')
        print("Base de données restaurée avec succès.")
    except Exception as e:
        print(f"Erreur lors de la restauration de la base de données : {e}")


