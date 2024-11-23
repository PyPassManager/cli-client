import sqlite3
import shutil
import os

#=========================================================================================================
# Ce fichier contient les fonctions pour créer une connexion à la base de données, créer les tables de la
# base de données lors de la première exécution, sauvegarder et restaurer la base de données.
#=========================================================================================================

def create_connection():
    '''Fonction pour créer une connexion à la base de données'''
    return sqlite3.connect('passwords.db')
     

def create_tables(conn):
    '''Fonction pour créer les tables de la base de données lors de la première exécution'''
    cursor = conn.cursor()
    tables = [
        '''CREATE TABLE IF NOT EXISTS master_password (id INTEGER PRIMARY KEY, encrypted_password BLOB, iv BLOB, salt BLOB, tag BLOB)''',
        '''CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, site TEXT, username BLOB, encrypted_password BLOB, iv_password BLOB, iv_username BLOB, tag_password BLOB, tag_username BLOB)''',
        '''CREATE TABLE IF NOT EXISTS totp (id INTEGER PRIMARY KEY, site TEXT, secret TEXT)''',
        '''CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY, attempts INTEGER, last_attempt INTEGER)''',
        '''CREATE TABLE IF NOT EXISTS security (id INTEGER PRIMARY KEY, login_attempts_hash TEXT, master_password_hash TEXT, last_hash_time INTEGER)'''
    ]
    for table in tables: # Permet d'optimiser la création des tables
        cursor.execute(table)
    conn.commit()
    os.chmod('passwords.db',0o600) # Implémenté par Yoann pour sécuriser la base de données

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


