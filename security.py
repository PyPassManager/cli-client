import time
import hashlib
import sys
from database import backup_database, restore_database

# =========================================================================================================
# Ce fichier contient les fonctions pour vérifier le mot de passe maître, réinitialiser les tentatives de
# connexion et mettre à jour le hachage de sécurité.
# =========================================================================================================

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

# =========================================================================================================
# Fonctions pour mettre à jour le hachage de sécurité. Le hachage de sécurité est utilisé pour vérifier
# l'intégrité des données de la base de données et pour empêcher les attaques par modification des données.
# =========================================================================================================
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

# =========================================================================================================
# Fonctions pour vérifier l'intégrité de la base de données. Cette fonction compare le hachage de sécurité
# stocké dans la base de données avec le hachage actuel des tentatives de connexion
# =========================================================================================================
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


# =========================================================================================================
# Fonction pour réinitialiser les tentatives de connexion. Cette fonction réinitialise le compteur de
# tentatives de connexion et met à jour le hachage de sécurité.
# =========================================================================================================
def reset_login_attempts(conn):
    '''Fonction pour réinitialiser les tentatives de connexion'''
    cursor = conn.cursor()
    cursor.execute("UPDATE login_attempts SET attempts = 0, last_attempt = 0 WHERE id = 1")
    conn.commit()
    update_security_hash(conn)








