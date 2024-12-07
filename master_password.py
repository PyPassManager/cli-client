import time
import getpass
import sys
import base64
import os
from encryption import derive_key, encrypt_password, decrypt_password
from security import create_attempts_table, check_security_integrity, update_security_hash
import logging
from cryptography.exceptions import InvalidTag

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# =========================================================================================================
# Fonctions pour définir et vérifier le mot de passe maître. Le mot de passe maître est utilisé pour chiffrer
# les mots de passe stockés dans la base de données.
# =========================================================================================================
def set_master_password(conn):
    cursor = conn.cursor()
    while True:
        master_password = getpass.getpass("Créez votre mot de passe maître : ")
        if len(master_password) < 12:
            print("Le mot de passe maître doit contenir au moins 12 caractères.")
            continue
        confirm_password = getpass.getpass("Confirmez votre mot de passe maître : ")
        if master_password != confirm_password:
            print("Les mots de passe ne correspondent pas.")
            continue
        break

    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    encrypted_password, iv, tag = encrypt_password(master_password, key)
    
    cursor.execute(
        "INSERT INTO master_password (encrypted_password, iv, salt, tag) VALUES (?, ?, ?, ?)",
        (encrypted_password, iv, base64.b64encode(salt).decode(), tag)
    )
    conn.commit()
    print("Mot de passe maître créé avec succès.")
    return master_password, salt


# =========================================================================================================
# Fonction pour vérifier le mot de passe maître. Cette fonction vérifie si le mot de passe maître existe
# déjà dans la base de données et le compare avec le mot de passe fourni par l'utilisateur.
# Cette fonction bloque également temporairement l'accès si le mot de passe est incorrect.
# =========================================================================================================
def check_master_password(conn):
    '''Fonction pour vérifier le mot de passe maître'''
    create_attempts_table(conn)
    check_security_integrity(conn)
    
    # Récupération du mot de passe maître de la base de données
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password, iv, salt, tag FROM master_password")
    result = cursor.fetchone()
    
    # Vérification des tentatives de connexion
    cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE id = 1")
    attempts_data = cursor.fetchone()
    attempts, last_attempt = attempts_data
    current_time = int(time.time())
    
    def get_wait_time(attempts):
        return 5 + max(0, (attempts - 3) * 5)

    wait_time = get_wait_time(attempts)
    
    if current_time - last_attempt < wait_time:
        remaining_time = wait_time - (current_time - last_attempt)
        print(f"Accès temporairement bloqué. Veuillez réessayer dans {int(remaining_time)} secondes.")
        conn.close()
        sys.exit()

    if result:
        encrypted_password, iv, salt, tag = result
        salt = base64.b64decode(salt)
        while True:
            master_password = getpass.getpass("Entrez votre mot de passe maître : ")
            key = derive_key(master_password, salt)
            try:
                decrypted_password = decrypt_password(encrypted_password, iv, tag, key)
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
            except InvalidTag:
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
        # Retourne les valeurs de set_master_password
        master_password, salt = set_master_password(conn)
        return master_password, salt
