import sqlite3
import random
import string
import os
from cryptography.fernet import Fernet
from getpass import getpass
import datetime
import hashlib

# Initialisation
DB_FILE = "passwords-pypass.db"
KEY_FILE = "key-pypass.key"
MASTER_PASSWORD_FILE = "master-password-pypass.key"
PIN_FILE = "pin-pypass.key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  identifiant TEXT NOT NULL,
                  password TEXT NOT NULL,
                  url TEXT,
                  a2f_bool BOOLEAN DEFAULT FALSE,
                  favorites BOOLEAN DEFAULT FALSE,
                  master_password_requirered_bool BOOLEAN DEFAULT FALSE,
                  otp TEXT,
                  notes TEXT,
                  folder TEXT,
                  created_at DATETIME NOT NULL,
                  updated_at DATETIME NOT NULL)''')
    conn.commit()
    conn.close()

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def analyze_password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    
    if score == 5:
        return "Très fort"
    elif score == 4:
        return "Fort"
    elif score == 3:
        return "Moyen"
    else:
        return "Faible"

def add_password(name, identifiant, password, key, url=None, a2f_bool=False, favorites=False, master_password_requirered_bool=False, otp=None, notes=None, folder=None):
    encrypted_password = encrypt_password(password, key)
    now = datetime.datetime.now(datetime.UTC).isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("""INSERT INTO passwords 
                     (name, identifiant, password, url, a2f_bool, favorites, master_password_requirered_bool, otp, notes, folder, created_at, updated_at) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (name, identifiant, encrypted_password, url, a2f_bool, favorites, master_password_requirered_bool, otp, notes, folder, now, now))
        conn.commit()
        print(f"Mot de passe pour {name} ajouté avec succès.")
    except sqlite3.IntegrityError:
        print(f"Un mot de passe pour {name} existe déjà.")
    finally:
        conn.close()


def retrieve_password(name, key):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM passwords WHERE name = ?", (name,))
    result = c.fetchone()
    conn.close()
    if result:
        return decrypt_password(result[0], key)
    else:
        return None

def list_passwords(key):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT name, identifiant, password, url, created_at, updated_at FROM passwords")
    for row in c.fetchall():
        name, identifiant, encrypted_password, url, created_at, updated_at = row
        decrypted_password = decrypt_password(encrypted_password, key)
        strength = analyze_password_strength(decrypted_password)
        print("-" * 30)
        print(f"Nom: {name}")
        print(f"Identifiant: {identifiant}")
        print(f"Mot de passe: {decrypted_password}")
        print(f"URL: {url}")
        print(f"Force: {strength}")
        print(f"Créé le: {created_at}")
        print(f"Mis à jour le: {updated_at}")
        print("-" * 30)
    conn.close()

def delete_password(name):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE name = ?", (name,))
    if c.rowcount > 0:
        conn.commit()
        print(f"Mot de passe pour {name} supprimé avec succès.")
    else:
        print(f"Aucun mot de passe trouvé pour {name}.")
    conn.close()

def modify_password(name, new_password, key):
    encrypted_password = encrypt_password(new_password, key)
    now = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE passwords SET password = ?, updated_at = ? WHERE name = ?",
              (encrypted_password, now, name))
    if c.rowcount > 0:
        conn.commit()
        print(f"Mot de passe pour {name} modifié avec succès.")
    else:
        print(f"Aucun mot de passe trouvé pour {name}.")
    conn.close()

def set_master_password():
    while True:
        master_password = getpass("Définissez un mot de passe maître (minimum 8 caractères) : ")
        if len(master_password) >= 8:
            hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
            with open(MASTER_PASSWORD_FILE, "w") as file:
                file.write(hashed_password)
            print("Mot de passe maître défini avec succès.")
            return
        else:
            print("Le mot de passe maître doit contenir au moins 8 caractères. Réessayez.")

def set_pin():
    while True:
        pin = getpass("Définissez un code PIN (4 à 6 chiffres) : ")
        if 4 <= len(pin) <= 6 and pin.isdigit():
            hashed_pin = hashlib.sha256(pin.encode()).hexdigest()
            with open(PIN_FILE, "w") as file:
                file.write(hashed_pin)
            print("Code PIN défini avec succès.")
            return
        else:
            print("Le code PIN doit contenir entre 4 et 6 chiffres. Réessayez.")

def verify_credentials():
    if not os.path.exists(MASTER_PASSWORD_FILE) or not os.path.exists(PIN_FILE):
        print("Configuration initiale requise.")
        set_master_password()
        set_pin()
        return True

    with open(MASTER_PASSWORD_FILE, "r") as file:
        stored_master_hash = file.read().strip()
    with open(PIN_FILE, "r") as file:
        stored_pin_hash = file.read().strip()

    attempts = 3
    while attempts > 0:
        choice = getpass("Entrez votre mot de passe maître ou votre code PIN : ").upper()
        hashed_input = hashlib.sha256(choice.encode()).hexdigest()
        if hashed_input == stored_master_hash or hashed_input == stored_pin_hash:
            return True
        attempts -= 1
        print(f"Identifiants incorrects. Il vous reste {attempts} tentative(s).")

    print("Nombre maximal de tentatives atteint. Accès refusé.")
    return False

def main():
    if not os.path.exists(KEY_FILE):
        print("Génération d'une nouvelle clé de chiffrement...")
        generate_key()
    
    key = load_key()
    init_db()
    
    if not os.path.exists(MASTER_PASSWORD_FILE) or not os.path.exists(PIN_FILE):
        print("Première utilisation détectée. Configuration initiale requise.")
        set_master_password()
        set_pin()
    else:
        if not verify_credentials():
            return

    while True:
        print("\n--- Gestionnaire de Mots de Passe ---")
        print("1. Ajouter un mot de passe")
        print("2. Récupérer un mot de passe")
        print("3. Lister tous les mots de passe")
        print("4. Supprimer un mot de passe")
        print("5. Modifier un mot de passe")
        print("6. Générer un mot de passe")
        print("7. Changer les identifiants")
        print("8. Quitter")
        
        choice = input("Entrez votre choix : ")
        
        if choice == '1':
            name = input("Entrez le nom du compte : ")
            identifiant = input("Entrez l'identifiant : ")
            password = getpass("Entrez le mot de passe : ")
            url = input("Entrez l'URL : ")
            add_password(name,identifiant, password, key, url)
        elif choice == '2':
            name = input("Entrez le nom du compte : ")
            password = retrieve_password(name, key)
            if password:
                print(f"Mot de passe pour {name} : {password}")
            else:
                print(f"Aucun mot de passe trouvé pour {name}.")
        elif choice == '3':
            list_passwords(key)
        elif choice == '4':
            name = input("Entrez le nom du compte à supprimer : ")
            delete_password(name)
        elif choice == '5':
            name = input("Entrez le nom du compte à modifier : ")
            new_password = getpass("Entrez le nouveau mot de passe : ")
            modify_password(name, new_password, key)
        elif choice == '6':
            length = int(input("Entrez la longueur du mot de passe à générer : "))
            password = generate_password(length)
            print(f"Mot de passe généré : {password}")
            print(f"Force : {analyze_password_strength(password)}")
        elif choice == '7':
            print("1. Changer le mot de passe maître")
            print("2. Changer le code PIN")
            sub_choice = input("Entrez votre choix : ")
            if sub_choice == '1':
                if verify_credentials():
                    set_master_password()
                else:
                    print("Échec de la vérification des identifiants. Opération annulée.")
            elif sub_choice == '2':
                if verify_credentials():
                    set_pin()
                else:
                    print("Échec de la vérification des identifiants. Opération annulée.")
            else:
                print("Choix invalide.")
        elif choice == '8':
            print("Au revoir !")
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()
