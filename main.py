import sys
from database import create_connection, create_tables, backup_database
from security import check_master_password
from encryption import derive_key
from password_utils import add_password, remove_password, analyze_password_strength, generate_password
from totp import add_totp, get_totp
import base64

def main():
    conn = create_connection()
    create_tables(conn)
    master_password, salt = check_master_password(conn)
    if master_password is None:
        print("ERREUR CRITIQUE : LE MOT DE PASSE MAÎTRE EST NULL.")
        sys.exit()
    
    key = derive_key(master_password, salt)
    
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
            password = input("Entrez le mot de passe : ")
            add_password(conn, site, username, password, key)
        elif choice == '2':
            site = input("Entrez le nom du site : ")
            username = input("Entrez le nom d'utilisateur : ")
            remove_password(conn, site, username)
        elif choice == '3':
            password = input("Entrez le mot de passe à analyser : ")
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
        elif choice == '9':
            print("Au revoir !")
            conn.close()
            sys.exit()
        else:
            print("Option invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()
