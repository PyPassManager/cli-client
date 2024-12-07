import sys
from database import create_connection, create_tables
from master_password import check_master_password
from encryption import derive_key
from password_utils import add_password, remove_password, list_passwords
from pin import show_pin_interface
from auth import authenticate_user

def main():
    conn = create_connection()
    create_tables(conn)
    key, master_password, salt = authenticate_user(conn)

    if key is None:
        print("Échec de l'authentification.")
        sys.exit()

    while True:
        print("0. Lister les mots de passe")
        print("\n1. Ajouter un mot de passe")
        print("2. Supprimer un mot de passe")
        print("3. Paramètre de code PIN")
        print("9. Quitter")
        
        choice = input("Choisissez une option : ")
        if choice == '0':
            list_passwords(conn, key)
        elif choice == '1':
            name = input("Entrez le nom du site : ")
            username = input("Entrez le nom d'utilisateur : ")
            password = input("Entrez le mot de passe : ")
            add_password(conn, name, username, password, key)
        elif choice == '2':
            name = input("Entrez le nom du site : ")
            username = input("Entrez le nom d'utilisateur : ")
            remove_password(conn, name, username)
        elif choice == '3':
            show_pin_interface(conn, key)
        elif choice == '9':
            print("Au revoir !")
            conn.close()
            sys.exit()
        else:
            print("Option invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()
