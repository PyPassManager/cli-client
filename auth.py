from pin import has_pin, auth_with_pin
from master_password import check_master_password
from encryption import derive_key
import sys

def authenticate_user(conn):
    """
    Authentifie l'utilisateur en demandant soit le PIN, soit le mot de passe maître.
    Si le délai de sécurité du PIN a expiré, le mot de passe maître sera demandé.
    Retourne (clé dérivée, master_password, salt).
    """
    try:
        if has_pin(conn):
            # if is_pin_expired(conn):
            #     print("Le délai de sécurité pour le PIN a expiré.")
            #     master_password, salt = check_master_password(conn)
            #     update_pin_usage(conn)
            #     return derive_key(master_password, salt), master_password, salt
            # else:
                if auth_with_pin(conn):
                    print("PIN correct.")
                else:
                    print("PIN incorrect.")
                    sys.exit()
                # else:
                #     # Mettre last_usage à 0 pour bloquer l'accès avec pin pour la prochaine tentative
                #     # TODO : Ajouter "locked = 1" pour bloquer l'accès avec le pin dans la database pour avoir un meilleur message d'erreur
                #     cursor.execute("UPDATE pin SET last_usage = 0")
                #     conn.commit()
                #     pinchoice = input("Echec de l'authentification. Voulez-vous utiliser le mot de passe maître ? (o/n) : ")
                #     if pinchoice.lower() == 'o':
                #         master_password, salt = check_master_password(conn)
                #         return derive_key(master_password, salt), master_password, salt
                #     else:
                #         sys.exit()
        else:
            print("Aucun PIN défini. Utilisation du mot de passe maître.")
            master_password, salt = check_master_password(conn)
            return derive_key(master_password, salt), master_password, salt
    except Exception as e:
        print(f"Erreur pendant l'authentification : {str(e)}")
        sys.exit()