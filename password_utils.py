from encryption import encrypt_password, decrypt_password
from database import backup_database


# Ajoute un mot de passe à la base de données et le chiffre en utilisant la clé fournie
def add_password(conn, site, username, password, key):
    cursor = conn.cursor()
    # Chiffrer le mot de passe
    enc_password, pass_iv, pass_tag = encrypt_password(password, key)
    # Chiffrer le nom d'utilisateur avec un nouvel IV
    enc_username, user_iv, user_tag = encrypt_password(username, key)
    
    cursor.execute("""
        INSERT INTO passwords (site, username, encrypted_password, iv_password, iv_username, tag_password, tag_username)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (site, enc_username, enc_password, pass_iv, user_iv, pass_tag, user_tag))
    conn.commit()
    print("Mot de passe ajouté avec succès.")
    backup_database()

# Supprime un mot de passe de la base de données
def remove_password(conn, site, username):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE site = ? AND username = ?", (site, username))
    conn.commit()
    if cursor.rowcount > 0:
        print("Mot de passe supprimé avec succès.")
        backup_database()
    else:
        print("Aucun mot de passe trouvé pour ce site et cet utilisateur.")

def list_passwords(conn, key):
    cursor = conn.cursor()
    cursor.execute("SELECT site, username, encrypted_password, iv_password, iv_username, tag_password, tag_username FROM passwords")
    results = cursor.fetchall()
    for site, username, enc_password, pass_iv, user_iv, pass_tag, user_tag in results:
        # Déchiffrer le mot de passe
        password = decrypt_password(enc_password, pass_iv, pass_tag, key)
        # Déchiffrer le nom d'utilisateur
        username = decrypt_password(username, user_iv, user_tag, key)
        print(f"Site : {site}, Nom d'utilisateur : {username}, Mot de passe : {password}")
