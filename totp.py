import pyotp
from database import backup_database

# =========================================================================================================
# Fonctions pour gérer les TOTP (Time-based One-Time Password)
# Ces fonctions ne sont pas encore implémentées dans le programme principal.
# =========================================================================================================

def add_totp(conn, site, secret):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO totp (site, secret) VALUES (?, ?)", (site, secret))
    conn.commit()
    print("TOTP ajouté avec succès.")
    backup_database()

def get_totp(conn, site):
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM totp WHERE site = ?", (site,))
    result = cursor.fetchone()
    if result:
        totp = pyotp.TOTP(result[0])
        return totp.now()
    else:
        return "Aucun TOTP trouvé pour ce site."
