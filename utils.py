import random
import string
import re

def generate_password(length=12, avoid_ambiguous=False):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    punctuation = string.punctuation

    if avoid_ambiguous:
        lowercase = re.sub(r'[il]', '', lowercase)
        uppercase = re.sub(r'[IO]', '', uppercase)
        digits = re.sub(r'[01]', '', digits)
        punctuation = re.sub(r'[{}[\]()\/\'"`~,;:.<>]', '', punctuation)

    characters = lowercase + uppercase + digits + punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    
    # Assurez-vous que le mot de passe contient au moins un caractère de chaque catégorie
    while not (any(c.islower() for c in password) and
               any(c.isupper() for c in password) and
               any(c.isdigit() for c in password) and
               any(c in string.punctuation for c in password)):
        password = ''.join(random.choice(characters) for _ in range(length))
    
    return password
def analyze_password_strength(password, existing_passwords=None, common_passwords=None):
    score = 0

    if len(password) >= 20:
        score += 4
    elif len(password) >= 14:
        score += 3
    elif len(password) >= 10:
        score += 2
    elif len(password) >= 8:
        score += 1
    elif len(password) < 8:
        score -= 1
    elif len(password) < 6:
        score -= 2

    if any(c.islower() for c in password):
        score += 1
    elif any(c.isupper() for c in password):
        score += 1
    elif any(c.isdigit() for c in password):
        score += 1
    
    special_chars = set(string.punctuation)
    password_special_chars = set(c for c in password if c in special_chars)
    if len(password_special_chars) >= 3:
        score += 3
    elif len(password_special_chars) >= 2:
        score += 2
    elif len(password_special_chars) >= 1:
        score += 1

    file_path = 'passwords-bl.txt'
    with open(file_path, 'r', encoding='utf-8') as file:
        blacklisted_passwords = set(line.strip().lower() for line in file)

    #existing_passwords = TODO: load from database ⚠️

    if blacklisted_passwords and password.lower() in blacklisted_passwords:
        score -= 5

    if existing_passwords and password in existing_passwords:
        score -= 5

    # Évaluation finale
    if score >= 10:
        strength = "Très fort"
    elif score >= 8:
        strength = "Fort"
    elif score >= 6:
        strength = "Moyen"
    elif score >= 4:
        strength = "Faible"
    else:
        strength = "Très faible"

    return strength