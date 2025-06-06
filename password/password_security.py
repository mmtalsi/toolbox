import getpass
import hashlib
import re
import requests
import time
from zxcvbn import zxcvbn

class PasswordSecurity:
    API_URL = "https://api.pwnedpasswords.com/range/"

    def analyze_password_security(self):
        password = getpass.getpass("Veuillez entrer votre mot de passe : ")
        if not password:
            print("Erreur : Vous devez entrer un mot de passe.")
            return
        if not self.is_password_strong(password):
            print("Erreur : Votre mot de passe ne respecte pas les politiques de mot de passe.")
            print("Politique : 8+ caractères, majuscule, minuscule, chiffre, caractère spécial.")
            return
        analysis = zxcvbn(password)
        print(f"Score : {analysis['score']} (plus élevé = plus sûr)")
        print(f"Temps de crack estimé : {analysis['crack_times_seconds']['online_no_throttling_10_per_second']}s")
        if analysis['score'] < 3:
            print("Mot de passe faible. Considérez les suggestions.")
        else:
            print("Mot de passe fort.")
        pwned_count = self.pwned_api_check(password)
        if pwned_count:
            print(f"⚠ Mot de passe exposé {pwned_count} fois dans des fuites connues.")

    def pwned_api_check(self, password):
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1password[:5], sha1password[5:]
        try:
            response = requests.get(self.API_URL + first5_char)
            hashes = (line.split(':') for line in response.text.splitlines())
            return next((int(count) for t, count in hashes if t == tail), 0)
        except requests.exceptions.RequestException as e:
            print(f"Erreur API : {e}")
            return None

    def is_password_strong(self, password):
        return (len(password) >= 8 and
                re.search(r'[A-Z]', password) and
                re.search(r'[a-z]', password) and
                re.search(r'\d', password) and
                re.search(r'\W', password))

if __name__ == "__main__":
    ps = PasswordSecurity()
    ps.analyze_password_security()

