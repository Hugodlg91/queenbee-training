# ruff: noqa
# fmt: off
"""CODE DE DÉPART (issu de « Python Scripting Sécu ») — volontairement MAUVAIS.

Atelier J1-A2 : relever toutes les violations SOLID et de sécurité, puis refactorer.
Ne pas déployer. Ne pas copier ces pratiques.
"""
import re, sqlite3, smtplib

SMTP_PASSWORD = "Sup3rS3cret!"           # secret en dur, versionné dans Git
DB = sqlite3.connect("incidents.db")

class LogWatcher:                          # God class : lit, parse, détecte, stocke, alerte
    def __init__(self, path):
        self.path = path
        self.counts = {}

    def run(self):
        for line in open(self.path):        # fichier jamais fermé, aucune limite de taille
            m = re.search(r"Failed password for (.*) from (.*)", line)  # .* gourmand, non ancré
            if m:
                user, ip = m.group(1), m.group(2)
                self.counts[ip] = self.counts.get(ip, 0) + 1
                if self.counts[ip] == 5:
                    # Injection SQL : ip vient du log, donc de l'attaquant
                    DB.execute(f"INSERT INTO incidents VALUES ('{ip}', '{user}')")
                    self.alert(ip)

    def alert(self, ip):
        s = smtplib.SMTP("mail.local")
        s.login("queenbee", SMTP_PASSWORD)
        s.sendmail("qb@local", "soc@local", f"Brute force from {ip}")

    def report(self, kind):
        if kind == "csv":                    # OCP : chaque format = un elif de plus
            return "\n".join(f"{k},{v}" for k, v in self.counts.items())
        elif kind == "html":
            return "<br>".join(f"{k}:{v}" for k, v in self.counts.items())  # XSS possible
        elif kind == "json":
            return str(self.counts)
