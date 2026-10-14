import re
from collections import Counter

LOG_FILE = "access.log"

def analyze_logs():
    failed_attempts = Counter()
    # Motif élargi pour détecter les injections SQL courantes
    sqli_pattern = re.compile(r"(union|select|insert|delete|drop|or|'|1=1)", re.IGNORECASE)

    with open(LOG_FILE, "r") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            
            ip = line_str.split()[0]

            # Détection Brute-Force (code HTTP 401)
            if " 401 " in line_str:
                failed_attempts[ip] += 1

            # Détection SQL Injection
            if sqli_pattern.search(line_str):
                print(f"[ALERT SQLi] Injection détectée depuis {ip} -> {line_str}")

    for ip, count in failed_attempts.items():
        if count >= 3:
            print(f"[ALERT BRUTE-FORCE] L'IP {ip} cumule {count} échecs d'authentification.")

if __name__ == "__main__":
    analyze_logs()