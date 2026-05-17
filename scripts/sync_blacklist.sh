#!/bin/bash
# sync_blacklist.sh — Sincronizza blacklist.txt con la VM bersaglio in tempo reale
TARGET_IP="10.60.1.1"

# Usa sempre il path assoluto relativo allo script, indipendentemente da dove viene lanciato
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILE="$SCRIPT_DIR/../blacklist.txt"

# Assicurati che il file esista localmente
touch "$FILE"

echo "[*] Sincronizzazione attiva: $FILE -> root@$TARGET_IP:/root/blacklist.txt"
echo "[*] In attesa di modifiche... (CTRL+C per uscire)"

# Monitora i cambiamenti del file e copia via SCP
while inotifywait -q -e close_write "$FILE"; do
    echo "[+] Blacklist aggiornata! Sincronizzo con la VM..."
    if scp "$FILE" root@$TARGET_IP:/root/blacklist.txt 2>/dev/null; then
        echo "[OK] Sync completato -> $(wc -l < "$FILE") entries"
    else
        echo "[ERR] SCP fallito. VM raggiungibile? (ssh root@$TARGET_IP)"
    fi
done
