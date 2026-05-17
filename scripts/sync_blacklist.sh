#!/bin/bash
# sync_blacklist.sh
TARGET_IP="10.60.1.1"
FILE="blacklist.txt"

# Assicurati che il file esista localmente
touch $FILE

echo "Sincronizzazione attiva su $FILE -> root@$TARGET_IP"

# Monitora i cambiamenti del file e copia via SCP
while inotifywait -e close_write $FILE; do
    echo "[+] Blacklist aggiornata! Sincronizzo con la VM..."
    scp $FILE root@$TARGET_IP:/root/blacklist.txt
done
