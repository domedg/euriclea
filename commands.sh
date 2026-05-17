# ==========================================
#  EURICLEA - ACTIVE DEFENSE COMMAND GUIDE
# ==========================================

# ------------------------------------------
# 1. GESTIONE E COMPILAZIONE (Makefile)
# ------------------------------------------

# Compila tutti i binari (TUI e NFQueue) all'interno della cartella bin/
make all

# Compila solo la TUI
make tui

# Compila solo NFQueue
make nfqueue

# Pulisce l'ambiente da eseguibili e file di log (debug.log, blacklist.txt, bin/)
make clean


# ------------------------------------------
# 2. AVVIO DELLA TUI (Radar/Monitor)
# ------------------------------------------

# Avvio rapido per test locali (interfaccia loopback) tramite Makefile
make run-tui

# Avvio in ambiente di GARA (ascolto da remoto via SSH su interfaccia "game")
# Sostituisci 10.60.1.1 con l'IP della tua VM vulnerabile.
# La flag -host serve a ignorare i pacchetti in uscita dalla VM.
ssh root@10.60.1.1 "tcpdump -i game -n --immediate-mode -s 65535 -U -w - 'port 3000 or port 80'" | tee >(nc localhost 9999) | ./bin/euriclea-tui -host 10.60.1.1 -

# Avvio locale personalizzato catturando da pcap (es. per analisi post-gara)
./bin/euriclea-tui -host <TARGET_IP> traffico_gara.pcap
# Test locale
sudo tcpdump -i lo -n -U -w - | ./bin/euriclea-tui -host 127.0.0.1 -

# ------------------------------------------
# 3. DIFESA ATTIVA (NFQueue e Iptables)
# ------------------------------------------

# Sulla VM Bersaglio: Imposta iptables per catturare il traffico TCP e mandarlo alla coda 420
iptables -A INPUT -p tcp -j NFQUEUE --queue-num 420

# Sulla VM Bersaglio: Avvia il demone NFQueue per scartare i pacchetti blacklistati
./bin/nfqueue

# Sulla VM Bersaglio: Per rimuovere la regola iptables a fine gara
iptables -D INPUT -p tcp -j NFQUEUE --queue-num 420


# ------------------------------------------
# 4. SINCRONIZZAZIONE BLACKLIST
# ------------------------------------------

# Dal tuo Host: Avvia lo script che osserva blacklist.txt in tempo reale
# e lo spedisce tramite scp alla VM bersaglio
make sync
# (In alternativa: ./scripts/sync_blacklist.sh)


# ------------------------------------------
# 5. SCRIPT DI TESTING E SIMULAZIONE
# ------------------------------------------

# Avvia l'ambiente virtuale python (se non già fatto)
source scripts/venv/bin/activate

# Testa Euriclea simulando un NAT (Stesso IP, Timestamp Riscritti)
# NOTA: Funziona solo se la rete non sovrascrive i TCP Timestamps.
sudo python3 scripts/test_nat.py

# Stress Test su Loopback (Simula 3 attaccanti con Haiku diversi sullo stesso IP)
# Usa questo insieme a `make run-tui` in un altro terminale.
sudo python3 scripts/test_stress.py

# Test Identità (Invia 2 fingerprint diversi dal tuo IP Reale)
sudo python3 scripts/test_identita.py
