from scapy.all import *
import time

target_ip = "127.0.0.1"
fake_nat_ip = "1.2.3.4"

# Definiamo 3 attaccanti con Delta (identità) molto diversi
identities = [
    {"name": "TEAM_A", "delta": 100000},
    {"name": "TEAM_B", "delta": 500000},
    {"name": "TEAM_C", "delta": 1200000}
]

print(f"[*] Stress test avviato verso {target_ip}...")
print("[*] IP simulato per tutti: {fake_nat_ip}")
print("[*] Premi Ctrl+C per fermare il test.")

try:
    count = 0
    while True:
        for iden in identities:
            now_ms = int(time.time() * 1000)
            # Calcoliamo il TSval per mantenere il Delta costante
            ts_val = (now_ms - iden["delta"]) % (2**32)
            opts = [('Timestamp', (ts_val, 1337))]
            
            pkt = IP(src=fake_nat_ip, dst=target_ip)/TCP(dport=80, flags="S", options=opts)
            send(pkt, verbose=False)
        
        count += 1
        if count % 10 == 0:
            print(f"[+] Inviate {count} raffiche...")
            
        time.sleep(0.2) # Aspetta un attimo tra una raffica e l'altra
except KeyboardInterrupt:
    print("\n[*] Test interrotto dall'utente.")
