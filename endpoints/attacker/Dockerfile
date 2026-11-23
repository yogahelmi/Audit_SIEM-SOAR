# Attacker lab (Kali) - tool simulasi serangan sudah terpasang agar pengujian cepat.
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
LABEL clo3.kelompok.nim="101032300037,101032300151" clo3.endpoint="attacker"
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap hydra sshpass openssh-client curl iproute2 netcat-openbsd ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY attack.sh /usr/local/bin/attack.sh
RUN sed -i 's/\r$//' /usr/local/bin/attack.sh && chmod 755 /usr/local/bin/attack.sh
CMD ["sleep", "infinity"]
