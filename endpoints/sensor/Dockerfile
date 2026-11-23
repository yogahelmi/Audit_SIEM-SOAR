# Endpoint 2: SENSOR / gateway - Nginx reverse proxy di depan WEB + Suricata IDS
# Semua trafik HTTP ke aplikasi melewati container ini, sehingga Suricata melihatnya.
# Kelompok: 101032300037 Yoga Helmi Ilham Saputra / 101032300151 Muhammad Hafidz Abdurrahman
# Build context: ./endpoints
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
LABEL clo3.kelompok.nim="101032300037,101032300151" \
      clo3.kelompok.nama="Yoga Helmi Ilham Saputra, Muhammad Hafidz Abdurrahman" \
      clo3.endpoint="sensor"

RUN apt-get update && apt-get install -y suricata nginx curl gnupg lsb-release jq \
        iptables iproute2 conntrack procps tcpdump \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && WAZUH_MANAGER=placeholder apt-get install -y wazuh-agent=4.9.2-1 \
    && rm -rf /var/lib/apt/lists/*

COPY sensor/local.rules /etc/suricata/rules/local.rules
COPY sensor/nginx-proxy.conf /etc/nginx/sites-available/default
COPY common/active-response/ /var/ossec/active-response/bin/
COPY common/agent-setup.sh /usr/local/bin/agent-setup.sh
COPY sensor/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /usr/local/bin/agent-setup.sh /var/ossec/active-response/bin/clo3-*.sh /etc/suricata/rules/local.rules \
    && chmod 755 /entrypoint.sh /usr/local/bin/agent-setup.sh \
    && chown root:wazuh /var/ossec/active-response/bin/clo3-*.sh \
    && chmod 750 /var/ossec/active-response/bin/clo3-*.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
