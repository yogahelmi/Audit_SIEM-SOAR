# Endpoint 1: WEB server (Nginx + SSH) - sumber log auth/nginx/FIM
# Kelompok: 101032300037 Yoga Helmi Ilham Saputra / 101032300151 Muhammad Hafidz Abdurrahman
# Build context: ./endpoints
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
LABEL clo3.kelompok.nim="101032300037,101032300151" \
      clo3.kelompok.nama="Yoga Helmi Ilham Saputra, Muhammad Hafidz Abdurrahman" \
      clo3.endpoint="web"

RUN apt-get update && apt-get install -y nginx openssh-server rsyslog sudo curl gnupg lsb-release \
        jq iptables iproute2 conntrack procps \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list \
    # Manager = Wazuh 4.9.2; agent tidak boleh lebih baru dari manager.
    && apt-get update && WAZUH_MANAGER=placeholder apt-get install -y wazuh-agent=4.9.2-1 \
    && rm -rf /var/lib/apt/lists/*

# Akun lab (JANGAN dipakai di luar lab):
#   yoga, hafidz = admin (sudo)     intern = akun low-privilege, BUKAN sudoers
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf && mkdir -p /run/sshd /var/www/html/uploads \
    && useradd -m -s /bin/bash -G sudo yoga   && echo 'yoga:Password123'   | chpasswd \
    && useradd -m -s /bin/bash -G sudo hafidz && echo 'hafidz:Password123' | chpasswd \
    && useradd -m -s /bin/bash intern         && echo 'intern:Intern123'   | chpasswd \
    && printf 'Endpoint WEB - Kelompok CLO3\n101032300037 - Yoga Helmi Ilham Saputra\n101032300151 - Muhammad Hafidz Abdurrahman\n' > /etc/issue.net \
    && echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config \
    && printf '<h1>Endpoint WEB - Kelompok CLO3</h1>\n<p>101032300037 - Yoga Helmi Ilham Saputra<br>101032300151 - Muhammad Hafidz Abdurrahman</p>\n' > /var/www/html/index.html

COPY common/active-response/ /var/ossec/active-response/bin/
COPY common/agent-setup.sh /usr/local/bin/agent-setup.sh
COPY web/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /usr/local/bin/agent-setup.sh /var/ossec/active-response/bin/clo3-*.sh \
    && chmod 755 /entrypoint.sh /usr/local/bin/agent-setup.sh \
    && chown root:wazuh /var/ossec/active-response/bin/clo3-*.sh \
    && chmod 750 /var/ossec/active-response/bin/clo3-*.sh

EXPOSE 22 80
CMD ["/entrypoint.sh"]
