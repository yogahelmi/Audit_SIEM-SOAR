FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nginx openssh-server rsyslog iptables sudo curl gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

RUN mkdir -p /run/sshd && useradd -m -s /bin/bash yoga \
    && echo 'yoga:Password123' | chpasswd

RUN echo "Endpoint WEB - 101032300037 - Yoga Helmi Ilham Saputra" > /etc/issue.net \
    && echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config \
    && echo "<h1>Endpoint WEB - 101032300037 - Yoga Helmi Ilham Saputra</h1>" \
       > /var/www/html/index.html

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]