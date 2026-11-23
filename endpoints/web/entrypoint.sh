#!/bin/bash
set -e
rm -f /run/rsyslogd.pid /run/nginx.pid
rsyslogd
/usr/sbin/sshd
/usr/local/bin/agent-setup.sh web
exec nginx -g 'daemon off;'
