#!/bin/bash
# fleet-status-report.sh — READ-ONLY security/status audit for any Ubuntu LAMP fleet server.
# Run as root: bash fleet-status-report.sh
# Prints findings only; changes nothing; does not print any secret values.

section() { echo; echo "===== $1 ====="; }

section "HOST"
hostname; hostname -I 2>/dev/null
grep -oP '(?<=PRETTY_NAME=").*' /etc/os-release 2>/dev/null
echo "kernel: $(uname -r)   uptime: $(uptime -p 2>/dev/null)"
[ -f /var/run/reboot-required ] && echo "REBOOT-REQUIRED: yes $(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')" || echo "REBOOT-REQUIRED: no"

section "SSH EFFECTIVE (sshd -T)"
sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|x11forwarding|allowtcpforwarding|clientaliveinterval) ' || echo "sshd -T failed (run as root)"
echo "-- drop-in files (first-match-wins order) --"
ls -1 /etc/ssh/sshd_config.d/ 2>/dev/null

section "FIREWALL"
if command -v ufw >/dev/null; then
  ufw status verbose 2>&1 | head -40
  echo "-- numbered --"
  ufw status numbered 2>&1 | head -50
else
  echo "ufw not present — raw filter policy:"
  iptables -S INPUT 2>/dev/null | head -30
fi

section "LISTENING PORTS (flag anything not 22/80/443 on a public bind)"
ss -tlnp 2>/dev/null

section "APACHE"
apache2ctl -v 2>/dev/null | head -1
echo "-- effective banner settings (conf-enabled only) --"
grep -rhE '^\s*(ServerTokens|ServerSignature|TraceEnable)' /etc/apache2/conf-enabled/*.conf 2>/dev/null
echo "-- expose_php / cookie defaults (fpm+cli) --"
for ini in /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini; do [ -f "$ini" ] && echo "$ini: $(grep -E '^(expose_php|session.cookie_secure)' $ini | tr '\n' ' ')"; done
echo "-- sensitive-files block conf --"
ls /etc/apache2/conf-enabled/ | grep -iE 'block|sensitive' || echo "NOT INSTALLED"
echo "-- docroots --"
grep -Rh 'DocumentRoot' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | sort -u

section "WEBROOT SENSITIVE FILES (perms only, no contents)"
for d in $(grep -Rh 'DocumentRoot' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | sort -u); do
  [ -d "$d" ] || { echo "MISSING DOCROOT: $d"; continue; }
  find "$d" -xdev -maxdepth 3 -type f \( -name '.env' -o -name '.env.*' -o -name '*.bak' -o -name '*.old' -o -name '*.sql' -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.log' \) \
    -exec stat -c '%a %U:%G %n' {} + 2>/dev/null | grep -vE '\.env\.(example|sample)'
done

section "SYSCTL NETWORK"
sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
       net.ipv4.conf.all.log_martians net.ipv4.tcp_syncookies \
       net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route \
       net.ipv4.ip_forward net.ipv4.tcp_max_syn_backlog 2>/dev/null
echo "-- ufw sysctl clobber check (values here win at boot; log_martians=0 reverts hardening) --"
grep -E "log_martians" /etc/ufw/sysctl.conf 2>/dev/null || echo "no /etc/ufw/sysctl.conf martian lines"

section "RIVAL WEB SERVERS (must be absent/purged on Apache boxes)"
dpkg -l 2>/dev/null | grep -E "^ii\s+(nginx|lighttpd|caddy)" || echo "none installed"

section "MYSQL / REDIS (running-daemon truth, not config files)"
ss -ltn sport = :3306 | tail -n +2 || echo "no 3306 listener"
mysql -N -e "SHOW VARIABLES LIKE 'bind%';" 2>/dev/null || echo "(mysql query skipped)"
grep -E '^(bind|protected-mode)' /etc/redis/redis.conf 2>/dev/null || echo "no redis config"
ss -ltn sport = :6379 | tail -n +2 || echo "no 6379 listener"

section "SERVICE ENABLED vs ACTIVE (reboot landmines)"
for s in apache2 mysql redis-server fail2ban ssh ufw; do
  printf "%-14s enabled=%-12s active=%s\n" "$s" "$(systemctl is-enabled $s 2>&1)" "$(systemctl is-active $s 2>&1)"
done

section "FAIL2BAN"
systemctl is-active fail2ban 2>&1
fail2ban-client status sshd 2>/dev/null | grep -E 'Currently banned|Total banned|Total failures'
grep -h '^ignoreip' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.conf 2>/dev/null | sort -u
crontab -l 2>/dev/null | grep -c 3306 | xargs -I{} echo "mysql guard cron entries: {}"

section "UPDATES"
apt list --upgradable 2>/dev/null | grep -v '^Listing' > /tmp/.upg.$$ 
echo "pending updates: $(wc -l < /tmp/.upg.$$)"
cut -d/ -f1 /tmp/.upg.$$ | tr '\n' ' ' | head -c 1500; echo
rm -f /tmp/.upg.$$
ls /etc/apt/apt.conf.d/51blacklist-critical-stack >/dev/null 2>&1 && echo "unattended-upgrades stack blacklist: PRESENT" || echo "unattended-upgrades stack blacklist: ABSENT"

section "DOCKER"
if command -v docker >/dev/null 2>&1; then
  docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null
  iptables -t nat -S DOCKER 2>/dev/null | grep -i dnat | head -10
else echo "no docker"; fi

section "TLS CERT EXPIRY"
for c in $(grep -Rh 'SSLCertificateFile' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | sort -u); do
  [ -f "$c" ] && echo "$c : $(openssl x509 -in $c -noout -enddate 2>/dev/null) : $(openssl x509 -in $c -noout -subject 2>/dev/null | sed 's/subject=//')"
done

section "DISK / MEMORY / LOAD"
df -h / | tail -1
free -h | head -2
cat /proc/loadavg

echo
echo "===== END REPORT ====="
