#!/bin/bash

set -e

if [ -d /etc/exim4 ]; then
    echo "You already seem to have an exim installation.  Running this script"
    echo -n "may be dangerous.  Continue anyway?  (y/n) "
    read answer
    if [ "$answer" != "y" ]; then
	exit
    fi
fi

# Do preliminary pre-MTA stuff.
function preinstall() {
    echo -n "Do basic system updates? (y/n) "
    read answer
    if [ "$answer" != "y" ]; then
	return
    fi
    apt update
    apt -y upgrade
    apt -y autoremove
}

function firewall() {
    echo -n "Install firewall? (y/n) "
    read firewall
    if [ "$firewall" != "y" ]; then
	return
    fi
    apt -y install ufw
    ufw allow ssh
    ufw enable
    ufw allow smtp
    ufw allow imaps
    ufw allow http
    ufw allow https
    # SMTP submit ports (with SSL and STARTTLS).
    ufw allow smtps
    ufw allow 587

    # Make syslog slightly less noisy.
    if [ -f /etc/rsyslog.d/20-ufw.conf ]; then
	sed -isave 's/^#& stop/\& stop/' /etc/rsyslog.d/20-ufw.conf
	service rsyslog restart
    fi
    # Make brute forcing less likely.
    apt -y install fail2ban
    cat <<EOF > /etc/fail2ban/jail.d/exim.conf
[exim]
enabled=true
EOF
    cat <<EOF > /etc/fail2ban/jail.d/dovecot.conf
[dovecot]
enabled=true
EOF
    systemctl restart fail2ban.service
}

function sethost() {
    ip=$(hostname -I | awk '{ print $1; }')
    host=$(getent hosts $ip | awk '{ print $2; }')
    echo -n "What is the host name? (default $host) "
    read prompthost
    if [ "$prompthost" != "" ]; then
	host="$prompthost"
    fi
}

function check-web() {
    lsof -i :80 -sTCP:LISTEN
}

function get-certbot() {
    echo -n "Get certificates from Let's Encypt? (y/n) "
    read answer
    if [ "$answer" != "y" ]; then
	return
    fi
    apt -y install certbot lsof

    # If we have a web server, then don't use standalone certbot,
    # because it'll fail.
    if check-web > /dev/null; then
	if check-web | grep apache > /dev/null; then
	    apt -y install python-certbot-apache
	elif check-web | grep nginx > /dev/null; then
	    apt -y install python-certbot-nginx
	fi
	# Try to use the web server to get certificates.
	certbot certonly -d $host
    else
	# This will start a standalone http server and get the certificate.
	certbot certonly --standalone -d $host
    fi
    # Renew certificates.
    echo "10 3 * * 1 certbot renew" >> /var/spool/cron/crontabs/root
}

function exim() {
    apt -y install exim4-daemon-heavy clamav spamassassin clamav-daemon\
	sasl2-bin
    # Allow authentication of submitted mail via the SASL daemon.
    adduser Debian-exim sasl
    sed -i 's/^START=.*/START=yes/' /etc/default/saslauthd
    systemctl restart saslauthd.service

    # Use the Let's Encrypt certificates in exim.
    cat <<EOF > /etc/exim4/conf.d/main/00_tls_macros
MAIN_TLS_ENABLE=yes
MAIN_TLS_PRIVATEKEY=/etc/letsencrypt/live/$host/privkey.pem
MAIN_TLS_CERTIFICATE=/etc/letsencrypt/live/$host/fullchain.pem
EOF

    # Make exim use the split config and be an internet MTA.
    sed -i "s/dc_use_split_config='false'/dc_use_split_config='true'/" \
	/etc/exim4/update-exim4.conf.conf
    sed -i "s/dc_other_hostnames=.*/dc_other_hostnames='$host:$domain'/" \
	/etc/exim4/update-exim4.conf.conf
    sed -i "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
	/etc/exim4/update-exim4.conf.conf
    sed -i "s/dc_local_interfaces='127.0.0.1 ; ::1'/dc_local_interfaces=''/" \
	/etc/exim4/update-exim4.conf.conf

    # Add the SMTP submit ports (TLS and STARTTLS).
    cat <<EOF > /etc/exim4/conf.d/main/00_ports
daemon_smtp_ports = smtp : smtps : 587
tls_on_connect_ports = 465
EOF

    # Allow authentication via SASL.
    cat <<"EOF" > /etc/exim4/conf.d/auth/10_plain_server
plain_server:
  driver = plaintext
  public_name = PLAIN
  server_condition = ${if saslauthd{{$auth2}{$auth3}}{1}{0}}
  server_set_id = $auth2
  server_prompts = :
  server_advertise_condition = ${if eq{$received_port}{587}{${if eq{$tls_in_cipher}{}{no}{yes}}}{${if eq{$received_port}{465}{yes}{no}}}}
EOF

    # Make exim do virus and spam scanning.
    sed -i 's/# av_scanner/av_scanner/' \
	/etc/exim4/conf.d/main/02_exim4-config_options
    sed -i 's/# spamd_address/spamd_address/' \
	/etc/exim4/conf.d/main/02_exim4-config_options

    cat <<"EOF" > /etc/exim4/conf.d/acl/45_stop_spam
deny  message = This message scored too many spam points
  spam = Debian-exim:true
  condition = ${if >{$spam_score_int}{49}{yes}{no}}

deny
  malware = *
  message = This message was detected as possible malware ($malware_name).
EOF

    # The previous elements have to be in the check_data ACL, but that
    # file ends with "accept", which lets everything through.  So
    # remove that from that file...
    sed -i 's/^ *accept/  #accept/' \
	/etc/exim4/conf.d/acl/40_exim4-config_check_data

    # ... and put it in a separate file.
    cat <<"EOF" > /etc/exim4/conf.d/acl/55_exim4_check_data_end
  # accept otherwise
  accept
EOF
    
    systemctl enable spamassassin.service
    service spamassassin restart

    # ClamAV needs to be able to access /var/spool/exim4/scan.
    adduser clamav Debian-exim
    systemctl enable clamav-daemon.service
    
    update-exim4.conf
    service exim4 restart

    # Allow exim to read the Let's Encrypt certificates.
    adduser Debian-exim mail
    chgrp -R mail /etc/letsencrypt
    chmod -R g+rx /etc/letsencrypt
}

function dkim() {
    cd /etc/exim4
    
    # Generate private and public keys.
    openssl genrsa -out "$domain-dkim-private.pem" 2048
    openssl rsa -in "$domain-dkim-private.pem" -out \
	    "$domain-dkim-public.pem" -pubout

    # Allow exim to read the file.
    chmod g+r "$domain-dkim-private.pem"
    chgrp Debian-exim "$domain-dkim-private.pem"

    selector=$(date +%Y%m%d)

    cat <<EOF > conf.d/main/00_dkim_macros
DKIM_CANON = relaxed
DKIM_SELECTOR = $selector
DKIM_DOMAIN = $domain
DKIM_PRIVATE_KEY = /etc/exim4/$domain-dkim-private.pem
EOF
    update-exim4.conf
    service exim4 reload

    echo "Make the following TXT DNS record for $selector._domainkey.$domain"
    echo
    echo -n "  k=rsa; p="
    grep -v '^-' < "$domain-dkim-public.pem" | tr -d '\n'
    echo
}

function dns() {
    echo
    echo "Make the following TXT DNS record for $domain"
    echo
    echo "  v=spf1 a mx ~all"
    echo
    echo "Make the following TXT DNS record for _dmarc.$domain"
    echo
    echo "  v=DMARC1; p=none"
    echo
    echo "Make the following MX DNS record for $domain"
    echo
    echo "  $host"
}

function dovecot() {
    echo -n "Install Dovecot IMAP? (y/n) "
    read answer
    if [ "$answer" != "y" ]; then
	return
    fi
    apt -y install dovecot-imapd

    # Use the Let's Encrypt certificates.
    sed -i "s#/etc/dovecot/private/dovecot.pem#/etc/letsencrypt/live/$host/fullchain.pem#" /etc/dovecot/conf.d/10-ssl.conf
    sed -i "s#/etc/dovecot/private/dovecot.key#/etc/letsencrypt/live/$host/privkey.pem#" /etc/dovecot/conf.d/10-ssl.conf
    service dovecot restart
    # The certificate will change, and dovecot has to reload so that
    # it doesn't expire.
    echo "20 3 * * 1 systemctl reload dovecot.service" >> \
	 /var/spool/cron/crontabs/root
}

preinstall
firewall
sethost

echo "Configuring for $host..."

domain=$(echo $host | sed 's/^[^.]*[.]//')

get-certbot
exim
dovecot

dkim
dns
