#!/bin/bash

set -e

# Do preliminary pre-MTA stuff.
function preinstall() {
    echo -n "Do basic system updates? (y/n) "
    read answer
    if [ "$answer" != "y" ]; then
	return
    fi
    apt update
    apt upgrade
    apt autoremove
}

function firewall() {
    echo -n "Install firewall? (y/n) "
    read firewall
    if [ "$firewall" != "y" ]; then
	return
    fi
    apt install ufw
    ufw allow ssh
    ufw enable
    ufw allow smtp
    ufw allow imaps
    ufw allow http
    ufw allow https
    # SMTP submit port.
    ufw allow 587

    # Make syslog slightly less noisy.
    if [ -f /etc/rsyslog.d/20-ufw.conf ]; then
	sed -isave 's/^#& stop/\& stop/' /etc/rsyslog.d/20-ufw.conf
	service rsyslog restart
    fi
    apt install fail2ban
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

function certbot() {
    echo -n "Get certificates from Let's Encypt? (y/n) "
    read answer
    if [ "$answer" != "y" ]; then
	return
    fi
    apt install certbot
    certbot certonly --standalone -d $host
}

#preinstall
#firewall
sethost

echo "Configuring for $host..."

#certbot
