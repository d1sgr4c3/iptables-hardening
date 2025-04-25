#!/bin/sh
# License: Apache License, Version 2.0
# Copyright: Frank Caviggia, 2018
# Author: Frank Caviggia <fcaviggi (at) gmail.com>
# please see https://github.com/fcaviggia/hardened-centos7-kickstart/blob/master/config/hardening/iptables.sh
# 
# Modified by valera disgrace for debian-based distros

# USAGE STATEMENT
function usage() {
cat << EOF
usage: $0 [options]

  -h,--help	show this message

  --http	allows HTTP (80/tcp)
  --https	allows HTTPS (443/tcp)
  --dns	 <IP>	allows DNS (53/udp)
  --sdns <IP>	allows DNSoverTLS (853/tcp)
  --ntp		allows NTP (123/tcp/udp)
  --dhcp	allows DHCP (67,68/tcp/udp)
  --tftp	allows TFTP (69/tcp/udp)
  --rsyslog	allows RSYSLOG (514/tcp/udp)
  --kerberos	allows Kerberos (88,464/tcp/udp)
  --ldap	allows LDAP (389/tcp/udp)
  --ldaps	allows LDAPS (636/tcp/udp)
  --nfsv4	allows NFSv4 (2049/tcp)
  --iscsi	allows iSCSI (3260/tcp)
  --samba       allows Samba Services (137,138/udp;139,445/tcp)
  --mysql	allows MySQL (3306/tcp)
  --postgresql	allows PostgreSQL (5432/tcp)
  --kvm		allows KVM Hypervisor (Ovirt-attached)
  --ovirt	allows Ovirt Manager Specific Ports
  --ipa		allows IPA/IdM Authentication Server
  --hkps        allows HKPS (HTTP Keyserver Protocol over TLS)

Configures iptables firewall rules for Debian-based distros.
 
EOF
}

# Get options
OPTS=`getopt -o h --long hkps,http,https,dns:,sdns:,ldap,ldaps,kvm,ovirt,nfsv4,iscsi,idm,ipa,krb5,kerberos,rsyslog,dhcp,bootp,tftp,ntp,smb,samba,cifs,mysql,mariadb,postgres,postgresql,help -- "$@"`
if [ "$#" -eq 0 ]; then
    usage
    exit 0
fi
eval set -- "$OPTS"

while true ; do
    case "$1" in
	--hkps) HKPS=1 ; shift ;;
	--http) HTTP=1 ; shift ;;
	--https) HTTPS=1 ; shift ;;
        --dns)
            if [ -z "$2" ] || [[ ! "$2" =~ ^([0-9]{1,3}[\.]){3}[0-9]{1,3} ]]; then echo -e "\033[1m[!] --sdns requires an IP address argument.\033[0m" && exit 1; else DNS_IP="$2"; shift 2; fi ;;
        --sdns)
            if [ -z "$2" ] || [[ ! "$2" =~ ^([0-9]{1,3}[\.]){3}[0-9]{1,3} ]]; then echo -e "\033[1m[!] --sdns requires an IP address argument.\033[0m" && exit 1; else SDNS_IP="$2"; shift 2; fi ;;
	--dhcp) DHCP=1 ; shift ;;
	--ldap) LDAP=1 ; shift ;;
	--ldaps) LDAPS=1 ; shift ;;
	--kerberos) KERBEROS=1 ; shift ;;
	--idm) KERBEROS=1 ; LDAP=1; LDAPS=1; DNS=1; NTP=1; HTTPS=1; shift ;;
	--ipa) KERBEROS=1 ; LDAP=1; LDAPS=1; DNS=1; NTP=1; HTTPS=1; shift ;;
	--krb5) KERBEROS=1 ; shift ;;
	--kvm) KVM=1 ; shift ;;
	--ovirt) HTTPS=1; OVIRT=1 ; shift ;;
	--iscsi) ISCSI=1 ; shift ;;
	--nfsv4) NFSV4=1 ; shift ;;
	--tftp) TFTP=1 ; shift ;;
	--dhcp) DHCP=1 ; shift ;;
	--bootp) DHCP=1 ; shift ;;
	--ntp) NTP=1 ; shift ;;
	--smb) SAMBA=1 ; shift ;;
	--samba) SAMBA=1 ; shift ;;
	--cifs) SAMBA=1 ; shift ;;
	--mysql) MARIADB=1 ; shift ;;
	--mariadb) MARIADB=1 ; shift ;;
	--postgres) POSTGRESQL=1 ; shift ;;
	--postgresql) POSTGRESQL=1 ; shift ;;
	--rsyslog) RSYSLOG=1 ; shift ;;
        --) shift ; break ;;
        *) usage ; exit 0 ;;
    esac
done


# Check if iptables package is installed
if [ ! -e $(which iptables) ]; then
	echo "ERROR: The iptables package is not installed."
	exit 1
fi


# Basic rule set - allows established/related pakets and SSH through firewall
cat <<EOF > ./rules.v4
#################################################################################################################
# HARDENING SCRIPT IPTABLES Configuration
#################################################################################################################
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
# Allow Traffic that is established or related
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow ICMP (Ping)
-A INPUT -p icmp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
# Allow Traffic on LOCALHOST/127.0.0.1
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
#### SSH/SCP/SFTP
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
EOF

if [ -n "$DNS_IP" ]; then
cat <<EOF >> ./rules.v4
#### DNS (53/tcp)
-A INPUT -m state --state NEW -m udp -p udp --dport 53 -d ${DNS_IP} -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 53 -d ${DNS_IP} -j ACCEPT
EOF
fi

if [ -n "$SDNS_IP" ]; then
cat <<EOF >> ./rules.v4
#### DNSoverTLS (853/tcp)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 853 -d ${SDNS_IP} -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 853 -d ${SDNS_IP} -j ACCEPT
EOF
fi

if [ ! -z $DHCP ]; then
cat <<EOF >> ./rules.v4
#### DHCP Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 67 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 67 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 68 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 68 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 67 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 67 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 68 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 68 -j ACCEPT
EOF
fi

if [ ! -z $TFTP ]; then
cat <<EOF >> ./rules.v4
#### TFTP Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 69 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 69 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 69 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 69 -j ACCEPT
EOF
fi

if [ ! -z $HTTP ]; then
cat <<EOF >> ./rules.v4
#### HTTPD - Recommend forwarding traffic to HTTPS 443
####   Recommended Article: http://www.cyberciti.biz/tips/howto-apache-force-https-secure-connections.html
-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
EOF
fi

if [ ! -z $HKPS ]; then
cat <<EOF >> ./rules.v4
#### HKPS -- HTTP Keyserver Protocol over TLS
-A INPUT -m state --state NEW -m tcp -p tcp --dport 11371 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 11371 -j ACCEPT
EOF
fi

if [ ! -z $KERBEROS ]; then
cat <<EOF >> ./rules.v4
#### Kerberos Authentication (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 88 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 88 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 88 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 88 -j ACCEPT
#### Kerberos Authentication - kpasswd (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 464 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 464 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 464 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 464 -j ACCEPT
EOF
fi

if [ ! -z $NTP ]; then
cat <<EOF >> ./rules.v4
#### NTP Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 123 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 123 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 123 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 123 -j ACCEPT
EOF
fi

if [ ! -z $LDAP ]; then
cat <<EOF >> ./rules.v4
#### LDAP (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 389 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 389 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 389 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 389 -j ACCEPT
EOF
fi

if [ ! -z $HTTPS ]; then
cat <<EOF >> ./rules.v4
#### HTTPS
-A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
EOF
fi

if [ ! -z $RSYSLOG ]; then
cat <<EOF >> ./rules.v4
#### RSYSLOG Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 514 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 514 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 514 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 514 -j ACCEPT
EOF
fi

if [ ! -z $LDAPS ]; then
cat <<EOF >> ./rules.v4
#### LDAPS - LDAP via SSL (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 636 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 636 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 636 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 636 -j ACCEPT
EOF
fi

if [ ! -z $NFSV4 ]; then
cat <<EOF >> ./rules.v4
#### NFSv4 Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 2049 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 2049 -j ACCEPT
EOF
fi

if [ ! -z $ISCSI ]; then
cat <<EOF >> ./rules.v4
#### iSCSI Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 3260 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 3260 -j ACCEPT
EOF
fi

if [ ! -z $POSTGRESQL ]; then
cat <<EOF >> ./rules.v4
#### PostgreSQL Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 5432 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 5432 -j ACCEPT
EOF
fi

if [ ! -z $MARIADB ]; then
cat <<EOF >> ./rules.v4
#### MariaDB/MySQL Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 3306 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 3306 -j ACCEPT
EOF
fi

if [ ! -z $SAMBA ]; then
cat <<EOF >> ./rules.v4
#### Samba/CIFS Server
-A INPUT -m udp -p udp --dport 137 -j ACCEPT
-A INPUT -m udp -p udp --dport 138 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 139 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 445 -j ACCEPT
-A OUTPUT -m udp -p udp --dport 137 -j ACCEPT
-A OUTPUT -m udp -p udp --dport 138 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 139 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 445 -j ACCEPT
EOF
fi

if [ ! -z $KVM ]; then
cat <<EOF >> ./rules.v4
#### SPICE/VNC Client (KVM)
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 5634:6166 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 5634:6166 -j ACCEPT
#### KVM Virtual Desktop and Server Manager (VDSM) Service
-A INPUT -m state --state NEW -m tcp -p tcp --dport 54321 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 54321 -j ACCEPT
#### KVM VM Migration
-A INPUT -m state --state NEW -m tcp -p tcp --dport 16514 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 49152:49216 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 16514 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 49152:49216 -j ACCEPT
EOF
fi

if [ ! -z $OVIRT ]; then
cat <<EOF >> ./rules.v4
#### Ovirt Manager (ActiveX Client)
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
#### Ovirt Manager (ActiveX Client)
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
EOF
fi

cat <<EOF >> ./rules.v4
#################################################################################################################
# Block timestamp-request and timestamp-reply

-A INPUT -p ICMP --icmp-type timestamp-request -j DROP
-A INPUT -p ICMP --icmp-type timestamp-reply -j DROP
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF

# IPv6 Basic rule set - allows established/related pakets and SSH through firewall
cat <<EOF > ./rules.v6
#################################################################################################################
# HARDENING SCRIPT IPTABLES Configuration
#################################################################################################################
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
# Allow Traffic that is established or related
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow ICMP (Ping)
-A INPUT -p ipv6-icmp -j ACCEPT
-A OUTPUT -p ipv6-icmp -j ACCEPT
# Allow Traffic on LOCALHOST/127.0.0.1
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
#### SSH/SCP/SFTP
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
EOF

if [ -n "$DNS_IP" ]; then
cat <<EOF >> ./rules.v6
#### DNS (53/tcp)
-A INPUT -m state --state NEW -m udp -p udp --dport 53 -d ${DNS_IP} -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 53 -d ${DNS_IP} -j ACCEPT
EOF
fi

if [ -n "$SDNS_IP" ]; then
cat <<EOF >> ./rules.v6
#### DNSoverTLS (853/tcp)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 853 -d ${SDNS_IP} -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 853 -d ${SDNS_IP} -j ACCEPT
EOF
fi

if [ ! -z $DHCP ]; then
cat <<EOF >> ./rules.v6
#### DHCP Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 67 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 67 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 68 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 68 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 67 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 67 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 68 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 68 -j ACCEPT
EOF
fi

if [ ! -z $TFTP ]; then
cat <<EOF >> ./rules.v6
#### TFTP Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 69 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 69 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 69 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 69 -j ACCEPT
EOF
fi

if [ ! -z $HTTP ]; then
cat <<EOF >> ./rules.v6
#### HTTPD - Recommend forwarding traffic to HTTPS 443
####   Recommended Article: http://www.cyberciti.biz/tips/howto-apache-force-https-secure-connections.html
-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
EOF
fi

if [ ! -z $HKPS ]; then
cat <<EOF >> ./rules.v6
#### HKPS -- HTTP Keyserver Protocol over TLS
-A INPUT -m state --state NEW -m tcp -p tcp --dport 11371 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 11371 -j ACCEPT
EOF
fi

if [ ! -z $KERBEROS ]; then
cat <<EOF >> ./rules.v6
#### Kerberos Authentication (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 88 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 88 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 88 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 88 -j ACCEPT
#### Kerberos Authentication - kpasswd (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 464 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 464 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 464 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 464 -j ACCEPT
EOF
fi

if [ ! -z $NTP ]; then
cat <<EOF >> ./rules.v6
#### NTP Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 123 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 123 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 123 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 123 -j ACCEPT
EOF
fi

if [ ! -z $LDAP ]; then
cat <<EOF >> ./rules.v6
#### LDAP (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 389 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 389 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 389 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 389 -j ACCEPT
EOF
fi

if [ ! -z $HTTPS ]; then
cat <<EOF >> ./rules.v6
#### HTTPS
-A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
EOF
fi

if [ ! -z $RSYSLOG ]; then
cat <<EOF >> ./rules.v6
#### RSYSLOG Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 514 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 514 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 514 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 514 -j ACCEPT
EOF
fi

if [ ! -z $LDAPS ]; then
cat <<EOF >> ./rules.v6
#### LDAPS - LDAP via SSL (IdM/IPA)
-A INPUT -m state --state NEW -m tcp -p tcp --dport 636 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 636 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 636 -j ACCEPT
-A OUTPUT -m state --state NEW -m udp -p udp --dport 636 -j ACCEPT
EOF
fi

if [ ! -z $NFSV4 ]; then
cat <<EOF >> ./rules.v6
#### NFSv4 Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 2049 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 2049 -j ACCEPT
EOF
fi

if [ ! -z $ISCSI ]; then
cat <<EOF >> ./rules.v6
#### iSCSI Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 3260 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 3260 -j ACCEPT
EOF
fi

if [ ! -z $POSTGRESQL ]; then
cat <<EOF >> ./rules.v6
#### PostgreSQL Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 5432 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 5432 -j ACCEPT
EOF
fi

if [ ! -z $MARIADB ]; then
cat <<EOF >> ./rules.v6
#### MariaDB/MySQL Server
-A INPUT -m state --state NEW -m tcp -p tcp --dport 3306 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 3306 -j ACCEPT
EOF
fi

if [ ! -z $SAMBA ]; then
cat <<EOF >> ./rules.v6
#### Samba/CIFS Server
-A INPUT -m udp -p udp --dport 137 -j ACCEPT
-A INPUT -m udp -p udp --dport 138 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 139 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 445 -j ACCEPT
-A OUTPUT -m udp -p udp --dport 137 -j ACCEPT
-A OUTPUT -m udp -p udp --dport 138 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 139 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 445 -j ACCEPT
EOF
fi

if [ ! -z $KVM ]; then
cat <<EOF >> ./rules.v6
#### SPICE/VNC Client (KVM)
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 5634:6166 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 5634:6166 -j ACCEPT
#### KVM Virtual Desktop and Server Manager (VDSM) Service
-A INPUT -m state --state NEW -m tcp -p tcp --dport 54321 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 54321 -j ACCEPT
#### KVM VM Migration
-A INPUT -m state --state NEW -m tcp -p tcp --dport 16514 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 49152:49216 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --dport 16514 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 49152:49216 -j ACCEPT
EOF
fi

if [ ! -z $OVIRT ]; then
cat <<EOF >> ./rules.v6
#### Ovirt Manager (ActiveX Client)
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
#### Ovirt Manager (ActiveX Client)
-A INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 8006:8009 -j ACCEPT
EOF
fi

cat <<EOF >> ./rules.v6
#################################################################################################################
# Limit Echo Requests - Prevents DoS attacks
-A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 900/min -j ACCEPT
-A OUTPUT -p icmpv6 --icmpv6-type echo-reply -m limit --limit 900/min -j ACCEPT
-A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
-A OUTPUT -p icmpv6 --icmpv6-type echo-reply -j DROP
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
EOF

exit 0
