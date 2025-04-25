# iptables-hardening
the iptables-hardening script sets up iptables(v4 and v6) rules to strengthen Linux firewall security and block unwanted network traffic.

```
$ iptables.sh --help
usage: iptables.sh [options]

  -h,--help	show this message

  --http	allows HTTP (80/tcp)
  --https	allows HTTPS (443/tcp)
  --dns		allows DNS (53/tcp/udp)
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
```

# getting started

obtain a utility to make the parameters persistent.

```
sudo apt-get install iptables-persistent
```

verify hardening:

```bash
sudo bash iptables.sh --http --https --dhcp --ntp --dns 1.1.1.1
vi rules.v4 # verify config manually
vi rules.v6 # verify config manually
```

apply changes:

```bash
cp rules.v4 /etc/iptables/rules.v4
cp rules.v6 /etc/iptables/rules.v6
sudo systemctl restart systemd-resolved NetworkManager iptables.service
```
