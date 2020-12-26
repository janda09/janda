#!/bin/bash
#
# Original script by fornesia, rzengineer and fawzya 
# Mod by Janda Baper
# 
# ==================================================

# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# company name details
country=ID
state=JATIM
locality=KEDIRI
organization=NOTT
organizationalunit=NETT
commonname=IPANG
email=jandabaper09@gmail.com

# setting hostname
hostnamectl set-hostname ipang

# configure rc.local
cat <<EOF >/etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

exit 0
EOF
chmod +x /etc/rc.local
systemctl daemon-reload
systemctl start rc-local

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local


# install wget and curl
apt-get -y install wget curl

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# setting repo ke unej
cp /etc/apt/sources.list /etc/apt/soutces.list-original
sudo echo > /etc/apt/sources.list
cat <<REPO' > /etc/apt/sources.list
# Mod By Janda Baper Group
deb http://mirror.unej.ac.id/debian/ stretch main contrib non-free
deb http://mirror.unej.ac.id/debian/ stretch-updates main contrib non-free
deb http://mirror.unej.ac.id/debian-security/ stretch/updates main contrib non-free
REPO

# update
apt-get update

# install essential package
sudo apt-get -y install nano iptables-persistent dnsutils screen whois ngrep unzip ssh cmake make gcc libc6-dev zlib1g-dev net-tools

# install neofetch
echo "deb http://dl.bintray.com/dawidd6/neofetch jessie main" | tee -a /etc/apt/sources.list
curl "https://bintray.com/user/downloadSubjectPublicKey?username=bintray"| apt-key add -
apt-get update
apt-get install neofetch

# Creating a SSH server config using cat eof tricks
cat <<'MySSHConfig' > /etc/ssh/sshd_config
# Setup By Janda Baper Group
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/janda09/install/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/janda09/install/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config

# install sslh multiport
apt-get -y install sslh
cat > /etc/default/sslh <<-END
#Mod By Janda Baper Group
RUN=yes

DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen $MYIP:443 --ssl 127.0.0.1:443 --ssh 127.0.0.1:22 -P --pidfile /var/run/sslh/sslh.pid"

END

/etc/init.d/sslh restart

# install dropbear
cd
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 80 -p 109 -p 110"/g' /etc/default/dropbear

# update dropbear 2019
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
bzip2 -cd dropbear-2019.78.tar.bz2 | tar xvf -
cd dropbear-2019.78
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart
cd

# install squid
apt-get -y install squid
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/janda09/janda/main/repo/squid3.conf"
sed -i $MYIP2 /etc/squid/squid.conf;

# install stunnel
apt-get install stunnel4 -y

# configur certifikate stunnel
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.crt -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cp /root/key.pem /etc/stunnel/key.pem
cp /root/cert.crt /etc/stunnel/cert.crt

# Configure config stunnel
cat > /etc/stunnel/stunnel.conf <<-END
# Setup By Janda Baper Group
pid = /var/run/stunnel.pid
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
debug = 2

[ssl_frontend]
key = /etc/stunnel/key.pem
cert = /etc/stunnel/cert.crt
accept  = 127.0.0.1:443
connect = $MYIP:22
ciphers = ALL
client = no
;sessiond = 127.0.0.1:443
;session = 60
TIMEOUTconnect = 5
TIMEOUTbusy = 25
TIMEOUTidle = 25
TIMEOUTclose = 0
END

# configure stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
cd

# colored text
apt-get -y install ruby
gem install lolcat

# install fail2ban
apt-get -y install fail2ban

# install ddos deflate
cd
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/janda09/install/master/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/ddos-deflate-master.zip

# banner /etc/bnr
wget -O /etc/bnr "https://raw.githubusercontent.com/janda09/install/master/bnr"
wget -O /etc/banner "https://raw.githubusercontent.com/janda09/install/master/banner"
sed -i 's@#Banner@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/bnr"@g' /etc/default/dropbear

# Installing Premium Script
cd
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.d/rc.local
echo "0 0 * * * root /usr/local/bin/user-expire" > /etc/cron.d/user-expire

cat > /root/ban.sh <<END3
#!/bin/bash
#/usr/local/bin/user-ban
END3

cat > /root/limit.sh <<END3
#!/bin/bash
#/usr/local/bin/user-limit
END3

cd /usr/local/bin
wget -O premi.zip "https://raw.githubusercontent.com/janda09/janda/main/repo/premi.zip"
unzip premi.zip
rm -f premi.zip

cp /usr/local/bin/premium-script /usr/local/bin/menu
chmod +x /usr/local/bin/*
cd

# blockir torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

#set auto kill multi login
cd /usr/bin
wget -O janda "https://raw.githubusercontent.com/janda09/janda/main/repo/set_multilogin_autokill_lib"
chmod +x janda
echo "* * * * * root /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 5; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 10; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 15; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 20; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 25; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 30; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 35; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 40; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 45; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 50; /usr/bin/janda" >> /etc/crontab
echo "* * * * * root sleep 55; /usr/bin/janda" >> /etc/crontab

# finishing
cd
service cron restart
service sshd restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/stunnel4 stop
/etc/init.d/stunnel4 start
/etc/init.d/sslh restart
/etc/init.d/squid start
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# grep ports 
ps -ef | grep sslh
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"

# Creating Profile Info
echo 'clear' > /etc/profile.d/janda.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/janda.sh
echo 'neofetch ' >> /etc/profile.d/janda.sh
echo 'echo -e "" ' >> /etc/profile.d/janda.sh
echo 'echo -e "################################################" ' >> /etc/profile.d/janda.sh
echo 'echo -e "#               Janda Baper Group              #" ' >> /etc/profile.d/janda.sh
echo 'echo -e "#                Ipang Nett Nott               #" ' >> /etc/profile.d/janda.sh
echo 'echo -e "# Ketik menu untuk menampilkan daftar perintah #" ' >> /etc/profile.d/janda.sh
echo 'echo -e "################################################" ' >> /etc/profile.d/janda.sh
echo 'echo -e "" ' >> /etc/profile.d/janda.sh
chmod +x /etc/profile.d/janda.sh

# remove unnecessary files
apt -y autoremove
apt -y autoclean
apt -y clean

# info
clear
bash /etc/profile.d/janda.sh
echo "Autoscript Include:" | tee log-install.txt
echo "===========================================" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Service"  | tee -a log-install.txt
echo "-------"  | tee -a log-install.txt
echo "OpenSSH  : 22"  | tee -a log-install.txt
echo "Dropbear : 80, 109, 143, 110, 443"  | tee -a log-install.txt
echo "SSL      : 443"  | tee -a log-install.txt
echo "Squid    : 3128, 8080 (limit to IP SSH)"  | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7500"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Script"  | tee -a log-install.txt
echo "------"  | tee -a log-install.txt
echo "menu (Displays a list of available commands)"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Other features"  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo "Timezone : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "IPv6     : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Setup By Janda Baper Group"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt
cd
rm -f /root/janda.sh
