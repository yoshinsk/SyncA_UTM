# iso/kickstart/synca-utm.ks
# Kickstart for SyncA UTM. The installer UI is ASCII-only for console safety.

text
skipx
lang en_US.UTF-8
keyboard us
timezone Asia/Tokyo --utc
firstboot --disable
selinux --disabled
firewall --enabled --service=ssh
network --bootproto=dhcp --device=link --activate --onboot=on
rootpw --lock
reboot

zerombr
clearpart --all --initlabel
autopart --type=lvm

repo --name="BaseOS" --baseurl=file:///run/install/repo/BaseOS
repo --name="AppStream" --baseurl=file:///run/install/repo/AppStream

%packages --ignoremissing
@^minimal-environment
NetworkManager
NetworkManager-ppp
bind-utils
certbot
cronie
curl
dnsmasq
fail2ban
firewalld
git
glibc-langpack-ja
iproute
iptables-nft
langpacks-ja
nginx
nftables
openssh-server
openssl
policycoreutils
postfix
ppp
python3
python3-pip
rsync
strongswan
sudo
tar
tcpdump
vim-minimal
wireguard-tools
mod_security
mod_security_crs
nginx-mod-modsecurity
%end

%post --nochroot --log=/mnt/sysroot/root/synca-utm-nochroot-post.log
set -euxo pipefail
mkdir -p /mnt/sysroot/opt/synca-installer
cp -a /run/install/repo/synca/. /mnt/sysroot/opt/synca-installer/
%end

%post --log=/root/synca-utm-post.log
set -euxo pipefail
chmod +x /opt/synca-installer/*.sh
/opt/synca-installer/synca-install.sh --postinstall
systemctl enable synca-firstboot.service
%end
