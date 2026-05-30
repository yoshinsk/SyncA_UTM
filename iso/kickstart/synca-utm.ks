# iso/kickstart/synca-utm.ks
# Kickstart for SyncA UTM. The installer UI is ASCII-only for console safety.

text
skipx
interactive
lang en_US.UTF-8
keyboard us
timezone Asia/Tokyo --utc
firstboot --disable
selinux --disabled
firewall --enabled --service=ssh
network --bootproto=dhcp --device=link --activate --onboot=on
rootpw --lock
reboot

# Storage is intentionally left to Anaconda's installation destination screen.
# Device names differ across physical servers, VPS/KVM, NVMe systems, and USB
# boot media. The operator must choose the target disk during installation.
bootloader --location=mbr

repo --name="BaseOS" --baseurl=file:///run/install/repo/BaseOS
repo --name="AppStream" --baseurl=file:///run/install/repo/AppStream
repo --name="SyncA-Extra" --baseurl=file:///run/install/repo/synca/rpms

%packages --ignoremissing
bash
ca-certificates
coreutils
dnf
efibootmgr
grub2-efi-x64
grub2-pc
grub2-tools
kernel
lvm2
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
passwd
python3
python3-pip
rootfiles
rsync
shadow-utils
strongswan
sudo
systemd
tar
tcpdump
util-linux
vim-minimal
wireguard-tools
xfsprogs
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
