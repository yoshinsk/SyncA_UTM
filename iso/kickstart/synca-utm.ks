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
kbd
kbd-misc
lvm2
NetworkManager
NetworkManager-ppp
bind-utils
certbot
chrony
cronie
curl
dnsmasq
dialog
fail2ban
firewalld
frr
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
radvd
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

%post --nochroot --log=/mnt/sysroot/root/synca-utm-bootloader-post.log
set -euxo pipefail

mountpoint -q /mnt/sysroot/dev || mount --bind /dev /mnt/sysroot/dev
mountpoint -q /mnt/sysroot/proc || mount --bind /proc /mnt/sysroot/proc
mountpoint -q /mnt/sysroot/sys || mount --bind /sys /mnt/sysroot/sys
mountpoint -q /mnt/sysroot/run || mount --bind /run /mnt/sysroot/run

boot_source="$(findmnt -n -o SOURCE /mnt/sysroot/boot 2>/dev/null || true)"
if [[ -z "$boot_source" ]]; then
    boot_source="$(findmnt -n -o SOURCE /mnt/sysroot 2>/dev/null || true)"
fi
boot_device="$(readlink -f "$boot_source" 2>/dev/null || printf '%s' "$boot_source")"
target_disk="$(lsblk -npo PKNAME "$boot_device" 2>/dev/null | head -n1 || true)"

if [[ -z "$target_disk" && "$boot_device" =~ ^/dev/(sd[a-z]|vd[a-z])[0-9]+$ ]]; then
    target_disk="/dev/${BASH_REMATCH[1]}"
fi
if [[ -z "$target_disk" && "$boot_device" =~ ^/dev/(nvme[0-9]+n[0-9]+)p[0-9]+$ ]]; then
    target_disk="/dev/${BASH_REMATCH[1]}"
fi

if [[ -n "$target_disk" && -b "$target_disk" && ! -d /sys/firmware/efi ]]; then
    chroot /mnt/sysroot grub2-install "$target_disk"
fi

chroot /mnt/sysroot grub2-mkconfig -o /boot/grub2/grub.cfg

if [[ -d /sys/firmware/efi && -d /mnt/sysroot/boot/efi/EFI ]]; then
    install -d -m 0755 /mnt/sysroot/boot/efi/EFI/BOOT
    if [[ -f /mnt/sysroot/boot/efi/EFI/almalinux/shimx64.efi ]]; then
        cp -f /mnt/sysroot/boot/efi/EFI/almalinux/shimx64.efi \
            /mnt/sysroot/boot/efi/EFI/BOOT/BOOTX64.EFI
    elif [[ -f /mnt/sysroot/boot/efi/EFI/almalinux/grubx64.efi ]]; then
        cp -f /mnt/sysroot/boot/efi/EFI/almalinux/grubx64.efi \
            /mnt/sysroot/boot/efi/EFI/BOOT/BOOTX64.EFI
    fi
    cp -f /mnt/sysroot/boot/efi/EFI/almalinux/grubx64.efi \
        /mnt/sysroot/boot/efi/EFI/BOOT/grubx64.efi 2>/dev/null || true
    cp -f /mnt/sysroot/boot/efi/EFI/almalinux/mmx64.efi \
        /mnt/sysroot/boot/efi/EFI/BOOT/mmx64.efi 2>/dev/null || true
    cp -f /mnt/sysroot/boot/efi/EFI/almalinux/grub.cfg \
        /mnt/sysroot/boot/efi/EFI/BOOT/grub.cfg 2>/dev/null || true
fi
%end
