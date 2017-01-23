#Realtek rtl8811AU_8812AU_8821AU_linux

Realtek rtl8811AO_8812AU_8821AU linux kernel driver for 801.11ac Wireless Dual-Band module

## Compiling with DKMS

```sh
# sudo cp -R . /usr/src/rtl8812AU_8821AU_linux-1.0
# sudo dkms add -m rtl8812AU_8821AU_linux -v 1.0
# sudo dkms build -m rtl8812AU_8821AU_linux -v 1.0
# sudo dkms install -m rtl8812AU_8821AU_linux -v 1.0
```

### Compiling for Raspberry Pi

Install kernel headers and other dependencies.

```sh
# sudo apt-get install linux-image-rpi-rpfv linux-headers-rpi-rpfv dkms build-essential bc
```

Append following at the end of your ``/boot/config.txt``, reboot your Pi

```sh
kernel=vmlinuz-3.10-3-rpi
initramfs initrd.img-3.10-3-rpi followkernel
```

Edit Makefile and turn on ``CONFIG_PLATFORM_ARM_RPI``, turn off ``CONFIG_PLATFORM_I386_PC``

```sh
CONFIG_PLATFORM_I386_PC = n
CONFIG_PLATFORM_ARM_RPI = y
```

```sh
# cd /usr/src/rtl8812AU_8821AU_linux
# sudo make clean
# sudo make
# sudo make install
# sudo modprobe -a 8812au
```
