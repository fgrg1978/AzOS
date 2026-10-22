# U-Boot script of the board farm (tools/farm): boot the kernel the farm
# host staged on its TFTP server.
#
# DEVELOPMENT BOARDS ONLY (BUILD_TYPE_DEV, SECURE_BOOT_ENFORCED=n): it boots
# whatever the TFTP server hands it, unsigned and unverified. A board that
# boots a signed chain does not carry this script; its SD card boots slots
# A/B/R with tools/boot.cmd.
#
# Compile with:
#   mkimage -A riscv -T script -C none -n "azos farm" \
#           -d tools/farm/boot.cmd $AZOS_OUT/build/boot.scr
#
# Install: copy boot.scr to the FAT partition root of the SD card.
# U-Boot runs it automatically (its default bootcmd reads /boot.scr).
#
# Behavior:
#   1. `dhcp` takes a lease and fetches ${kernel_name} from the server the
#      lease names (tools/farm/farm_net.py writes the dnsmasq configuration).
#      U-Boot's own BOOTP timeout applies; `tftptimeout` is the wait for
#      each TFTP packet and `netretry` how often a failed transfer restarts.
#   2. On success `booti` starts it: the flat kernel opens with the Linux
#      RISC-V Image header (kernel/src/entry/riscv64/asm/boot.S).
#   3. On failure it stops at the U-Boot prompt. There is no SD fallback: a
#      farm run judges the kernel it staged, and an older kernel booted from
#      the SD card would print a verdict about a kernel nobody asked for.
#
# All addresses come from the U-Boot environment (kernel_addr_r,
# fdt_addr_r), so the script works on VF2 (JH7110) and K1 (BPI-F3)
# without modification.

setenv tftptimeout 3000
setenv netretry    2
setenv kernel_name kernel.bin

echo "[farm boot] dhcp + tftp ${kernel_name}"
if dhcp ${kernel_addr_r} ${kernel_name}; then
    echo "[farm boot] fetched ${filesize} bytes; booting @ ${kernel_addr_r}"
    booti ${kernel_addr_r} - ${fdt_addr_r}
    echo "[farm boot] FAILED: booti refused the image"
else
    echo "[farm boot] FAILED: no lease or no ${kernel_name} on the server"
fi
exit 1
