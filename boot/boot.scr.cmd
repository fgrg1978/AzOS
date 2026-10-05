# DEV01.B — U-Boot boot script with TFTP+SD fallback.
#
# Compile with:
#   mkimage -A riscv -T script -C none -n "azos boot" \
#           -d boot/boot.scr.cmd boot/boot.scr
#
# Install: copy boot.scr to the FAT partition root of the SD card.
# U-Boot will run it automatically (default bootcmd reads /boot.scr).
#
# Behavior:
#   1. Try DHCP. If no lease in 3s, jump to SD fallback.
#   2. tftpboot kernel.bin from server (advertised by DHCP option 66).
#      Timeout: 3s. If it fails, jump to SD fallback.
#   3. Otherwise: load /KERN_A.BIN from SD into kernel_addr_r.
#   4. booti to launch the kernel.
#
# All addresses come from the U-Boot environment (kernel_addr_r,
# fdt_addr_r) so this script works on VF2 (JH7110) and K1 (BPI-F3)
# without modification.

# ── Constants ──────────────────────────────────────────────────────────────
setenv tftp_timeout_ms 3000
setenv net_retry_max   2
setenv kernel_name     kernel.bin
setenv sd_kernel_path  /KERN_A.BIN
setenv sd_dev          mmc 0:1

# ── Try TFTP boot ──────────────────────────────────────────────────────────
echo "[boot.scr] DEV01 — attempting TFTP boot (timeout=${tftp_timeout_ms}ms)"

# DHCP lease + TFTP fetch in one shot. The "dhcp" command in newer U-Boot
# versions accepts an optional load address + filename. If the lease or
# transfer fails, the variable $? is non-zero and we fall through.
setenv tftp_ok 0
if dhcp ${kernel_addr_r} ${kernel_name}; then
    echo "[boot.scr] TFTP load OK (${filesize} bytes)"
    setenv tftp_ok 1
fi

# ── Fallback to SD if TFTP failed ─────────────────────────────────────────
if test "${tftp_ok}" = "0"; then
    echo "[boot.scr] TFTP failed, falling back to SD ${sd_kernel_path}"
    if load ${sd_dev} ${kernel_addr_r} ${sd_kernel_path}; then
        echo "[boot.scr] SD load OK"
    else
        echo "[boot.scr] FATAL: TFTP failed AND SD fallback failed."
        echo "[boot.scr] Drop to U-Boot shell."
        exit 1
    fi
fi

# ── Boot ───────────────────────────────────────────────────────────────────
echo "[boot.scr] booting kernel @ ${kernel_addr_r}"
booti ${kernel_addr_r} - ${fdt_addr_r}
