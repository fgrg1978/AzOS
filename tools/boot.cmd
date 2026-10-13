# AzOS — U-Boot boot script for A/B OTA slot selection + R recovery.
#
# Compile to boot.scr with:
#   mkimage -C none -A riscv -T script -d tools/boot.cmd build/boot.scr
#
# Copy boot.scr + KERN_A.BIN + BOOTMETA to the FAT32 boot partition.
# OT04 — KERN_R.BIN is the immutable recovery slot. It is never written
# by OTA; the only way to update it is to physically reflash the FAT32
# boot partition. If both A and B fail to load, U-Boot falls back to R.
# U-Boot will execute boot.scr automatically if configured.

echo "[ROTA] Reading boot metadata..."
if fatload mmc 0:1 ${loadaddr} BOOTMETA 2>/dev/null; then
    env import -t ${loadaddr} ${filesize}
else
    echo "[ROTA] No BOOTMETA found — defaulting to slot A"
    setenv active_slot a
fi

# Try the active slot first.
if test "${active_slot}" = "b"; then
    echo "[ROTA] Booting slot B (KERN_B.BIN)"
    if fatload mmc 0:1 ${kernel_addr_r} KERN_B.BIN; then
        booti ${kernel_addr_r} - ${fdt_addr}
    fi
    echo "[ROTA] Slot B failed to load — trying slot A"
    if fatload mmc 0:1 ${kernel_addr_r} KERN_A.BIN; then
        booti ${kernel_addr_r} - ${fdt_addr}
    fi
elif test "${active_slot}" = "r"; then
    # OT04 — kernel-side steered NEXT boot to the recovery slot (CRC
    # verified R after both A and B failed on a previous boot). Try it
    # directly instead of falling through the A/B branch below, which
    # would silently default to A for any unrecognized active_slot value.
    echo "[ROTA] Booting recovery slot (KERN_R.BIN)"
    if fatload mmc 0:1 ${kernel_addr_r} KERN_R.BIN; then
        booti ${kernel_addr_r} - ${fdt_addr}
    fi
    echo "[ROTA] Recovery slot failed to load — trying slot A"
    if fatload mmc 0:1 ${kernel_addr_r} KERN_A.BIN; then
        booti ${kernel_addr_r} - ${fdt_addr}
    fi
else
    echo "[ROTA] Booting slot A (KERN_A.BIN)"
    if fatload mmc 0:1 ${kernel_addr_r} KERN_A.BIN; then
        booti ${kernel_addr_r} - ${fdt_addr}
    fi
    echo "[ROTA] Slot A failed to load — trying slot B"
    if fatload mmc 0:1 ${kernel_addr_r} KERN_B.BIN; then
        booti ${kernel_addr_r} - ${fdt_addr}
    fi
fi

# OT04 — last resort: immutable recovery slot.
echo "[ROTA] Both A and B failed — booting recovery slot (KERN_R.BIN)"
if fatload mmc 0:1 ${kernel_addr_r} KERN_R.BIN; then
    booti ${kernel_addr_r} - ${fdt_addr}
fi

echo "[ROTA] FATAL: no bootable kernel found. Reflash the SD card."
