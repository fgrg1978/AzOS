# config/fragments/overlays/rpi5.frag — Raspberry Pi 5 (BCM2712): what its device tree does not give yet
# The board (BOARD_RPI5: its driver set, Armv8.2, the 54 MHz generic timer)
# until drivers bind from the device tree (kconfig sub-front F8).
CONFIG_BOARD_RPI5=y
# SoC resource frameworks (clock, reset, regulator, power domain from the
# device tree) and the PCI host driver (most peripherals sit behind the RP1
# southbridge on PCIe).
CONFIG_SOC_FRAMEWORKS=y
CONFIG_DRV_PCI=y
