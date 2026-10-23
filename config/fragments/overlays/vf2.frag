# config/fragments/overlays/vf2.frag — StarFive VisionFive 2 (JH7110): what its device tree does not give yet
# The board (BOARD_VF2: its driver set, RV64GC, the SoC frameworks on by
# default) until drivers bind from the device tree (kconfig sub-front F8).
CONFIG_BOARD_VF2=y
# The PCI host driver.
CONFIG_DRV_PCI=y
