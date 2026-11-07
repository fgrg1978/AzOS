# config/fragments/overlays/linux-dev.frag — The Linux personality as a development image has it
# The personality and the C library, as linux.frag, without that overlay's gate
# pins: BusyBox, its GPL switch and (x86_64) the ring-3 runtime take their
# Kconfig defaults, which are on in a development build with the personality.
# The native console stays (the gate's sh rows need it) and the personality is beside it.
CONFIG_USERLAND_BOTH=y
CONFIG_LINUX_ABI=y
CONFIG_RELIBC=y
