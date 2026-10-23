# config/fragments/overlays/linux.frag — The Linux personality and the C library, on so the gate tests them
# Linux personality: off by default everywhere; on here so the gate tests it.
CONFIG_LINUX_ABI=y
# The C library and its test programs: `make relibc` builds them for this ISA.
CONFIG_RELIBC=y
