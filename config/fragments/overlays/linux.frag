# config/fragments/overlays/linux.frag — The Linux personality and the C library, on so the gate tests them
# Linux personality: off by default everywhere; on here so the gate tests it.
CONFIG_LINUX_ABI=y
# The C library and its test programs: `make relibc` builds them for this ISA.
CONFIG_RELIBC=y
# The gate's kernels carry no BusyBox: its BusyBox rows build their own
# configuration with both on, and the rows that read "BusyBox off" depend on
# these lines. A development build outside the gate takes the Kconfig default
# (on with the Linux personality).
# CONFIG_USERSPACE_GPL is not set
# CONFIG_BUSYBOX is not set
