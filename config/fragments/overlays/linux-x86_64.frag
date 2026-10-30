# config/fragments/overlays/linux-x86_64.frag — the Linux personality on x86_64
# Hosted by the ring-3 runtime, which Kconfig turns on by default here; the gate
# keeps it off in the kernels that do not run a Linux task, and the rows that do
# add CONFIG_LINUX_RUNTIME=y to the defconfig.
# CONFIG_LINUX_RUNTIME is not set
