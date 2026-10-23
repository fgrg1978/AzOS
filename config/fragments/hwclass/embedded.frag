# config/fragments/hwclass/embedded.frag — HWCLASS EMBEDDED: small boards, 16-64 MiB of RAM
# The smallest limit tables (config/limits/Kconfig.limits).
CONFIG_HWCLASS_EMBEDDED=y
# The RAM the board is expected to have (the build checks the kernel heap
# against it); the PMM manages whatever RAM the device tree reports, so one
# image serves a 16 and a 64 MiB board. Until the build takes it from the
# device tree (kconfig sub-front F7), the class names it.
CONFIG_RAM_SIZE=64
