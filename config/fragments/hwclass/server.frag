# config/fragments/hwclass/server.frag — HWCLASS SERVER: servers and gateway machines
# The Fleet limit tables (config/limits/Kconfig.limits).
CONFIG_HWCLASS_SERVER=y
# The RAM the class is built for (the build checks the 256 MiB kernel heap
# against it). Until the build takes it from the device tree (F7), the class
# names it.
CONFIG_RAM_SIZE=1024
