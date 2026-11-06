# config/fragments/overlays/hv-host.frag — The hypervisor host role
# A guest's RAM is MemObj frames, and the guests may take half of MAX_MEMOBJS
# (config/axes/Kconfig.virt): its maximum, 256, is 32 MiB of guest RAM at a
# 4 KiB granule (219 KiB of static table).
CONFIG_MAX_MEMOBJS=256
