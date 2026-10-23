# config/fragments/overlays/hv-guest.frag — The guest kernel of `make azos-guest`
# The RAM the host gives the guest, and a kernel heap that fits in it. Until
# the build takes the RAM from the guest's device tree (F7), the overlay names it.
CONFIG_RAM_SIZE=24
CONFIG_KERNEL_HEAP_SIZE=8192
