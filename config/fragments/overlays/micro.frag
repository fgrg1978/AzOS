# config/fragments/overlays/micro.frag — AzOS-micro, the MCU kernel (`make micro`)
# `make micro` expands this into $AZOS_OUT/build/micro.config. The ISA choices are the
# main kernel's (riscv64 is not built); what the micro kernel reads is MICRO_*,
# the topology limits (embedded class) and BUILD_TYPE_DEV, which lets the
# topology verify against the test key.
CONFIG_MICRO=y
