# config/fragments/overlays/qemu.frag — QEMU development and test images
# Every line at the kernel console: the gate waits for info lines ("Starting
# scheduler on boot CPU"). A product build keeps its profile's level, warn.
CONFIG_LOG_LEVEL_DEBUG=y
