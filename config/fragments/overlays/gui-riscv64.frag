# config/fragments/overlays/gui-riscv64.frag — The compositor on QEMU ramfb (riscv64)
# The compositor and the framebuffer it composes onto (QEMU ramfb, which the
# kernel drives only when it is built with the `ramfb` feature and QEMU has the
# device: the generic rows boot the same userspace with no framebuffer, where the
# compositor runs headless). On here so the gate tests the trusted path: after
# Ctrl+Alt+Delete the input server refuses every caller but the compositor the
# focus. 6000 ms of banner (the default is 1500) so the gate's typed refusal
# lands inside the interval, and the `input` row's status before the compositor
# hands the focus on, on a loaded host.
CONFIG_DRV_DISPLAY_RAMFB=y
CONFIG_COMPOSITOR=y
CONFIG_COMPOSITOR_BANNER_MS=6000
