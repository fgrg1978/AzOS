# config/fragments/overlays/gui.frag — The input and audio servers, and what each ISA's gate machine can show it
# The input server (INPUTD) on every ISA; gui-riscv64.frag adds the compositor
# on QEMU's ramfb, gui-x86_64.frag the USB keyboard of the x86_64 machine.
CONFIG_INPUTD=y
# The audio server (config/subsys/Kconfig.audio AUDIOD): the gate's `beep` rows play
# through it, and its own row mixes two beeps. A robot image has no speaker to
# share, so the symbol is n by default there; the QEMU gate machines have
# virtio-sound.
CONFIG_AUDIOD=y
