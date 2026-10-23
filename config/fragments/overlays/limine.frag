# config/fragments/overlays/limine.frag — x86_64 booted by Limine, with a framebuffer console and a PS/2 keyboard
CONFIG_X86_BOOT_LIMINE=y
CONFIG_FB_GENERIC=y
CONFIG_FB_CONSOLE=y
CONFIG_FB_PANIC_SCREEN=y
CONFIG_DRV_PS2=y
