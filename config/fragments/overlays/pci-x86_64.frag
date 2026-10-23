# config/fragments/overlays/pci-x86_64.frag — The x86_64 PCI configuration space of the gate machine
# q35's MMCONFIG window. Until the kernel takes it from ACPI MCFG (F7), the
# overlay names it.
CONFIG_X86_PCI_ECAM_BASE=0xE0000000
