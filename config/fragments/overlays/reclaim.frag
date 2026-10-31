# config/fragments/overlays/reclaim.frag — Reclaim under real pressure (the gate's `reclaim:` rows)
# Compression and swap to a file, on a small machine, with MEMPRESS.ELF started
# to fill past its RAM and the decision ring on the console. The machine is small
# so the fill is short, and every table bound is opened so that the pool's room
# (Full) and not a table or a quota is what sends segments to swap. The other
# rows' budgets take most of what memory admission gives on a machine this
# size, so the watermarks are set where a program holding its whole budget takes
# the machine past the system's, and one its storms keep at its own does not. The
# swap file grows once: a grow zero-fills through the filesystem with the reclaim
# task waiting, and on a loaded host a step every few seconds starves the fill.
CONFIG_LOG_LEVEL_DEBUG=y
CONFIG_RAM_SIZE=128
CONFIG_KERNEL_HEAP_SIZE=8192
CONFIG_MM_RECLAIM_COMPRESS=y
CONFIG_MM_SWAP_BACKEND_FILE=y
CONFIG_MM_SWAP_SEGMENTS=256
CONFIG_MM_SWAP_FILE_GROW_SEGMENTS=128
CONFIG_MM_ZPOOL_ENTRIES=65536
CONFIG_MM_ZPOOL_DOMAIN_KIB=0
CONFIG_MM_AGING_INTERVAL_MS=100
CONFIG_MM_RECLAIM_POLL_MS=50
CONFIG_MM_RECLAIM_HIGH_PCT=40
CONFIG_MM_RECLAIM_LOW_PCT=30
CONFIG_MM_PRESSURE_TEST_PAGES=10000
CONFIG_USERSPACE_MEMPRESS=y
CONFIG_DECISION_RECORDS_CONSOLE=y
