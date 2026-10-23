# config/fragments/overlays/k1.frag — SpacemiT K1 / BananaPi BPI-F3: what its device tree does not give yet
# The board (BOARD_K1: its driver set, RV64GCV, the SoC frameworks on by
# default) until drivers bind from the device tree (kconfig sub-front F8).
CONFIG_BOARD_K1=y
# The K1 I2C controller moves one byte per service step (config/subsys/Kconfig.drivers
# I2C_SERVICE_POLL_US): the minimum keeps a 17-byte IMU burst well inside
# I2C_XFER_TIMEOUT_US. Board validation pending.
CONFIG_I2C_SERVICE_POLL_US=50
# Energy model: the K1's clusters take their OPPs and voltages from the device
# tree and the thermal task moves the P1 PMIC's buck with the clock
# (kernel/src/boot/thermal.rs; THERMAL follows ENERGY on a robot image).
# Without it the K1 image links the frameworks and never moves a clock or a rail.
CONFIG_ENERGY=y
