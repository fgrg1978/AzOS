<!--
SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
SPDX-FileCopyrightText: 2026 Fernando Rodriguez
-->
# Board farm

Tooling that runs a development kernel on one attached board: a host, the
board, a relay in the board's supply and a serial line on its console.
`make vf2-ktest` builds the development test kernel, serves it over TFTP,
power-cycles the board and reads the ktest TAP off the console under a
deadline; the exit code is the verdict. With no board configured on the host,
every farm command exits 3 and the gate row is skipped.

Source: `tools/farm/farm.py` and the `farm_*.py` modules beside it,
`mk/kernel.mk` (the `vf2-ktest` and `vf2-pstore` targets),
`tools/farm/boot.cmd`.

## Wiring

- **Console:** the board's console UART to a USB-serial adapter, 115200 8N1.
  The adapter is `serial` in `boards.ini`.
- **Power:** a USB relay (or smart plug) in the board's supply. Two commands
  switch it (`relay_on`, `relay_off`); `relay = dry-run` rehearses a run
  without one.
- **Boot medium:** U-Boot reads `boot.scr` from the FAT root of the SD card.
  The script (`tools/farm/boot.cmd`, development boards only: it boots an
  unsigned kernel) runs `dhcp ${kernel_addr_r} kernel.bin`, then `booti`;
  build it with
  `mkimage -A riscv -T script -C none -n "azos farm" -d tools/farm/boot.cmd $AZOS_OUT/build/boot.scr`.
- **Network:** a cable between the host and the board, the host's interface on
  `server_ip`. No other DHCP server on that segment.

## Setup

```
cp tools/farm/boards.ini.example tools/farm/boards.ini     # fill in this host's wiring
python3 tools/farm/farm.py net-config --out $AZOS_OUT/build/farm/dnsmasq.conf
sudo dnsmasq --keep-in-foreground --conf-file=$AZOS_OUT/build/farm/dnsmasq.conf
python3 tools/farm/farm.py check                            # exit 0: a board is configured
python3 tools/farm/farm.py power cycle                      # the relay works
```

The generated dnsmasq configuration serves one board and nobody else (one
interface, one static lease, `dhcp-ignore` for unknown clients, DNS off) and
TFTP from `tftp_root`. `AZOS_FARM_CONFIG` names another config file.

## Runs

| Command | Builds | Judges |
| --- | --- | --- |
| `make vf2-ktest` | `vf2 BUILD_TYPE=DEV` (a development build: the test signing key is accepted) with `CONFIG_KTEST` | the TAP: the plan is the image's test registry, every test reports `ok` once, a summary line, no `Bail out!`, one plan only (a second plan is a restart) |
| `make vf2-pstore` | `vf2 BUILD_TYPE=DEV` with a pstore region and the `pstore-smoke` feature | the pstore boot counter: two boots in one capture, one panic, the record written on boot 1 and recovered on boot 2 |

Both print the board facts the kernel reports (`[ISA]`, `[MM] ASID`, the ktest
phases) and keep the serial log in `$AZOS_OUT/build/farm/`. `make vf2-pstore`
needs the FAT volume mounted, because the record is appended to
`/fat/CRASH.LOG`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | pass |
| 1 | red verdict: a test failed, a run stalled, or the board restarted |
| 2 | the farm itself: a bad entry, a relay or TFTP server that does not answer, a board that never printed a plan |
| 3 | no board configured on this host |
