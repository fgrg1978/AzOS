<!--
SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
SPDX-FileCopyrightText: 2026 Fernando Rodriguez
-->
# Board farm (one board: StarFive VisionFive 2)

A host, a board, a relay in the board's supply and a serial line on its
console. `make vf2-ktest` builds the development test kernel, serves it,
power-cycles the board and reads the ktest TAP off the console under a
deadline; the exit code is the verdict. No board attached: every farm command
exits 3 and the gate row SKIPs.

## Wiring (once)

- **Console:** the UART on the 40-pin header (pins 6 GND, 8 TX, 10 RX) to a
  USB-serial adapter, 115200 8N1. The adapter is `serial` in `boards.ini`.
- **Power:** a USB relay (or smart plug) in the board's 5 V supply. Two
  commands switch it (`relay_on`, `relay_off`); `relay = dry-run` rehearses a
  run without one.
- **SD card:** U-Boot reads `boot.scr` from the FAT root and the script
  (`boot/boot.scr.cmd`) runs `dhcp ${kernel_addr_r} kernel.bin`:
  `mkimage -A riscv -T script -C none -n "azos boot" -d boot/boot.scr.cmd boot.scr`.
- **Network:** a cable between the host and the board, the host's interface on
  `server_ip`. No other DHCP server on that segment.

## Setup

```
cp tools/farm/boards.ini.example tools/farm/boards.ini     # fill in this host's wiring
python3 tools/farm/farm.py net-config --out build/farm/dnsmasq.conf
sudo dnsmasq --keep-in-foreground --conf-file=build/farm/dnsmasq.conf
python3 tools/farm/farm.py check                            # exit 0: a board is configured
python3 tools/farm/farm.py power cycle                      # the relay works
```

The generated dnsmasq serves this board and nobody else (one interface, one
static lease, `dhcp-ignore` for unknown clients, DNS off) and TFTP from
`tftp_root`. `AZOS_FARM_CONFIG` names another config file.

## Runs

| Command | Builds | Judges |
| --- | --- | --- |
| `make vf2-ktest` | `vf2 BUILD_TYPE=DEV` + `CONFIG_KTEST` + the built-in topology (the test kernel does not need the signed volume) | the TAP: plan = the image's registry, every test `ok` once, summary, no `Bail out!`, one plan only (a second one is a restart) |
| `make vf2-pstore` | `vf2 BUILD_TYPE=DEV` + a pstore region + `pstore-smoke` | the pstore boot counter: two boots in one capture, one panic, the record written on boot 1 and recovered on boot 2 |

Both print the board facts they find (`[ISA]`, `[MM] ASID: hw N bits`, the
ktest phases) and keep the serial log in `build/farm/`.

Exit codes: 0 pass, 1 red verdict (a test failed, a run stalled, a restart), 2
the farm (a bad entry, a relay or TFTP that does not answer, a board that never
printed a plan), 3 no board configured.

`make vf2-pstore` needs `/fat`: on a board whose storage driver does not exist
yet it fails with "no /fat" and that is the finding.
