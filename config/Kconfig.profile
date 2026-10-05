# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# config/Kconfig.profile — Deployment profile
#
# RFC-0026 Phase C1.  Selects the cap-size tier.  Individual caps in
# config/Kconfig.limits can be overridden after choosing a profile.

menu "Deployment Profile"

choice
    prompt "Deployment profile"
    default PROFILE_EDGE
    help
      Selects the default static resource cap sizes.  See RFC-0023 for the
      full table.  Individual caps in "Resource Limits" can be overridden
      after choosing a profile, but choose the closest base first to
      minimise manual editing.

    config PROFILE_EMBEDDED
        bool "Embedded — small rv64 boards (16-64 MiB RAM)"
        help
          For rv64 SoCs with 16-64 MiB of RAM running one device's
          workload.  Smallest static tables (config/Kconfig.limits).
          Built from config/defconfigs/embedded.config with
          kernel/linker-embedded.ld, which links the image into the
          14 MiB above OpenSBI and holds it to a named budget.  The
          measured image is 5.8 MiB, of which the secure-boot image
          buffer is 2 MiB and the four TCP connections 1.0 MiB;
          tools/size_report.sh prints the per-subsystem figures.

    config PROFILE_EDGE
        bool "Edge — single-board computer (VF2 / K1 / RK3588)"
        help
          Default profile.  Sized for ~200 userspace apps, 100 sensor
          streams, one upstream link (the brain link on a robot) and OTA.
          Memory budget ~40 MiB: the static image and the 32 MiB kernel
          heap.  Targets single-board computers with
          1-8 GiB RAM.

    config PROFILE_FLEET
        bool "Fleet — gateway / edge server (many devices aggregated)"
        help
          For a AZOS instance acting as a gateway that aggregates many
          downstream devices.  Large cap tables, high TCP connection
          count, multi-stream OTA.  Memory budget ~390 MiB: a 135 MiB
          static image and the 256 MiB kernel heap.
          Incompatible with NO_MMU and PROFILE_EMBEDDED.

endchoice

endmenu # Deployment Profile
