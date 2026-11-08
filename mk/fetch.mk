# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The one place that downloads (network here only; `make build` stays offline):
# tools/build/fetch.py holds the inventory of everything the build takes from outside the checkout.
#   make fetch                  every pinned tree, toolchain, host tool and package the build needs; skips what is present
#   make fetch CONFIG=1         only the third-party trees the .config consumes
#   make fetch BRAIN=1          also the AzOSRobotBrain venv (BRAIN_OPTIONAL=1 adds its optional packages)
#   make fetch-check            offline-first report of each pin, its upstream, CVEs and the inventory; changes nothing
#   make fetch-update NAME=<tree> [VERSION=<tag>]   move one pin and fetch it; leaves the change uncommitted
FETCH_PY = $(PYTHON) tools/build/fetch.py

.PHONY: fetch fetch-check fetch-update
fetch:
	@BRAIN_OPTIONAL='$(BRAIN_OPTIONAL)' $(FETCH_PY) fetch $(if $(CONFIG),--config-only --config '$(KCONFIG_CONFIG)') $(if $(BRAIN),--brain)

fetch-check:
	@$(FETCH_PY) check $(if $(OFFLINE),--offline)

fetch-update:
	@test -n '$(NAME)' || { echo 'make fetch-update NAME=<busybox|limine|linux|relibc|u-boot> [VERSION=<tag>]'; exit 2; }
	@$(FETCH_PY) update '$(NAME)' $(VERSION)
