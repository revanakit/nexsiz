# Nexsiz — Operational Makefile
#
# High-quality task runner for red-team / APT campaign workflows.
# Pure Make + shell; no external task runners required.
#
# Design goals:
#   - One command for every common operational action
#   - Deterministic, verbose-by-default where useful
#   - Zero behaviour change to the binary itself
#   - Safe defaults; override via environment or make VAR=value
#
# Author  : Revana / Nexsiz maintainers
# License : Apache-2.0 (same as the project)

.PHONY: help release release-full debug nxs nxs-clean clean clean-all \
        clean-shm clean-output infer infer-ftp infer-http \
        campaign-ftp campaign-smtp campaign-http campaign-dns campaign-mqtt campaign-smb \
        campaign-generic check list-nxs install-nxs status

# ---------------------------------------------------------------------------
# Configuration (override on command line or via environment)
# ---------------------------------------------------------------------------
CARGO       ?= cargo
TARGET_DIR  ?= target
BIN         := $(TARGET_DIR)/release/nexsiz
BIN_DEBUG   := $(TARGET_DIR)/debug/nexsiz
NXS_DIR     := nxs
NXS_BIN     := $(NXS_DIR)/bin
FEATURES    ?=
HOST        ?= 127.0.0.1
PORT        ?= 21
MODEL       ?= ftp
SEED        ?= sample/seeds/ftp
OUT         ?= output
WORKERS     ?=
TIMEOUT     ?=
VERBOSE     ?= -v
NXS_SET     ?= default
EXTRA_FLAGS ?=

# Optional feature sets
FEATURES_LIBAFL   := libafl
FEATURES_JSON     := json-model
FEATURES_CRIU     := criu
FEATURES_FULL     := libafl,json-model,criu

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help:
	@echo ""
	@echo "  Nexsiz Operational Makefile"
	@echo "  ==========================="
	@echo ""
	@echo "  Build"
	@echo "    make release          Build optimised binary (default features)"
	@echo "    make release-full     Build with libafl + json-model + criu"
	@echo "    make debug            Build debug binary"
	@echo "    make nxs              Build all official NXS existence scripts"
	@echo "    make nxs-clean        Remove NXS build artefacts"
	@echo ""
	@echo "  Campaign (quick-start against localhost)"
	@echo "    make campaign-ftp     FTP campaign (port 21)"
	@echo "    make campaign-smtp    SMTP campaign (port 25)"
	@echo "    make campaign-http    HTTP campaign (port 80)"
	@echo "    make campaign-dns     DNS TCP campaign (port 53)"
	@echo "    make campaign-mqtt    MQTT campaign (port 1883)"
	@echo "    make campaign-smb     SMB campaign (port 445)"
	@echo "    make campaign-generic Generic binary campaign"
	@echo ""
	@echo "  Inference & Utilities"
	@echo "    make infer            Infer model from SEED= dir"
	@echo "    make infer-ftp        Infer from sample/seeds/ftp"
	@echo "    make clean-shm        Remove residual /dev/shm/nexsiz-cov* maps"
	@echo "    make clean-output     Remove output/ directory"
	@echo "    make clean            cargo clean + nxs-clean"
	@echo "    make clean-all        Full wipe (build + output + shm)"
	@echo "    make list-nxs         Show resolved NXS set"
	@echo "    make status           Show binary + NXS presence"
	@echo ""
	@echo "  Overrides (examples)"
	@echo "    make campaign-ftp HOST=10.0.0.5 PORT=2121"
	@echo "    make release FEATURES=libafl,json-model"
	@echo "    make campaign-ftp NXS_SET=intrusive EXTRA_FLAGS='-C software'"
	@echo "    make infer SEED=seeds/custom OUT=models/inferred.json"
	@echo ""

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------
release:
	@echo "[nexsiz] building release binary…"
	$(CARGO) build --release $(if $(FEATURES),--features "$(FEATURES)")
	@echo "[nexsiz] binary → $(BIN)"
	@ls -lh $(BIN) 2>/dev/null || true

release-full:
	@$(MAKE) release FEATURES="$(FEATURES_FULL)"

debug:
	@echo "[nexsiz] building debug binary…"
	$(CARGO) build $(if $(FEATURES),--features "$(FEATURES)")
	@echo "[nexsiz] binary → $(BIN_DEBUG)"

# Build every official NXS script into nxs/bin/
nxs:
	@echo "[nexsiz] building NXS existence scripts…"
	@cd $(NXS_DIR) && ./build.sh
	@echo "[nexsiz] NXS binaries ready in $(NXS_BIN)/"

nxs-clean:
	@echo "[nexsiz] cleaning NXS build artefacts…"
	@find $(NXS_DIR)/src -type d -name target -exec rm -rf {} + 2>/dev/null || true
	@rm -f $(NXS_BIN)/nxs-*
	@echo "[nexsiz] NXS clean done"

# ---------------------------------------------------------------------------
# Campaign shortcuts (safe localhost defaults)
# ---------------------------------------------------------------------------
# Common runner: requires release binary
define RUN_CAMPAIGN
	@test -x $(BIN) || $(MAKE) release
	@echo "[nexsiz] campaign $(1) → $(HOST):$(2) model=$(3)"
	$(BIN) -h $(HOST) -p $(2) -m $(3) \
		-s $(or $(4),sample/seeds/$(3)) \
		-o $(OUT)/$(3) \
		$(VERBOSE) \
		$(if $(WORKERS),-w $(WORKERS)) \
		$(if $(TIMEOUT),-T $(TIMEOUT)) \
		$(if $(filter-out default,$(NXS_SET)),--nxs $(NXS_SET)) \
		$(EXTRA_FLAGS)
endef

campaign-ftp:
	$(call RUN_CAMPAIGN,ftp,21,ftp,sample/seeds/ftp)

campaign-smtp:
	$(call RUN_CAMPAIGN,smtp,25,smtp,sample/seeds/smtp)

campaign-http:
	$(call RUN_CAMPAIGN,http,80,http,sample/seeds/http)

campaign-dns:
	$(call RUN_CAMPAIGN,dns,53,dns,sample/seeds/generic)
	# DNS frequently needs TCP; override with EXTRA_FLAGS='-P tcp' if desired

campaign-mqtt:
	$(call RUN_CAMPAIGN,mqtt,1883,mqtt,sample/seeds/generic)

campaign-smb:
	$(call RUN_CAMPAIGN,smb,445,smb,sample/seeds/generic)

campaign-generic:
	$(call RUN_CAMPAIGN,generic,1234,generic,sample/seeds/generic)

# ---------------------------------------------------------------------------
# Model inference
# ---------------------------------------------------------------------------
infer:
	@test -x $(BIN) || $(MAKE) release
	@echo "[nexsiz] inferring model from $(SEED)…"
	$(BIN) --infer-model -s $(SEED) $(VERBOSE) \
		$(if $(filter-out output,$(OUT)),--infer-out $(OUT))

infer-ftp:
	@$(MAKE) infer SEED=sample/seeds/ftp

infer-http:
	@$(MAKE) infer SEED=sample/seeds/http

# ---------------------------------------------------------------------------
# House-keeping
# ---------------------------------------------------------------------------
clean-shm:
	@echo "[nexsiz] removing residual coverage SHM maps…"
	@rm -f /dev/shm/nexsiz-cov* 2>/dev/null || true
	@echo "[nexsiz] SHM clean done"

clean-output:
	@echo "[nexsiz] removing output directory…"
	@rm -rf $(OUT)
	@echo "[nexsiz] output clean done"

clean: nxs-clean
	@echo "[nexsiz] cargo clean…"
	$(CARGO) clean
	@echo "[nexsiz] clean done"

clean-all: clean clean-output clean-shm
	@echo "[nexsiz] full wipe complete"

# ---------------------------------------------------------------------------
# Inspection helpers
# ---------------------------------------------------------------------------
list-nxs:
	@test -x $(BIN) || $(MAKE) release
	$(BIN) --nxs $(NXS_SET) --nxs-list

status:
	@echo "=== Nexsiz status ==="
	@echo -n "release binary : "
	@if [ -x $(BIN) ]; then ls -lh $(BIN) | awk '{print $$5, $$9}'; else echo "missing (run make release)"; fi
	@echo -n "debug binary   : "
	@if [ -x $(BIN_DEBUG) ]; then ls -lh $(BIN_DEBUG) | awk '{print $$5, $$9}'; else echo "missing"; fi
	@echo -n "NXS binaries   : "
	@if [ -d $(NXS_BIN) ] && ls $(NXS_BIN)/nxs-* >/dev/null 2>&1; then \
		ls $(NXS_BIN)/nxs-* | wc -l | tr -d ' '; echo " present"; \
	else \
		echo "none (run make nxs)"; \
	fi
	@echo -n "SHM maps       : "
	@ls /dev/shm/nexsiz-cov* 2>/dev/null | wc -l | tr -d ' ' || echo 0
	@echo ""

# Install NXS into a user-local path (optional convenience)
install-nxs: nxs
	@mkdir -p $(HOME)/.nexsiz/nxs/bin
	@cp -f $(NXS_BIN)/nxs-* $(HOME)/.nexsiz/nxs/bin/ 2>/dev/null || true
	@echo "[nexsiz] NXS installed → $(HOME)/.nexsiz/nxs/bin/"
	@echo "         (Nexsiz search path already includes this location)"

# Default target
.DEFAULT_GOAL := help
