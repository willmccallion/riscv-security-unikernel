# Global config
TAP_DEV := tap0
HOST_IP := 192.168.100.1
KERNEL_BIN := target/riscv64gc-unknown-none-elf/release/security-unikernel
GUI_BIN := target/release/security-dashboard

# Multi-source traffic generator (netns mode).
BRIDGE := br-sec
NS_PREFIX := sec-ns
NS_COUNT ?= 200

RAM_LIMIT := 65536

# rustup users get nightly via `+nightly`; the Nix dev shell sets
# CARGO_NIGHTLY=cargo-nightly since it has no rustup proxy.
CARGO_NIGHTLY ?= cargo +nightly

.PHONY: all kernel gui daemon run setup_net setup_net_many teardown_net_many \
        bench check-size clean miri dev-key qemu-test \
        fuzz-process-packet fuzz-mgmt-auth fuzz-vm fuzz-ahocorasick fuzz-build \
        fuzz-engine-frame fuzz-engine-sequence

all: kernel gui

# Local developer mgmt key. The kernel's build.rs refuses release builds
# without KERNEL_MGMT_KEY, so we materialize a random 16-byte key on first
# build and reuse it for both kernel and GUI. Never committed (see
# .gitignore). For real deployments, set KERNEL_MGMT_KEY in the environment
# before building and this fallback is ignored.
DEV_KEY_FILE := .mgmt-key.local

$(DEV_KEY_FILE):
	@echo "[!] KERNEL_MGMT_KEY not set — generating local dev key at $(DEV_KEY_FILE)"
	@echo "[!] This key is for development only. DO NOT DEPLOY a kernel built with it."
	@openssl rand -hex 16 > $(DEV_KEY_FILE)

dev-key: $(DEV_KEY_FILE)
	@echo "[*] Dev mgmt key: $$(cat $(DEV_KEY_FILE))"

# If the caller hasn't exported KERNEL_MGMT_KEY, depend on the local key
# file and read it from inside the recipe (after the file exists).
ifeq ($(origin KERNEL_MGMT_KEY), undefined)
KEY_DEP := $(DEV_KEY_FILE)
KEY_CMD := KERNEL_MGMT_KEY=$$(cat $(CURDIR)/$(DEV_KEY_FILE))
else
KEY_DEP :=
KEY_CMD :=
endif

# kernel (RISC-V)
kernel: $(KEY_DEP)
	@echo "[*] Building Kernel (RISC-V)..."
	@cd crates/kernel && $(KEY_CMD) cargo build --release

# GUI (Host)
#
# Builds the GUI, then grants it CAP_SYS_ADMIN so the traffic generator
# can `setns(2)` into each per-source namespace without running the
# whole dashboard as root. The capability has to be re-applied after
# every rebuild (cargo replaces the binary); doing it here keeps the
# flow a single `make gui`. Requires sudo once per build; skipped if
# `make setup_net_many` hasn't been run and the GUI will fall back to
# host-bound sockets.
gui: $(KEY_DEP)
	@echo "[*] Building GUI (Host)..."
	@$(KEY_CMD) cargo build -p security-dashboard --release
	@echo "[*] Granting cap_sys_admin to GUI binary (sudo)..."
	@sudo setcap cap_sys_admin,cap_net_admin+ep $(GUI_BIN)
	@echo "[*] Running GUI..."
	@$(KEY_CMD) $(GUI_BIN)

# Linux userspace daemon (stub)
daemon:
	@echo "[*] Running Linux daemon (stub)..."
	@cargo run -p security-daemon --release

# Runtime
setup_net:
	@echo "[*] Configuring Network..."
	@# If setup_net_many is already active, the bridge owns $(HOST_IP)
	@# and tap0 is enslaved to it; re-flushing tap0 or re-adding
	@# $(HOST_IP) to it would yank networking out from under the
	@# namespaces. Detect and skip.
	@if ip link show $(BRIDGE) > /dev/null 2>&1; then \
		echo "[*] Bridge $(BRIDGE) present — leaving multi-source topology alone"; \
	else \
		(ip link show $(TAP_DEV) > /dev/null 2>&1 || \
			sudo ip tuntap add dev $(TAP_DEV) mode tap user $(shell whoami)) && \
		sudo ip link set $(TAP_DEV) up && \
		sudo ip addr flush dev $(TAP_DEV) && \
		sudo ip addr add $(HOST_IP)/24 dev $(TAP_DEV); \
	fi

# Multi-source traffic topology.
#
# Goal: let the GUI traffic generator present NS_COUNT genuinely
# distinct source IPs so the kernel's per-source heavy-hitter detector
# is exercised against real diversity (not just ~50 host-bound
# sockets, which trips the threshold on every legit client).
#
# Topology: a bridge joins the QEMU tap to one veth pair per
# namespace. Each namespace gets 192.168.100.{10+i}/24, default
# route via $(HOST_IP), and its veth-host peer is enslaved to the
# bridge. $(HOST_IP) stays on the bridge (not on tap0) so the host,
# QEMU kernel, and all namespace endpoints sit on one L2 segment.
#
# Idempotent: re-running first tears down, then rebuilds. The GUI's
# setcap already picks up the new namespaces on next launch.
#
# Requires sudo (CAP_NET_ADMIN). NS_COUNT defaults to 200; override
# with `make setup_net_many NS_COUNT=50` for a lighter dev setup.
setup_net_many: teardown_net_many
	@echo "[*] Creating bridge $(BRIDGE) and $(NS_COUNT) namespaces..."
	@sudo ip link add name $(BRIDGE) type bridge
	@sudo ip link set $(BRIDGE) up
	@# Move tap0 onto the bridge: flush its IP (it now belongs to the
	@# bridge itself) and enslave it. Recreate tap0 if the user
	@# skipped setup_net.
	@ip link show $(TAP_DEV) > /dev/null 2>&1 || \
		(sudo ip tuntap add dev $(TAP_DEV) mode tap user $(shell whoami))
	@sudo ip link set $(TAP_DEV) up
	@sudo ip addr flush dev $(TAP_DEV)
	@sudo ip link set $(TAP_DEV) master $(BRIDGE)
	@sudo ip addr add $(HOST_IP)/24 dev $(BRIDGE)
	@for i in $$(seq 0 $$(($(NS_COUNT) - 1))); do \
		idx=$$(printf "%03d" $$i); \
		ns=$(NS_PREFIX)-$$idx; \
		veth_h=vh-$$idx; veth_n=vn-$$idx; \
		ip=192.168.100.$$(( 10 + $$i )); \
		sudo ip netns add $$ns; \
		sudo ip link add $$veth_h type veth peer name $$veth_n; \
		sudo ip link set $$veth_n netns $$ns; \
		sudo ip link set $$veth_h master $(BRIDGE); \
		sudo ip link set $$veth_h up; \
		sudo ip -n $$ns addr add $$ip/24 dev $$veth_n; \
		sudo ip -n $$ns link set $$veth_n up; \
		sudo ip -n $$ns link set lo up; \
		sudo ip -n $$ns route add default via $(HOST_IP); \
	done
	@echo "[*] Done: $(NS_COUNT) namespaces (192.168.100.10 .. 192.168.100.$$(( 10 + $(NS_COUNT) - 1 )))"

teardown_net_many:
	@echo "[*] Tearing down netns topology (if present)..."
	@for ns in $$(ip netns list 2>/dev/null | awk '/^$(NS_PREFIX)-/ {print $$1}'); do \
		sudo ip netns del $$ns 2>/dev/null || true; \
	done
	@# Veth host-ends are deleted with their peer in the ns, but
	@# belt-and-braces in case a ns was already gone.
	@for v in $$(ip -o link show type veth 2>/dev/null | awk -F': ' '/vh-[0-9]/ {print $$2}' | awk '{print $$1}'); do \
		sudo ip link del $$v 2>/dev/null || true; \
	done
	@if ip link show $(BRIDGE) > /dev/null 2>&1; then \
		sudo ip link del $(BRIDGE); \
	fi

run: kernel setup_net
	@echo "[*] Starting QEMU..."
	@size $(KERNEL_BIN) | awk 'NR==2 {total = $$1 + $$2 + $$3 + 4096; printf "[*] Memory Usage: %d Bytes / 65536 Bytes (%.4f%%)\n", total, (total/65536)*100}'
	@qemu-system-riscv64 \
		-machine virt \
		-global virtio-mmio.force-legacy=true \
		-m 128M \
		-bios none \
		-nographic \
		-kernel $(KERNEL_BIN) \
		-netdev tap,id=n0,ifname=$(TAP_DEV),script=no,downscript=no \
		-device virtio-net-device,netdev=n0 \
		-object rng-random,id=rng0,filename=/dev/urandom \
		-device virtio-rng-device,rng=rng0 \
		-echr 0x02

# Boot the real kernel under QEMU and run the end-to-end tests against it.
# Frames travel over a Unix socket, so no tap device or sudo is needed.
qemu-test: kernel
	@cargo test -p qemu-harness -- --ignored --test-threads=4

# Run criterion benchmarks (host-native, no QEMU required)
bench:
	@echo "[*] Running benchmarks..."
	@cargo bench -p benches

# Verify the kernel static footprint stays within the 64 KB RAM budget.
# Measures .text + .rodata + .data + .bss and adds a 4 KB stack guard.
check-size: kernel
	@size $(KERNEL_BIN) | awk -v limit=$(RAM_LIMIT) \
	  'NR==2 { \
	    total = $$1 + $$2 + $$3 + 4096; \
	    pct = (total / limit) * 100; \
	    printf "[*] Kernel footprint: %d / %d bytes (%.1f%%)\n", total, limit, pct; \
	    if (total > limit) { \
	      printf "FAIL: kernel exceeds %d-byte RAM budget by %d bytes\n", limit, total - limit; \
	      exit 1 \
	    } else { \
	      print "PASS: within budget" \
	    } \
	  }'

# Miri runs the sec-core test suite under an interpreter that detects UB
# (out-of-bounds, uninit reads, aliasing/provenance violations). Exercises
# every unsafe block we ship.
miri:
	@echo "[*] Running Miri on sec-core..."
	@MIRIFLAGS=-Zmiri-disable-isolation $(CARGO_NIGHTLY) miri test -p sec-core

# cargo-fuzz harnesses for the parsers and stateful primitives that take
# attacker-controlled bytes. Each target runs until interrupted; pass
# `-- -max_total_time=N` for a bounded run, e.g.:
#   make fuzz-process-packet ARGS="-- -max_total_time=60"
FUZZ_DIR := crates/core/fuzz
ARGS ?=

fuzz-build:
	@echo "[*] Compiling all fuzz targets..."
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz build

fuzz-process-packet:
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz run process_packet $(ARGS)

fuzz-mgmt-auth:
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz run mgmt_auth_verify $(ARGS)

fuzz-vm:
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz run vm_execute $(ARGS)

fuzz-ahocorasick:
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz run ahocorasick_scan $(ARGS)

fuzz-engine-frame:
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz run engine_frame $(ARGS)

fuzz-engine-sequence:
	@cd $(FUZZ_DIR) && $(CARGO_NIGHTLY) fuzz run engine_sequence $(ARGS)

clean:
	@cargo clean
	@cd $(FUZZ_DIR) && cargo clean 2>/dev/null || true
