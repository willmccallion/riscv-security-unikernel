# Global config
TAP_DEV := tap0
HOST_IP := 192.168.100.1
KERNEL_BIN := target/riscv64gc-unknown-none-elf/release/security-unikernel

RAM_LIMIT := 65536

.PHONY: all kernel gui daemon run setup_net bench check-size clean miri \
        fuzz-process-packet fuzz-mgmt-auth fuzz-vm fuzz-ahocorasick fuzz-build

all: kernel gui

# kernel (RISC-V)
kernel:
	@echo "[*] Building Kernel (RISC-V)..."
	@cd crates/kernel && cargo build --release

# GUI (Host)
gui:
	@echo "[*] Running GUI (Host)..."
	@cargo run -p security-dashboard --release

# Linux userspace daemon (stub)
daemon:
	@echo "[*] Running Linux daemon (stub)..."
	@cargo run -p security-daemon --release

# Runtime
setup_net:
	@echo "[*] Configuring Network..."
	@ip link show $(TAP_DEV) > /dev/null 2>&1 || \
		(sudo ip tuntap add dev $(TAP_DEV) mode tap user $(shell whoami))
	@sudo ip link set $(TAP_DEV) up
	@sudo ip addr flush dev $(TAP_DEV)
	@sudo ip addr add $(HOST_IP)/24 dev $(TAP_DEV)

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
		-echr 0x02

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
	@MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p sec-core

# cargo-fuzz harnesses for the parsers and stateful primitives that take
# attacker-controlled bytes. Each target runs until interrupted; pass
# `-- -max_total_time=N` for a bounded run, e.g.:
#   make fuzz-process-packet ARGS="-- -max_total_time=60"
FUZZ_DIR := crates/core/fuzz
ARGS ?=

fuzz-build:
	@echo "[*] Compiling all fuzz targets..."
	@cd $(FUZZ_DIR) && cargo +nightly fuzz build

fuzz-process-packet:
	@cd $(FUZZ_DIR) && cargo +nightly fuzz run process_packet $(ARGS)

fuzz-mgmt-auth:
	@cd $(FUZZ_DIR) && cargo +nightly fuzz run mgmt_auth_verify $(ARGS)

fuzz-vm:
	@cd $(FUZZ_DIR) && cargo +nightly fuzz run vm_execute $(ARGS)

fuzz-ahocorasick:
	@cd $(FUZZ_DIR) && cargo +nightly fuzz run ahocorasick_scan $(ARGS)

clean:
	@cargo clean
	@cd $(FUZZ_DIR) && cargo clean 2>/dev/null || true
