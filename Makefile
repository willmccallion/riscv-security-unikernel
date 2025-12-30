# Global config
TAP_DEV := tap0
HOST_IP := 192.168.100.1
KERNEL_BIN := target/riscv64gc-unknown-none-elf/release/security-unikernel

.PHONY: all kernel gui run setup_net clean

all: kernel gui

# kernel (RISC-V)
kernel:
	@echo "[*] Building Kernel (RISC-V)..."
	@cd kernel && cargo build --release

# GUI (Host)
gui:
	@echo "[*] Running GUI (Host)..."
	@cd gui && cargo run --release

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
		-device virtio-net-device,netdev=n0

clean:
	@cd kernel && cargo clean
	@cd gui && cargo clean
