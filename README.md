# RISC-V Security Unikernel

This project is a high-performance **Network Security Unikernel** written in Rust. It runs as a bare-metal application in Ring 0 on RISC-V architecture, functioning as a programmable edge security appliance similar to Cloudflare's data plane, but running directly on hardware without a host operating system.

It combines **Stateful Firewalling**, **DDoS mitigation**, **Deep Packet Inspection (DPI)**, and **eBPF programmability** into a single, specialized kernel image designed for sub-millisecond latency.

## Engineering Challenge: The 64KB Constraint

A primary goal of this project was to engineer a fully functional network stack and security suite within a strict **64KB RAM** limit. This constraint required aggressive optimization of memory usage and data structures:

*   **Zero-Allocation Runtime:** The kernel operates almost entirely without heap allocation during the hot path. All critical data structures are statically allocated or stack-allocated to ensure deterministic memory usage.
*   **Tuned Buffers:** The VirtIO DMA ring buffers were manually tuned to 1536 bytes (exact Ethernet MTU + headers) to prevent memory fragmentation and overflow.
*   **Probabilistic Data Structures:** Instead of storing full connection tables for DDoS tracking, the kernel uses a **Count-Min Sketch** to track flow frequency with O(1) space complexity.
*   **Static Flow Table:** To achieve stateful inspection without dynamic allocation, the kernel utilizes a fixed-size, packed flow table that fits exactly into the remaining memory, utilizing nearly 100% of available RAM.
*   **Compact DPI:** The Aho-Corasick automaton uses a reduced node set to fit complex signature matching within the remaining memory pages.

## System Architecture

The system operates as a **Unikernel**, meaning the operating system and the application are compiled into a single binary. It interacts directly with the hardware via MMIO.

```text
[ Traffic Generator (Rust GUI) ]
           |  (UDP Telemetry)
           v
      [ TAP Interface ]
           |
           v
[ VirtIO Driver (Zero-Copy DMA) ]
           |
           v
 [ SECURITY UNIKERNEL (Ring 0) ]
    |-- 1. Count-Min Sketch (Probabilistic DDoS Detection)
    |-- 2. Flow Tracker (Stateful Connection Tracking)
    |-- 3. Heuristic Engine (Behavioral Analysis)
    |-- 4. Token Bucket (Traffic Shaping)
    |-- 5. eBPF VM (Dynamic Packet Filtering)
    |-- 6. DPI Engine (Aho-Corasick Payload Scanning)
```

### Packet Processing Pipeline

The kernel utilizes a custom zero-copy driver to process packets directly from the VirtIO RX ring buffer. The processing pipeline consists of six stages:

1.  **Traffic Analysis (Count-Min Sketch):** Tracks the frequency of source IP addresses using hashing functions. This allows the kernel to identify "heavy hitters" (DDoS sources) without maintaining a state table for every IP.
2.  **Stateful Flow Tracking:** A static table tracks active connections (5-tuple), allowing the kernel to monitor flow volume and detect new connections versus established traffic.
3.  **Heuristic Analysis:** The engine scans for behavioral anomalies, such as TCP Xmas scans (invalid flag combinations) or NOP sleds (shellcode patterns) in the payload.
4.  **Rate Limiting & Mitigation:**
    *   **Token Bucket:** A global rate limiter controls total throughput to prevent resource exhaustion.
    *   **Penalty Box:** IP addresses exceeding the packet-per-second threshold are temporarily banned.
5.  **eBPF Packet Filtering:** A custom virtual machine executes bytecode injected at runtime. This allows for dynamic, programmable packet filtering without recompiling or rebooting the kernel.
6.  **Deep Packet Inspection (DPI):** An Aho-Corasick automaton scans packet payloads for known malicious signatures (e.g., SQL injection patterns, script tags) in a single pass.

## Control Plane (GUI)

The project includes a companion desktop application written in Rust (`eframe`/`egui`). This application acts as the management plane, communicating with the kernel via a custom binary UDP protocol.

*   **Dashboard:** Visualizes real-time throughput, active flows, drop rates, and specific alert logs.
*   **Traffic Generator:** Simulates normal HTTP traffic, malware injection, and volumetric DDoS attacks to validate kernel defenses.
*   **SDN Controller:** Pushes new firewall rules (port blocking) and DPI signatures to the kernel at runtime.
*   **eBPF Studio:** Compiles and uploads custom assembly instructions to the kernel's VM.

## Technical Specifications

*   **Target Architecture:** RISC-V 64-bit (`riscv64gc-unknown-none-elf`)
*   **Memory Limit:** 64KB (Defined in linker script `memory.x`)
*   **Language:** Rust (`no_std`, `no_main`)
*   **Network Driver:** VirtIO Net (Legacy) with DMA
*   **Concurrency:** Single-threaded event loop with non-blocking I/O

## Prerequisites

*   **Rust Nightly Toolchain:** Required for inline assembly and bare-metal features.
*   **QEMU:** `qemu-system-riscv64` for emulation.
*   **Make:** For build automation.
*   **IPRoute2:** For TAP interface configuration (requires `sudo`).

## Usage

### 1. Network Setup & Kernel Launch
The Makefile handles the creation of the `tap0` network interface and launches QEMU.

```bash
make run
```
*Note: This command requires `sudo` privileges to configure the TAP interface. To exit QEMU, press `Ctrl+A`, then `X`.*

### 2. Launch Control Plane
Open a separate terminal window to run the GUI.

```bash
make gui
```

### 3. Operation
Once both components are running:
1.  Use the **Traffic Generator** in the GUI to start sending packets to the kernel.
2.  Observe the **Dashboard** for real-time statistics, including active flow counts.
3.  Navigate to the **SDN** or **eBPF** tabs to inject rules and observe immediate effects on traffic processing.

## Project Structure

*   **kernel/**
    *   `src/core/`: Memory allocator and panic handlers.
    *   `src/drivers/`: VirtIO network and UART drivers.
    *   `src/net/`: Network stack implementation (Ethernet, ARP, IPv4, TCP/UDP).
    *   `src/security/`: Implementation of CMS, Flow Tracker, Heuristics, DPI, and the VM.
    *   `memory.x`: Linker script defining the 64KB memory layout.
*   **gui/**
    *   `src/main.rs`: Entry point and initialization.
    *   `src/app.rs`: UI logic and rendering.
    *   `src/traffic.rs`: Async traffic generation and telemetry handling.
*   **Makefile**: Build and deployment automation.
