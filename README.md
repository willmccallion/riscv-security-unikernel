# RISC-V Security Unikernel

A bare-metal **network security appliance** written in Rust, running in M-mode on RISC-V without a host OS. Heavy-hitter DDoS detection, rate limiting, a port firewall, deep packet inspection, heuristics and a programmable packet-filter VM all fit in a **64 KB RAM** budget.

The kernel inspects traffic addressed to it and reports verdicts; it does not forward packets. It is a demonstration of the techniques, not an inline firewall.

```mermaid
graph LR
    subgraph GUI["GUI Control Plane (egui)"]
        TG[Traffic Generator]
        CP[Dashboard / SDN / eBPF Studio]
    end

    subgraph Kernel["RISC-V Kernel · 64 KB RAM"]
        RX[VirtIO-Net]
        MGT[Management · UDP :1337]
        REP[Signed reports]
    end

    REP -->|telemetry, alerts, acks → UDP :8888| CP
    CP -->|sealed commands| MGT
    TG -->|test traffic| RX
```

---

## The 64 KB Budget

| Structure | Size | Technique |
|---|---|---|
| Count-Min Sketch | 6 KB | 3 × 1024 × u16, SipHash-keyed, conservative update, halved every 0.5 s |
| Flow table (74 entries) | ~3 KB | 5-tuple entries, LRU eviction with a minimum age |
| Aho-Corasick automaton | ~1.3 KB | 128-node trie for built-in signatures |
| VirtIO queues and buffers | ~6.3 KB | 2 RX + 2 TX MTU-sized buffers, rings on 64-byte legacy pages |
| BPF program slot | 448 B | 64 instructions × 7 bytes |
| Penalty box | 256 B | 16 bans, round-robin eviction once every slot is active |
| **Hot-path allocations** | **0 B** | No heap; all state is static |

`make check-size` adds a 4 KB stack reserve to `.text + .rodata + .data + .bss` and fails if the total exceeds 64 KB. The current kernel uses about **47.8 KB**.

---

## Packet Processing Pipeline

Every received frame goes through `sec_core::engine::Engine::process`, which is plain Rust with no I/O and runs, is tested and is fuzzed on the host.

```mermaid
flowchart TD
    RX["VirtIO RX"]
    MG{"UDP to :1337?"}
    ML["Mgmt rate limit → MAC + replay check<br/>→ apply command → signed ack"]
    PB["① Penalty box / Count-Min Sketch<br/>ban sources above ~100 packets per second"]
    TB["② Global token bucket"]
    FT["③ Flow table"]
    TF["④ TCP flag heuristics<br/>Xmas · null scans"]
    BPF["⑤ BPF filter VM"]
    FW["⑥ Port firewall"]
    ST["⑦ Network stack<br/>answers ARP, ICMP echo, SYN (SYN-ACK with cookie)"]
    HP["⑧ Payload heuristics<br/>x86 and RISC-V NOP sleds"]
    DPI["⑨ DPI<br/>Aho-Corasick + runtime patterns"]
    PASS["Counted as passed"]
    DROP["Dropped + rate-limited signed alert"]

    RX --> MG
    MG -->|yes| ML
    MG -->|no| PB
    PB -->|banned or heavy hitter| DROP
    PB --> TB
    TB -->|no token| DROP
    TB --> FT --> TF
    TF -->|anomaly| DROP
    TF --> BPF
    BPF -->|drop / timeout / bad action| DROP
    BPF --> FW
    FW -->|blocked port| DROP
    FW --> ST --> HP
    HP -->|sled| DROP
    HP --> DPI
    DPI -->|match| DROP
    DPI --> PASS
```

Management traffic is handled before any data-plane check, behind its own rate limiter, so no ban, filter program or flood can lock the operator out.

---

## Security Mechanisms

### Count-Min Sketch — heavy-hitter detection
Counts packets per source IP in a Count-Min Sketch keyed with a per-boot SipHash key, using conservative update. Counters are halved every half second, so a source's estimate tracks its recent packet rate; one above 100 per second is banned in the penalty box.

### Sizing the sketch

`make sketch-study` measures the sketch against exact ground truth (`crates/sketch-lab`) and redraws these charts.

![Count-Min estimate error against memory](docs/sketches/cms_error_vs_memory.svg)

On a skewed (Zipf 1.1) stream of 200k packets over 50k sources, conservative update cuts the average overestimate by 37–70% compared with the textbook update, depending on size; at the kernel's 6 KB it falls from 48 packets to 29.

![Legitimate sources banned as total traffic grows](docs/sketches/cms_false_positives_vs_load.svg)

The detector test runs legitimate sources at 5–20 pps alongside ten attackers at 300 pps for ten seconds, at increasing total traffic. The previous design (128 × 4, textbook update, reset every second) banned 68% of legitimate sources at 20k pps and all of them by 50k. At the same 1 KB, conservative update and decay hold out to 20k; the kernel's 6 KB sketch flags no legitimate source up to 200k pps, and the daemon's 512 KB one none at 500k. No configuration missed an attacker, and detection took 27–340 ms.

The study also caught a flaw in an earlier version of the hashing. Deriving each row's column as `h1 + i·h2` from one hash makes two sources that share `h1` and `h2` modulo the width collide in every row at once, so a legitimate source paired with an attacker this way was banned however many rows the sketch had. Each row now takes its column from its own slice of the 64-bit SipHash.

### Aho-Corasick DPI
Single-pass scan for the built-in signatures `DROP TABLE`, `<script>`, `eval(` and `UNION SELECT`. Up to eight more patterns of up to 32 bytes can be added and removed at runtime. Matching is case-sensitive and per packet.

### BPF filter VM
A small 16-register bytecode VM (not Linux eBPF) with load, move, compare, bitwise, jump and return instructions. Programs are validated on upload (opcodes, registers, jump targets), run with a 1,000-instruction budget per packet, and must return 0 (drop) or 1 (pass). The GUI's eBPF Studio compiles `BLOCK <TCP|UDP> DST <port>` and `DROP ALL`.

### Heuristics
TCP Xmas (FIN|URG|PSH) and null scans; x86 NOP sleds (a decaying score that reaches 8, so interleaved junk bytes do not hide them) and runs of 8 RISC-V NOPs.

---

## Management Protocol

Commands are UDP datagrams to port 1337 carrying `counter (u64) ‖ body ‖ SipHash-2-4 MAC (u64)`. The counter's high 32 bits are the kernel's per-boot epoch and the low 32 bits a strictly increasing sequence, so commands cannot be forged or replayed within or across boots. The key is set at build time (`KERNEL_MGMT_KEY`, or `.mgmt-key.local` created by `make dev-key`).

| Command | Undo |
|---|---|
| `BlockPort` | `UnblockPort` |
| `AddDpiPattern` | `RemoveDpiPattern` |
| `UploadBpfProgram` | `UnloadBpfProgram` |
| `BanIp` | `UnbanIp` |

Every authenticated command is answered with an ack carrying its sequence number and outcome (applied, table full, invalid or refused).

### Reports

Telemetry (every interval), alerts and acks go to UDP port 8888, broadcast until an operator has authenticated and unicast to that operator afterwards. Each is signed with a key derived from the management key, so it cannot be forged or replayed back to the kernel as a command:

`epoch (u32) ‖ sequence (u64) ‖ body ‖ SipHash-2-4 MAC (u64)`

The telemetry body is a type byte followed by ten big-endian u64 counters: passed, DDoS drops, firewall blocks, malware matches, BPF drops, heuristic drops, RAM used, active flows, management packets and the boot epoch.

---

## Dashboard

![Security Appliance Dashboard](assets/gui.png)

The companion desktop app (`egui`/`eframe`) shows live counters and the alert log, manages firewall rules, DPI patterns and BPF programs (with the kernel's ack for each), and generates test traffic. It accepts only reports that verify.

**Traffic modes:** Normal (about 2 packets per millisecond), DDoS (300 per millisecond to common ports), Live (normal traffic with periodic attack payloads and DDoS bursts). Run `make setup_net_many` first so the generator sends from 200 real source addresses; otherwise it falls back to 50 sockets on the host and normal traffic trips the heavy-hitter detector.

---

## Technical Specifications

| Property | Value |
|---|---|
| Target ISA | RV64GC (`riscv64gc-unknown-none-elf`) |
| RAM budget | 64 KB |
| Language | Rust `no_std` / `no_main` |
| Network driver | VirtIO-Net (legacy MMIO), polled |
| Concurrency model | Single hart, polling loop; other harts are parked |
| Memory protection | PMP: W^X over the kernel image, MMIO confined to the device window |
| Build profile | `opt-level = "z"`, LTO, `codegen-units = 1`, stripped |

Thresholds and intervals are in `mcycle` cycles, so their wall-clock meaning depends on the CPU's clock rate.

---

## Benchmarks

The pure-logic modules are benchmarked on the host with [Criterion](https://github.com/bheisler/criterion.rs):

```bash
make bench
```

Medians on an Intel Core i7-14700K:

| Benchmark | Median |
|---|---|
| `cms_insert` (single IP) | 8.3 ns |
| `cms_insert_64_ips` (varied) | 7.8 ns |
| `ac_scan_clean_payload` (128 B, no match) | 212 ns |
| `ac_scan_matching_payload` (early match) | 119 ns |
| `vm_execute_6_instructions` | 5.2 ns |
| `flow_update_new_flow` | 109 ns |
| `flow_update_existing_flow` | 3.3 ns |
| `flow_update_full_table_74_flows` | 42 ns |
| `heuristic_check_tcp_flags` | 0.7 ns |
| `heuristic_check_payload_clean` | 66 ns |
| `heuristic_check_payload_nop_sled` | 2.4 ns |
| `full_hot_path_per_packet` (CMS + Aho-Corasick + VM) | 226 ns |

---

## Linux Daemon

`security-daemon` runs the same `sec_core` engine as a Linux program, so the pipeline can be measured on real hardware and real traffic.

```bash
make daemon-bench DAEMON_ARGS="--threads 8 --mix clean"   # in-memory throughput
make daemon-speedtest                                      # live AF_PACKET test over a veth pair, no sudo
sudo ./target/release/security-daemon run --iface eth0     # inspect a real interface (needs CAP_NET_RAW)
```

`run` captures through a memory-mapped `TPACKET_V3` ring and sends replies and signed reports back out of the interface, so the GUI can drive it like the kernel. It takes on the kernel's identity from `sec_core::config` (192.168.100.2, `52:54:00:12:34:56`). `bench` tells the engine traffic arrives at `--offered-pps` (default 10k) while measuring the real CPU cost per frame.

On an Intel Core i7-14700K, one engine handles about **1.1 Mpps** of clean traffic with every frame running the full pipeline (about 890 ns per frame, mostly the Aho-Corasick scan), and attack traffic that is dropped early at about 10 Mpps. Engines are independent, so throughput scales with threads (about 11 Mpps on 16).

The daemon's engine uses a 65536 × 4 heavy-hitter sketch (512 KB) instead of the kernel's 6 KB one, so its detector stays accurate far past the kernel's 200k pps (see [Sizing the sketch](#sizing-the-sketch)). Above 100k pps the separate global rate limit, not the sketch, drops traffic.

---

## Testing

```bash
cargo test --workspace --exclude security-unikernel   # host unit, property and engine tests
make qemu-test                                         # boots the real kernel in QEMU
make miri                                              # sec-core tests under Miri
make fuzz-engine-sequence ARGS="-- -max_total_time=600"
make sketch-study                                      # sketch accuracy against ground truth
```

`make qemu-test` exchanges raw Ethernet frames with the kernel over a Unix socket (QEMU's `dgram` netdev), so it needs no tap device or root. Fuzz targets cover the packet stack, the whole engine (single frames and long sequences of frames, sealed commands and clock steps), the management verifier, the VM and the DPI automaton.

---

## Running

**Requirements:** Rust (pinned in `rust-toolchain.toml`; nightly for fuzzing and Miri) · `qemu-system-riscv64` · `iproute2` · `make`

On Nix, `nix develop` provides all of these.

```bash
# Build the kernel, configure the tap interface and launch QEMU
make run

# Launch the GUI (separate terminal)
make gui
```

1. On the **Dashboard** tab, click **NORMAL (HTTP)**, **DDoS ATTACK** or **LIVE SIMULATION**
2. Watch the counters, graph and event log for throughput and drop reasons
3. Use the **SDN / FIREWALL** tab to add or remove firewall rules and DPI signatures
4. Use the **eBPF STUDIO** tab to upload or unload a packet filter

Press `Ctrl+B X` to exit QEMU.

---

## Limitations and Next Steps

This is a demonstration of the techniques, not a production security appliance:

- **Nothing is protected inline.** The kernel and the daemon inspect traffic addressed to their own address (192.168.100.2, compiled in) and report verdicts; they do not forward or filter traffic for other hosts.
- **DPI is shallow.** Signatures are matched case-sensitively within single packets, with no TCP stream or IP fragment reassembly, so splitting or re-encoding a payload evades them, and encrypted traffic is opaque.
- **Tables are sized for 64 KB.** 74 flows, 16 bans, and in the kernel a heavy-hitter sketch that starts banning legitimate sources somewhere between 200k and 500k packets per second of total traffic.
- **IPv4 only**, no VLANs, no runtime configuration; thresholds are in CPU cycles.
- **One pre-shared key** authenticates the management plane, with no rotation.

The natural next step is an L3/L4 DDoS scrubber: an XDP program doing the per-packet ban, rate-limit and port checks in the kernel driver at line rate, driven by the existing authenticated control plane and dashboard, with deeper inspection of surviving traffic over AF_XDP.
