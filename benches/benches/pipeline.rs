use benches::{dos, dpi, flow, heuristic, vm};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// A synthetic 128-byte UDP payload used across benchmarks.
const CLEAN_PAYLOAD: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: 192.168.100.1\r\nAccept: */*\r\n\
                                Connection: keep-alive\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// The same payload with a SQL injection pattern injected.
const MALICIOUS_PAYLOAD: &[u8] =
    b"POST /login HTTP/1.1\r\nHost: 192.168.100.1\r\n\r\nuser=admin' UNION SELECT 1,2,3--";

/// A payload consisting of a NOP sled followed by dummy shellcode bytes.
const NOP_SLED_PAYLOAD: &[u8] = &[
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0, 0x50, 0x68,
];

// ---------------------------------------------------------------------------
// Count-Min Sketch — DDoS heavy-hitter detection
// ---------------------------------------------------------------------------

fn bench_cms_insert(c: &mut Criterion) {
    let mut cms = dos::CountMinSketch::new();
    let ip: [u8; 4] = [10, 0, 0, 1];
    c.bench_function("cms_insert", |b| {
        b.iter(|| {
            black_box(cms.insert(black_box(&ip)));
        });
    });
}

fn bench_cms_insert_varied(c: &mut Criterion) {
    let mut cms = dos::CountMinSketch::new();
    // 64 distinct source IPs to simulate realistic traffic
    let ips: Vec<[u8; 4]> = (0u8..64).map(|i| [10, 0, 0, i]).collect();
    c.bench_function("cms_insert_64_ips", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            black_box(cms.insert(black_box(&ips[idx % 64])));
            idx = idx.wrapping_add(1);
        });
    });
}

// ---------------------------------------------------------------------------
// Aho-Corasick DPI — multi-pattern payload scan
// ---------------------------------------------------------------------------

fn build_ac() -> dpi::AhoCorasick {
    let mut ac = dpi::AhoCorasick::new();
    ac.insert(b"DROP TABLE");
    ac.insert(b"<script>");
    ac.insert(b"eval(");
    ac.insert(b"UNION SELECT");
    ac.build();
    ac
}

fn bench_ac_scan_clean(c: &mut Criterion) {
    let ac = build_ac();
    c.bench_function("ac_scan_clean_payload", |b| {
        b.iter(|| {
            black_box(ac.scan(black_box(CLEAN_PAYLOAD)));
        });
    });
}

fn bench_ac_scan_match(c: &mut Criterion) {
    let ac = build_ac();
    c.bench_function("ac_scan_matching_payload", |b| {
        b.iter(|| {
            black_box(ac.scan(black_box(MALICIOUS_PAYLOAD)));
        });
    });
}

// ---------------------------------------------------------------------------
// eBPF VM — bytecode execution
// ---------------------------------------------------------------------------

/// Builds a small eBPF program that loads the byte at offset 23 (IP protocol
/// field in a raw Ethernet frame) and returns 0 (drop) if it equals 17 (UDP).
fn udp_drop_program() -> Vec<vm::Instruction> {
    use benches::vm::Instruction;
    vec![
        Instruction::new(0x01, 0, 0, 23),  // ldb r0, [23]   -- load proto byte
        Instruction::new(0x04, 1, 0, 17),  // ldi r1, 17     -- UDP protocol
        Instruction::new(0x06, 0, 1, 0),   // eq  r0, r1
        Instruction::new(0x0B, 0, 0, 5),   // jt  5          -- if equal, jump to drop
        Instruction::new(0x0D, 0, 0, 1),   // ret 1          -- pass
        Instruction::new(0x0D, 0, 0, 0),   // ret 0          -- drop
    ]
}

fn bench_vm_execute(c: &mut Criterion) {
    let mut vm_instance = vm::VM::new();
    let prog = udp_drop_program();
    c.bench_function("vm_execute_6_instructions", |b| {
        b.iter(|| {
            black_box(vm_instance.execute(black_box(&prog), black_box(CLEAN_PAYLOAD)));
        });
    });
}

// ---------------------------------------------------------------------------
// Flow table — 5-tuple lookup and update
// ---------------------------------------------------------------------------

fn bench_flow_update_new(c: &mut Criterion) {
    c.bench_function("flow_update_new_flow", |b| {
        b.iter_batched(
            || {
                // Fresh table for every sample so we always measure the "new flow" path
                flow::FlowTable::new()
            },
            |mut table| {
                black_box(table.update(
                    black_box(&[10, 0, 0, 1]),
                    black_box(&[192, 168, 100, 2]),
                    black_box(54321),
                    black_box(80),
                    black_box(6),
                    black_box(1460),
                    black_box(1_000_000usize),
                ));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_flow_update_existing(c: &mut Criterion) {
    let mut table = flow::FlowTable::new();
    // Pre-insert the flow
    table.update(&[10, 0, 0, 1], &[192, 168, 100, 2], 54321, 80, 6, 1460, 0);
    c.bench_function("flow_update_existing_flow", |b| {
        b.iter(|| {
            black_box(table.update(
                black_box(&[10, 0, 0, 1]),
                black_box(&[192, 168, 100, 2]),
                black_box(54321),
                black_box(80),
                black_box(6),
                black_box(1460),
                black_box(2_000_000usize),
            ));
        });
    });
}

fn bench_flow_full_table(c: &mut Criterion) {
    // Fill the table with 74 distinct flows, then benchmark lookup on the last one
    let mut table = flow::FlowTable::new();
    for i in 0u8..74 {
        table.update(&[10, 0, 0, i], &[192, 168, 100, 2], i as u16 + 1024, 80, 6, 64, 0);
    }
    c.bench_function("flow_update_full_table_74_flows", |b| {
        b.iter(|| {
            black_box(table.update(
                black_box(&[10, 0, 0, 73]),
                black_box(&[192, 168, 100, 2]),
                black_box(1097u16),
                black_box(80),
                black_box(6),
                black_box(64),
                black_box(3_000_000usize),
            ));
        });
    });
}

// ---------------------------------------------------------------------------
// Heuristic engine — TCP flag and NOP-sled detection
// ---------------------------------------------------------------------------

fn bench_heuristic_tcp_flags(c: &mut Criterion) {
    c.bench_function("heuristic_check_tcp_flags", |b| {
        b.iter(|| {
            // Alternate between xmas scan (0x29) and a clean SYN (0x02)
            black_box(heuristic::HeuristicEngine::check_tcp_flags(black_box(0x29)));
            black_box(heuristic::HeuristicEngine::check_tcp_flags(black_box(0x02)));
        });
    });
}

fn bench_heuristic_payload_clean(c: &mut Criterion) {
    c.bench_function("heuristic_check_payload_clean", |b| {
        b.iter(|| {
            black_box(heuristic::HeuristicEngine::check_payload(black_box(CLEAN_PAYLOAD)));
        });
    });
}

fn bench_heuristic_payload_nop_sled(c: &mut Criterion) {
    c.bench_function("heuristic_check_payload_nop_sled", |b| {
        b.iter(|| {
            black_box(heuristic::HeuristicEngine::check_payload(black_box(NOP_SLED_PAYLOAD)));
        });
    });
}

// ---------------------------------------------------------------------------
// Full hot-path simulation: CMS → AC scan → VM execute per packet
// ---------------------------------------------------------------------------

fn bench_full_hot_path(c: &mut Criterion) {
    let mut cms = dos::CountMinSketch::new();
    let ac = build_ac();
    let mut vm_instance = vm::VM::new();
    let prog = udp_drop_program();
    let ips: Vec<[u8; 4]> = (0u8..64).map(|i| [10, 0, 0, i]).collect();

    c.bench_function("full_hot_path_per_packet", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = &ips[idx % 64];
            idx = idx.wrapping_add(1);
            let _count = black_box(cms.insert(black_box(ip)));
            let _hit = black_box(ac.scan(black_box(CLEAN_PAYLOAD)));
            let _action =
                black_box(vm_instance.execute(black_box(&prog), black_box(CLEAN_PAYLOAD)));
        });
    });
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_cms_insert,
    bench_cms_insert_varied,
    bench_ac_scan_clean,
    bench_ac_scan_match,
    bench_vm_execute,
    bench_flow_update_new,
    bench_flow_update_existing,
    bench_flow_full_table,
    bench_heuristic_tcp_flags,
    bench_heuristic_payload_clean,
    bench_heuristic_payload_nop_sled,
    bench_full_hot_path,
);
criterion_main!(benches);
