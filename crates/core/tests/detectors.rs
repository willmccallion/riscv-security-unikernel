//! Detectors below the engine: the NOP-sled heuristic, the flow table
//! under a tuple flood, and DDoS alert sampling.

use sec_core::config::IP_ADDR as KERNEL_IP;
use sec_core::security::alert::should_emit_ddos_alert;
use sec_core::security::flow::{FlowKey, FlowTable};
use sec_core::security::heuristic;
use sec_core::time::Ticks;
use std::net::Ipv4Addr;

/// The shellcode heuristic must catch sleds in the architecture the
/// kernel is actually executing on. Eight consecutive RISC-V `addi
/// x0, x0, 0` instructions form a textbook sled.
#[test]
fn shellcode_heuristic_detects_riscv_nop_sled() {
    let mut payload = Vec::new();
    for _ in 0..8 {
        payload.extend_from_slice(&0x0000_0013u32.to_le_bytes());
    }
    assert!(
        heuristic::has_nop_sled(&payload),
        "RISC-V NOP sled should trigger the shellcode heuristic"
    );
}

/// Interleaving a non-NOP byte between every pair of NOPs must not be
/// enough to evade the heuristic; otherwise any attacker can defeat
/// it by inserting a single junk byte.
#[test]
fn shellcode_heuristic_resists_interleaved_nop_bypass() {
    let payload: Vec<u8> = (0..200).flat_map(|_| [0x00u8, 0x90, 0x90]).collect();
    assert!(
        heuristic::has_nop_sled(&payload),
        "interleaved NOP pattern should still be flagged"
    );
}

/// The flow table tracks at most a fixed number of 5-tuples. Pure LRU
/// eviction lets a flood of unique 5-tuples purge an existing flow,
/// so the eviction policy must keep recently-seen real flows around.
#[test]
fn flow_table_protects_existing_flow_from_unique_tuple_flood() {
    let mut ft = FlowTable::new();
    let now = 1_000u64;

    let real = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 1),
        dst_ip: KERNEL_IP,
        src_port: 1234,
        dst_port: 80,
        protocol: 6,
    };
    let real_seen = ft.update(&real, 100, Ticks::new(now));
    assert!(real_seen, "real flow should be created on first sighting");

    for i in 0..100u16 {
        let flood = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 99),
            dst_ip: KERNEL_IP,
            src_port: 10_000 + i,
            dst_port: 12_345,
            protocol: 6,
        };
        let _ = ft.update(&flood, 100, Ticks::new(now + i as u64 + 1));
    }

    let still_known = !ft.update(&real, 100, Ticks::new(now + 200));
    assert!(
        still_known,
        "the original flow was evicted by a unique-5-tuple flood"
    );
}

/// The first DDoS drop must fire an alert. The naive `count % N == 0`
/// rule swallows it because `1 % N == 1`, so an attack can dump
/// `N - 1` packets before any alert reaches the operator.
#[test]
fn ddos_alert_fires_on_first_drop() {
    assert!(should_emit_ddos_alert(1, 50), "first drop must alert");
    assert!(!should_emit_ddos_alert(2, 50));
    assert!(!should_emit_ddos_alert(49, 50));
    assert!(should_emit_ddos_alert(50, 50));
    assert!(should_emit_ddos_alert(100, 50));
    // sample_rate of 0 should not be a div-by-zero; treat as "alert always".
    assert!(should_emit_ddos_alert(1, 0));
    assert!(should_emit_ddos_alert(99, 0));
}
