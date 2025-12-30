pub struct HeuristicEngine;

impl HeuristicEngine {
    pub fn check_tcp_flags(flags: u8) -> Option<&'static str> {
        // Xmas Scan: FIN | URG | PSH (0x29)
        // Used to bypass simple firewalls
        if (flags & 0x29) == 0x29 {
            return Some("Heuristic: Xmas Scan Detected");
        }

        // Null Scan: No flags set
        // Used for OS fingerprinting
        if flags == 0 {
            return Some("Heuristic: Null Scan Detected");
        }

        None
    }

    pub fn check_payload(payload: &[u8]) -> Option<&'static str> {
        // NOP Sled Detection (0x90 0x90 0x90 0x90)
        // Indicates binary shellcode / buffer overflow attempt
        let mut consecutive_nops = 0;
        for &byte in payload {
            if byte == 0x90 {
                consecutive_nops += 1;
                if consecutive_nops >= 8 {
                    return Some("Heuristic: Shellcode (NOP Sled)");
                }
            } else {
                consecutive_nops = 0;
            }
        }
        None
    }
}
