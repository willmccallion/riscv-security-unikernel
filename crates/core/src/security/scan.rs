//! Port-scan detection: sources that open connections to many distinct
//! ports in a short window.

use crate::config::{
    PORT_SCAN_CANDIDATES, PORT_SCAN_CONFIRM_PORTS, PORT_SCAN_NOMINATE_PORTS, PORT_SCAN_POOL_REGISTERS,
    PORT_SCAN_REGISTERS_PER_SOURCE, PORT_SCAN_WINDOW_INTERVALS,
};
use crate::security::sketch::VirtualHyperLogLog;

/// Finds sources that try many distinct destination ports per window.
///
/// A shared virtual HyperLogLog estimates every source's distinct ports in
/// fixed memory, but sharing registers makes its estimates noisy once
/// thousands of sources are active, enough to pass ordinary sources for
/// scanners. So it only nominates suspects; each suspect then gets an
/// exact set of the ports it tries next, and only a full set confirms a
/// scan. The few suspect slots go to whoever was nominated last, evicting
/// the suspect that has shown the fewest ports.
#[derive(Debug)]
pub struct PortScanDetector {
    estimates: VirtualHyperLogLog<PORT_SCAN_POOL_REGISTERS, PORT_SCAN_REGISTERS_PER_SOURCE>,
    suspects: [Option<Suspect>; PORT_SCAN_CANDIDATES],
    intervals_in_window: u32,
}

/// A source confirmed as scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedScan {
    /// The scanning source.
    pub source: [u8; 4],
    /// Distinct ports it tried within one window, counted exactly.
    pub distinct_ports: u32,
}

#[derive(Debug, Clone, Copy)]
struct Suspect {
    source: [u8; 4],
    ports: [u16; PORT_SCAN_CONFIRM_PORTS],
    seen: usize,
}

impl Suspect {
    const fn new(source: [u8; 4], first_port: u16) -> Self {
        let mut ports = [0; PORT_SCAN_CONFIRM_PORTS];
        ports[0] = first_port;
        Self { source, ports, seen: 1 }
    }

    /// Records `port`; returns whether the set is now full.
    fn record(&mut self, port: u16) -> bool {
        if !self.ports[..self.seen].contains(&port) {
            self.ports[self.seen] = port;
            self.seen += 1;
        }
        self.seen == PORT_SCAN_CONFIRM_PORTS
    }
}

impl PortScanDetector {
    /// An empty detector whose hashing is keyed with `key`.
    pub const fn new(key: [u8; 16]) -> Self {
        Self {
            estimates: VirtualHyperLogLog::new(key),
            suspects: [None; PORT_SCAN_CANDIDATES],
            intervals_in_window: 0,
        }
    }

    /// Clears the detector and switches to hashing with `key`.
    pub fn rekey(&mut self, key: [u8; 16]) {
        self.estimates.rekey(key);
        self.suspects = [None; PORT_SCAN_CANDIDATES];
        self.intervals_in_window = 0;
    }

    /// Records a connection attempt from `source` to `port`; returns the
    /// scan it confirms, if any.
    pub fn observe(&mut self, source: [u8; 4], port: u16) -> Option<ConfirmedScan> {
        if let Some(slot) = self.suspects.iter_mut().find(|s| s.is_some_and(|s| s.source == source)) {
            let full = slot.as_mut().is_some_and(|suspect| suspect.record(port));
            if !full {
                return None;
            }
            *slot = None;
            return Some(ConfirmedScan {
                source,
                distinct_ports: PORT_SCAN_CONFIRM_PORTS as u32,
            });
        }
        if self.estimates.insert(&source, &port.to_be_bytes())
            && self.estimates.estimate(&source) > PORT_SCAN_NOMINATE_PORTS
        {
            self.nominate(Suspect::new(source, port));
        }
        None
    }

    /// Counts one detection interval, starting a new window every
    /// [`PORT_SCAN_WINDOW_INTERVALS`].
    pub fn end_interval(&mut self) {
        self.intervals_in_window += 1;
        if self.intervals_in_window >= PORT_SCAN_WINDOW_INTERVALS {
            self.estimates.clear();
            self.suspects = [None; PORT_SCAN_CANDIDATES];
            self.intervals_in_window = 0;
        }
    }

    fn nominate(&mut self, suspect: Suspect) {
        let slot = self
            .suspects
            .iter_mut()
            .min_by_key(|slot| slot.map_or(0, |s| s.seen));
        if let Some(slot) = slot {
            *slot = Some(suspect);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(detector: &mut PortScanDetector, source: [u8; 4], ports: core::ops::Range<u16>) -> Option<ConfirmedScan> {
        ports.into_iter().find_map(|port| detector.observe(source, port))
    }

    #[test]
    fn a_source_trying_hundreds_of_ports_is_confirmed() {
        let mut detector = PortScanDetector::new([3; 16]);

        let confirmed = scan(&mut detector, [10, 0, 0, 9], 1..1000);

        assert_eq!(
            confirmed,
            Some(ConfirmedScan {
                source: [10, 0, 0, 9],
                distinct_ports: PORT_SCAN_CONFIRM_PORTS as u32
            })
        );
    }

    #[test]
    fn sources_using_a_few_ports_are_never_confirmed() {
        let mut detector = PortScanDetector::new([3; 16]);

        let confirmed = (0u32..5_000).find_map(|s| {
            let source = (s | 0x0A00_0000).to_be_bytes();
            [80, 443, 22, 80].into_iter().find_map(|port| detector.observe(source, port))
        });

        assert_eq!(confirmed, None);
    }

    #[test]
    fn repeating_one_port_never_fills_a_suspect() {
        let mut suspect = Suspect::new([1, 2, 3, 4], 80);

        let filled = (0..1000).any(|_| suspect.record(443));

        assert!(!filled);
        assert_eq!(suspect.seen, 2);
    }

    #[test]
    fn a_new_window_forgets_progress() {
        let per_window = PORT_SCAN_CONFIRM_PORTS as u16;
        let mut detector = PortScanDetector::new([3; 16]);
        let source = [10, 0, 0, 9];
        assert_eq!(scan(&mut detector, source, 0..per_window), None);

        for _ in 0..PORT_SCAN_WINDOW_INTERVALS {
            detector.end_interval();
        }

        assert_eq!(scan(&mut detector, source, per_window..2 * per_window), None);
    }

    #[test]
    fn eviction_spares_the_suspect_closest_to_confirmation() {
        let mut detector = PortScanDetector::new([3; 16]);
        detector.suspects[0] = Some(Suspect {
            seen: PORT_SCAN_CONFIRM_PORTS - 1,
            ..Suspect::new([9, 9, 9, 9], 1)
        });
        for i in 1..PORT_SCAN_CANDIDATES {
            detector.suspects[i] = Some(Suspect::new([9, 9, 9, i as u8 + 10], 1));
        }

        for i in 0..PORT_SCAN_CANDIDATES as u8 {
            detector.nominate(Suspect::new([1, 1, 1, i], 1));
        }

        assert!(detector.suspects.iter().any(|s| s.is_some_and(|s| s.source == [9, 9, 9, 9])));
    }
}
