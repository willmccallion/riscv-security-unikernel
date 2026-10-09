//! Matches mgmt acks from the kernel back to the commands the UI issued.

use crate::types::{CommandId, CommandStatus};
use sec_core::security::mgmt::MgmtOutcome;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long to wait for an ack before reporting the command as unanswered.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Commands sent to the kernel and not yet acknowledged, keyed by the
/// sequence number they were sealed with.
#[derive(Debug, Default)]
pub struct PendingAcks {
    by_seq: HashMap<u32, (CommandId, Instant)>,
}

impl PendingAcks {
    /// Records that command `id` went out sealed with `seq` at `sent_at`.
    pub fn sent(&mut self, seq: u32, id: CommandId, sent_at: Instant) {
        let _ = self.by_seq.insert(seq, (id, sent_at));
    }

    /// Resolves the command acknowledged under `seq`, if it is pending.
    pub fn acked(&mut self, seq: u32, outcome: MgmtOutcome) -> Option<(CommandId, CommandStatus)> {
        let (id, _) = self.by_seq.remove(&seq)?;
        let status = match outcome {
            MgmtOutcome::Applied => CommandStatus::Applied,
            rejected => CommandStatus::Rejected(rejected),
        };
        Some((id, status))
    }

    /// Removes and returns every command sent more than `ACK_TIMEOUT`
    /// before `now`.
    pub fn expire(&mut self, now: Instant) -> Vec<CommandId> {
        let mut expired = Vec::new();
        self.by_seq.retain(|_, &mut (id, sent_at)| {
            let keep = now.duration_since(sent_at) < ACK_TIMEOUT;
            if !keep {
                expired.push(id);
            }
            keep
        });
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_resolves_the_command_sent_with_that_sequence() {
        let mut pending = PendingAcks::default();
        let t0 = Instant::now();
        pending.sent(7, CommandId(1), t0);
        pending.sent(8, CommandId(2), t0);

        let resolved = pending.acked(8, MgmtOutcome::TableFull);

        assert_eq!(
            resolved,
            Some((CommandId(2), CommandStatus::Rejected(MgmtOutcome::TableFull)))
        );
    }

    #[test]
    fn ack_for_an_unknown_sequence_is_ignored() {
        let mut pending = PendingAcks::default();
        pending.sent(7, CommandId(1), Instant::now());

        assert_eq!(pending.acked(99, MgmtOutcome::Applied), None);
    }

    #[test]
    fn a_command_is_resolved_only_once() {
        let mut pending = PendingAcks::default();
        pending.sent(7, CommandId(1), Instant::now());
        let _ = pending.acked(7, MgmtOutcome::Applied);

        assert_eq!(pending.acked(7, MgmtOutcome::Applied), None);
    }

    #[test]
    fn unanswered_commands_expire_after_the_timeout() {
        let mut pending = PendingAcks::default();
        let t0 = Instant::now();
        pending.sent(7, CommandId(1), t0);
        pending.sent(8, CommandId(2), t0 + ACK_TIMEOUT);

        let expired = pending.expire(t0 + ACK_TIMEOUT);

        assert_eq!(expired, [CommandId(1)]);
        assert_eq!(pending.acked(8, MgmtOutcome::Applied).map(|(id, _)| id), Some(CommandId(2)));
    }
}
