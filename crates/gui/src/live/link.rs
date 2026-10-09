//! Reading the monitor's stream in the background.

use monitor_proto::{Hello, MAX_LINE_LEN, Message, PROTOCOL_VERSION, Summary};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

/// How long to wait before trying to reconnect.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// What the background reader reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// Connected; the monitor's greeting.
    Connected(Hello),
    /// One interval's summary.
    Summary(Summary),
    /// Not connected, and why; retried every two seconds.
    Disconnected(String),
}

/// Starts reading the monitor at `path` on a background thread, calling
/// `wake` after each event so the window redraws. The thread ends when
/// the returned receiver is dropped.
pub fn spawn(path: PathBuf, wake: impl Fn() + Send + 'static) -> Receiver<LinkEvent> {
    let (events, receiver) = channel();
    let _ = thread::Builder::new()
        .name("monitor-link".into())
        .spawn(move || run(&path, &events, &wake));
    receiver
}

fn run(path: &PathBuf, events: &Sender<LinkEvent>, wake: &dyn Fn()) {
    loop {
        let why = match UnixStream::connect(path) {
            Ok(stream) => read_stream(BufReader::new(stream), events, wake),
            Err(e) => format!("cannot reach the monitor at {}: {e}", path.display()),
        };
        if events.send(LinkEvent::Disconnected(why)).is_err() {
            return;
        }
        wake();
        thread::sleep(RETRY_DELAY);
    }
}

/// Reads one connection until it ends; returns why it ended. The first
/// line must be a hello of this protocol version.
fn read_stream(mut reader: impl BufRead, events: &Sender<LinkEvent>, wake: &dyn Fn()) -> String {
    let mut first = true;
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_bounded_line(&mut reader, &mut line) {
            Ok(false) => return "the monitor closed the connection".into(),
            Ok(true) => {}
            Err(why) => return why,
        }
        let event = match parse(&line) {
            Ok(Message::Hello(hello)) if first => {
                if hello.protocol != PROTOCOL_VERSION {
                    return format!(
                        "the monitor speaks protocol {}, this dashboard {PROTOCOL_VERSION}; update one of them",
                        hello.protocol
                    );
                }
                LinkEvent::Connected(hello)
            }
            Ok(Message::Summary(summary)) if !first => LinkEvent::Summary(summary),
            Ok(_) => return "the monitor sent messages out of order".into(),
            Err(why) => return why,
        };
        first = false;
        if events.send(event).is_err() {
            return "the dashboard closed".into();
        }
        wake();
    }
}

/// Reads one line into `line`, without its newline. Returns `false` at a
/// clean end of stream; a line longer than [`MAX_LINE_LEN`] is an error.
fn read_bounded_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Result<bool, String> {
    let limit = u64::try_from(MAX_LINE_LEN).unwrap_or(u64::MAX) + 1;
    let read = reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', line)
        .map_err(|e| format!("lost the monitor: {e}"))?;
    if read == 0 {
        return Ok(false);
    }
    if line.last() != Some(&b'\n') {
        return Err(if line.len() > MAX_LINE_LEN {
            "the monitor sent an overlong line".into()
        } else {
            "the monitor's stream ended mid-line".into()
        });
    }
    let _ = line.pop();
    Ok(true)
}

fn parse(line: &[u8]) -> Result<Message, String> {
    let text = std::str::from_utf8(line).map_err(|_| "the monitor sent text that is not UTF-8".to_string())?;
    Message::from_line(text).map_err(|e| format!("the monitor sent something unexpected: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use monitor_proto::Totals;

    fn hello_line(protocol: u32) -> String {
        Message::Hello(Hello {
            protocol,
            interfaces: vec!["enp4s0".into()],
            local_networks: vec![],
            interval_ms: 1000,
        })
        .to_line()
        .unwrap()
    }

    fn summary_line() -> String {
        Message::Summary(Summary {
            start_unix_ms: 1000,
            length_ms: 1000,
            totals: Totals::default(),
            hosts: vec![],
            hosts_omitted: 0,
            active_flows: 0,
            untracked: 0,
        })
        .to_line()
        .unwrap()
    }

    fn read_all(stream: &str) -> (Vec<LinkEvent>, String) {
        let (events, receiver) = channel();
        let ended = read_stream(stream.as_bytes(), &events, &|| {});
        (receiver.try_iter().collect(), ended)
    }

    #[test]
    fn a_hello_then_summaries_become_events() {
        let (events, ended) = read_all(&format!("{}{}{}", hello_line(PROTOCOL_VERSION), summary_line(), summary_line()));

        assert!(matches!(events[0], LinkEvent::Connected(_)));
        assert_eq!(events.len(), 3);
        assert_eq!(ended, "the monitor closed the connection");
    }

    #[test]
    fn another_protocol_version_is_refused() {
        let (events, ended) = read_all(&hello_line(PROTOCOL_VERSION + 1));

        assert!(events.is_empty());
        assert!(ended.contains("protocol"), "{ended}");
    }

    #[test]
    fn a_summary_before_the_hello_is_refused() {
        let (events, ended) = read_all(&summary_line());

        assert!(events.is_empty());
        assert!(ended.contains("out of order"), "{ended}");
    }

    #[test]
    fn garbage_and_overlong_lines_end_the_connection() {
        let garbage = format!("{}not json\n", hello_line(PROTOCOL_VERSION));
        let overlong = format!("{}{}\n", hello_line(PROTOCOL_VERSION), "x".repeat(MAX_LINE_LEN + 10));

        assert!(read_all(&garbage).1.contains("unexpected"));
        assert!(read_all(&overlong).1.contains("overlong"));
        assert!(read_all("{\"type\":\"hel").1.contains("mid-line"));
    }
}
