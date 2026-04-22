//! UTC-midnight rotation for per-(session, layer) JSONL writers.
//!
//! [`RotatingWriterMap`] owns a [`HashMap<(SessionId, LayerKind), LayerWriter>`]
//! and is single-owner: the sink task is the only creator and the only
//! mutator, so there is no interior locking. On every `write` the
//! rotator compares the writer's recorded date against today-UTC (via
//! an injected [`Clock`]) and reopens the file on mismatch. A
//! reopen is cheap: the old `LayerWriter` is dropped (closing its
//! `File` handle), and a new one opens today's
//! `{layer}-YYYY-MM-DD.jsonl` with `append+create`.
//!
//! The rotation decision is made synchronously at the top of
//! `write`; there is no timer-driven preemption. This is deliberate:
//! a session that publishes no events for a day never produces a
//! stale handle, and the "first event after midnight triggers
//! rotation" model is the simplest correct shape. It does mean that
//! a writer opened at 23:59:59.999 and never touched again leaves
//! yesterday's file open until the map is dropped — acceptable, as
//! file handles are cheap on Linux and the sink task itself is
//! dropped on shutdown (which closes every handle).

use std::collections::HashMap;
use std::io;
use std::path::Path;

use chrono::{NaiveDate, Utc};

use crate::api::LayerKind;
use crate::session::SessionId;

use super::writer::LayerWriter;

/// Clock abstraction used by [`RotatingWriterMap`].
///
/// In production we use [`SystemClock`] which reads `Utc::now()`;
/// tests inject a mock implementation that returns a fixed
/// `NaiveDate` so rotation can be driven deterministically without
/// waiting for actual midnight.
pub(super) trait Clock: Send + Sync {
    fn today_utc(&self) -> NaiveDate;
}

/// Production [`Clock`] that reads the real UTC date.
pub(super) struct SystemClock;

impl Clock for SystemClock {
    fn today_utc(&self) -> NaiveDate {
        Utc::now().date_naive()
    }
}

/// Per-(session, layer) set of open writers, rotating at UTC midnight.
pub(super) struct RotatingWriterMap {
    writers: HashMap<(SessionId, LayerKind), LayerWriter>,
}

impl RotatingWriterMap {
    pub(super) fn new() -> Self {
        Self {
            writers: HashMap::new(),
        }
    }

    /// Append `line` to the writer for `(session_id, layer)`, rolling
    /// to today's file if the open handle is for an earlier date.
    ///
    /// Fetches or creates the entry, checks its date against the
    /// clock, reopens on mismatch, and appends. Returns the underlying
    /// [`io::Error`] on any step — the sink task logs and continues,
    /// so a one-off write failure does not bring down the whole
    /// persistent sink.
    pub(super) async fn write<C: Clock>(
        &mut self,
        clock: &C,
        base_dir: &Path,
        session_id: &SessionId,
        layer: LayerKind,
        line: &str,
    ) -> io::Result<()> {
        let today = clock.today_utc();
        let key = (*session_id, layer);
        let needs_open = match self.writers.get(&key) {
            Some(w) => w.date != today,
            None => true,
        };
        if needs_open {
            // Drop the old entry before opening the new one so the
            // old file handle is closed deterministically.
            self.writers.remove(&key);
            let new_writer = LayerWriter::open(base_dir, session_id, layer, today).await?;
            self.writers.insert(key, new_writer);
        }
        let writer = self.writers.get_mut(&key).expect("entry just inserted");
        writer.append_line(line).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use tempfile::tempdir;
    use tokio::fs;

    use super::super::writer::file_path;

    /// Mock clock whose today can be mutated between writes to
    /// simulate UTC-midnight rollover without waiting for real time.
    struct MockClock {
        today: Mutex<NaiveDate>,
    }

    impl MockClock {
        fn new(date: NaiveDate) -> Self {
            Self {
                today: Mutex::new(date),
            }
        }

        fn set(&self, date: NaiveDate) {
            *self.today.lock().unwrap() = date;
        }
    }

    impl Clock for MockClock {
        fn today_utc(&self) -> NaiveDate {
            *self.today.lock().unwrap()
        }
    }

    fn sid() -> SessionId {
        SessionId::parse("0123456789ab").unwrap()
    }

    #[tokio::test]
    async fn rotator_rolls_to_new_date_file() {
        // Start at 2026-04-22, write one line; roll the clock to
        // 2026-04-23, write a second. Two files must exist, each
        // with its one line.
        let dir = tempdir().unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let tomorrow = NaiveDate::from_ymd_opt(2026, 4, 23).unwrap();
        let clock = MockClock::new(today);
        let mut map = RotatingWriterMap::new();
        let sid = sid();

        map.write(
            &clock,
            dir.path(),
            &sid,
            LayerKind::Dns,
            "{\"day\":\"first\"}\n",
        )
        .await
        .expect("first write");
        clock.set(tomorrow);
        map.write(
            &clock,
            dir.path(),
            &sid,
            LayerKind::Dns,
            "{\"day\":\"second\"}\n",
        )
        .await
        .expect("second write");

        // Drop the map so handles flush/close.
        drop(map);

        let first = file_path(dir.path(), &sid, LayerKind::Dns, today);
        let second = file_path(dir.path(), &sid, LayerKind::Dns, tomorrow);
        let first_body = fs::read_to_string(&first).await.unwrap();
        let second_body = fs::read_to_string(&second).await.unwrap();
        assert_eq!(first_body, "{\"day\":\"first\"}\n", "file @ {first:?}");
        assert_eq!(second_body, "{\"day\":\"second\"}\n", "file @ {second:?}");
    }

    #[tokio::test]
    async fn rotator_reuses_writer_same_date() {
        // Two writes on the same day must land in the same file,
        // not reopen a fresh handle each time. Observable effect:
        // only one file exists after the two writes.
        let dir = tempdir().unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let clock = MockClock::new(today);
        let mut map = RotatingWriterMap::new();
        let sid = sid();

        map.write(&clock, dir.path(), &sid, LayerKind::Envoy, "{\"n\":1}\n")
            .await
            .unwrap();
        map.write(&clock, dir.path(), &sid, LayerKind::Envoy, "{\"n\":2}\n")
            .await
            .unwrap();
        drop(map);

        let path = file_path(dir.path(), &sid, LayerKind::Envoy, today);
        let body = fs::read_to_string(&path).await.unwrap();
        assert_eq!(body, "{\"n\":1}\n{\"n\":2}\n");

        // No "today+1" file should have been created.
        let tomorrow = NaiveDate::from_ymd_opt(2026, 4, 23).unwrap();
        let other = file_path(dir.path(), &sid, LayerKind::Envoy, tomorrow);
        assert!(
            !other.exists(),
            "rotator must not create a fresh file on reuse; stray file: {other:?}"
        );
    }

    #[tokio::test]
    async fn rotator_segregates_by_layer_and_session() {
        // Two different (session, layer) pairs written on the same
        // day must produce two files — keys must include both axes,
        // not just one.
        let dir = tempdir().unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let clock = MockClock::new(today);
        let mut map = RotatingWriterMap::new();
        let sid_a = SessionId::parse("aaaaaaaaaaaa").unwrap();
        let sid_b = SessionId::parse("bbbbbbbbbbbb").unwrap();

        map.write(
            &clock,
            dir.path(),
            &sid_a,
            LayerKind::Dns,
            "{\"a\":\"dns\"}\n",
        )
        .await
        .unwrap();
        map.write(
            &clock,
            dir.path(),
            &sid_a,
            LayerKind::Envoy,
            "{\"a\":\"envoy\"}\n",
        )
        .await
        .unwrap();
        map.write(
            &clock,
            dir.path(),
            &sid_b,
            LayerKind::Dns,
            "{\"b\":\"dns\"}\n",
        )
        .await
        .unwrap();
        drop(map);

        for (sid, layer, marker) in &[
            (&sid_a, LayerKind::Dns, "{\"a\":\"dns\"}\n"),
            (&sid_a, LayerKind::Envoy, "{\"a\":\"envoy\"}\n"),
            (&sid_b, LayerKind::Dns, "{\"b\":\"dns\"}\n"),
        ] {
            let p = file_path(dir.path(), sid, *layer, today);
            let body = fs::read_to_string(&p).await.unwrap();
            assert_eq!(body, *marker, "wrong body @ {p:?}");
        }
    }
}
