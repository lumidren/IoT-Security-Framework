//! Statistics used by the load test: latency recorders with exact nearest-rank percentiles over
//! every sample (no estimation, no histogram buckets), rates, the ramp schedule and Prometheus
//! text deltas.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Percentile summary of a latency sample, in milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Samples.
    pub count: u64,
    /// Minimum.
    pub min_ms: f64,
    /// Arithmetic mean.
    pub mean_ms: f64,
    /// Median (nearest rank).
    pub p50_ms: f64,
    /// 95th percentile (nearest rank).
    pub p95_ms: f64,
    /// 99th percentile (nearest rank).
    pub p99_ms: f64,
    /// Maximum.
    pub max_ms: f64,
}

impl Summary {
    /// `p50 / p95 / p99 / max` in ms, or `-` for an empty sample.
    #[must_use]
    pub fn short(&self) -> String {
        if self.count == 0 {
            return "-".into();
        }
        format!("{:.1} / {:.1} / {:.1} / {:.1}", self.p50_ms, self.p95_ms, self.p99_ms, self.max_ms)
    }
}

/// Nearest-rank percentile of an ascending-sorted sample (`q` in 0..=100); `None` when empty.
#[must_use]
pub fn percentile_sorted(sorted: &[u32], q: f64) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((q / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted.get(rank.min(sorted.len()) - 1).copied()
}

/// Summarise microsecond samples (sorts in place).
#[must_use]
pub fn summarize_us(samples: &mut [u32]) -> Summary {
    if samples.is_empty() {
        return Summary::default();
    }
    samples.sort_unstable();
    let ms = |us: u32| f64::from(us) / 1000.0;
    let pct = |q: f64| percentile_sorted(samples, q).map_or(0.0, ms);
    let sum: u64 = samples.iter().map(|&v| u64::from(v)).sum();
    Summary {
        count: samples.len() as u64,
        min_ms: ms(samples[0]),
        mean_ms: sum as f64 / samples.len() as f64 / 1000.0,
        p50_ms: pct(50.0),
        p95_ms: pct(95.0),
        p99_ms: pct(99.0),
        max_ms: ms(samples[samples.len() - 1]),
    }
}

#[derive(Default)]
struct RecorderInner {
    all: Vec<u32>,
    window: Vec<u32>,
}

/// Thread-safe latency recorder keeping every sample (microseconds, saturating at ~71 min) for
/// the whole run plus the samples since the last [`Recorder::take_window`].
#[derive(Default)]
pub struct Recorder {
    inner: Mutex<RecorderInner>,
}

impl Recorder {
    /// Empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RecorderInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record one duration.
    pub fn record(&self, d: Duration) {
        let us = u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
        let mut g = self.lock();
        g.all.push(us);
        g.window.push(us);
    }

    /// Summary of the samples since the previous call; starts a new window.
    pub fn take_window(&self) -> Summary {
        let mut w = std::mem::take(&mut self.lock().window);
        summarize_us(&mut w)
    }

    /// Summary of every sample so far.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let mut all = self.lock().all.clone();
        summarize_us(&mut all)
    }

    /// Samples so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.lock().all.len() as u64
    }
}

/// Events per second over `seconds` (0 for an empty interval).
#[must_use]
pub fn rate(delta: u64, seconds: f64) -> f64 {
    if seconds > 0.0 {
        delta as f64 / seconds
    } else {
        0.0
    }
}

/// Start offsets (ms from the beginning of the ramp) of `n` devices: `rate` starts per second,
/// pausing `hold_ms` after each stage boundary (`stages_pct`, cumulative percentages of `n`,
/// ascending; the last stage is always 100 %). The pause after the final stage is not included.
#[must_use]
pub fn ramp_schedule(n: usize, rate_per_s: f64, stages_pct: &[u32], hold_ms: u64) -> Vec<u64> {
    let rate = if rate_per_s > 0.0 { rate_per_s } else { 1.0 };
    let mut bounds: Vec<usize> = stages_pct.iter().map(|p| (n as u64 * u64::from((*p).min(100)) / 100) as usize).collect();
    bounds.retain(|b| *b > 0 && *b < n);
    bounds.sort_unstable();
    bounds.dedup();
    (0..n)
        .map(|i| {
            let holds = bounds.iter().filter(|b| **b <= i).count() as u64 * hold_ms;
            (i as f64 * 1000.0 / rate).round() as u64 + holds
        })
        .collect()
}

/// One sample line of the Prometheus text format: `(series with labels, value)`.
#[must_use]
pub fn prometheus_samples(text: &str) -> BTreeMap<String, f64> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (series, value) = l.rsplit_once(' ')?;
            Some((series.trim().to_owned(), value.trim().parse::<f64>().ok()?))
        })
        .collect()
}

/// A series whose value changed between two scrapes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SeriesDelta {
    /// Series (name + labels).
    pub series: String,
    /// Value before.
    pub before: f64,
    /// Value after.
    pub after: f64,
    /// `after - before`.
    pub delta: f64,
}

/// Every series whose name starts with one of `prefixes` and that is present after the run,
/// with its delta (a series absent before counts from 0).
#[must_use]
pub fn prometheus_deltas(before: &str, after: &str, prefixes: &[&str]) -> Vec<SeriesDelta> {
    let b = prometheus_samples(before);
    prometheus_samples(after)
        .into_iter()
        .filter(|(s, _)| prefixes.iter().any(|p| s.starts_with(p)))
        .map(|(series, after)| {
            let before = b.get(&series).copied().unwrap_or(0.0);
            SeriesDelta { series, before, after, delta: after - before }
        })
        .collect()
}

/// Sum of the deltas of every series of metric `name` whose labels contain `label_filter`.
#[must_use]
pub fn delta_sum(deltas: &[SeriesDelta], name: &str, label_filter: &str) -> f64 {
    deltas
        .iter()
        .filter(|d| {
            let (metric, labels) = match d.series.find('{') {
                Some(i) => (&d.series[..i], &d.series[i..]),
                None => (d.series.as_str(), ""),
            };
            metric == name && labels.contains(label_filter)
        })
        .map(|d| d.delta)
        .sum::<f64>()
        + 0.0 // normalise the -0.0 of an empty f64 sum
}

/// Mean and maximum of a series of samples (`(0, 0)` when empty).
#[must_use]
pub fn mean_max(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let sum: f64 = values.iter().sum();
    (sum / values.len() as f64, values.iter().copied().fold(f64::MIN, f64::max))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles() {
        let v: Vec<u32> = (1..=100).collect();
        assert_eq!(percentile_sorted(&v, 50.0), Some(50));
        assert_eq!(percentile_sorted(&v, 95.0), Some(95));
        assert_eq!(percentile_sorted(&v, 99.0), Some(99));
        assert_eq!(percentile_sorted(&v, 100.0), Some(100));
        assert_eq!(percentile_sorted(&v, 0.0), Some(1));
        assert_eq!(percentile_sorted(&[], 50.0), None);
        assert_eq!(percentile_sorted(&[7], 99.0), Some(7));
        // 20 samples: p95 is the 19th value, p99 the 20th.
        let w: Vec<u32> = (1..=20).collect();
        assert_eq!(percentile_sorted(&w, 95.0), Some(19));
        assert_eq!(percentile_sorted(&w, 99.0), Some(20));
    }

    #[test]
    fn summary_of_unsorted_microseconds() {
        let mut v = vec![3000, 1000, 2000, 10_000, 4000];
        let s = summarize_us(&mut v);
        assert_eq!(s.count, 5);
        assert!((s.min_ms - 1.0).abs() < 1e-9);
        assert!((s.max_ms - 10.0).abs() < 1e-9);
        assert!((s.p50_ms - 3.0).abs() < 1e-9);
        assert!((s.p99_ms - 10.0).abs() < 1e-9);
        assert!((s.mean_ms - 4.0).abs() < 1e-9);
        assert_eq!(summarize_us(&mut []), Summary::default());
        assert_eq!(Summary::default().short(), "-");
        assert_eq!(s.short(), "3.0 / 10.0 / 10.0 / 10.0");
    }

    #[test]
    fn recorder_windows_and_totals() {
        let r = Recorder::new();
        for ms in [5u64, 1, 3] {
            r.record(Duration::from_millis(ms));
        }
        let w = r.take_window();
        assert_eq!(w.count, 3);
        assert!((w.p50_ms - 3.0).abs() < 1e-9);
        assert_eq!(r.take_window().count, 0, "window was reset");
        r.record(Duration::from_millis(100));
        assert_eq!(r.take_window().count, 1);
        let all = r.summary();
        assert_eq!(all.count, 4);
        assert!((all.max_ms - 100.0).abs() < 1e-9);
        assert_eq!(r.count(), 4);
        // Saturation instead of wrap-around.
        r.record(Duration::from_secs(10_000));
        assert_eq!(r.summary().max_ms, f64::from(u32::MAX) / 1000.0);
    }

    #[test]
    fn rates() {
        assert!((rate(500, 5.0) - 100.0).abs() < 1e-9);
        assert_eq!(rate(5, 0.0), 0.0);
        assert_eq!(mean_max(&[]), (0.0, 0.0));
        assert_eq!(mean_max(&[1.0, 3.0, 2.0]), (2.0, 3.0));
    }

    #[test]
    fn ramp_schedule_rate_and_holds() {
        // 10 devices at 2/s, stages at 50 % and 100 %, 1 s hold after the 50 % stage.
        let s = ramp_schedule(10, 2.0, &[50, 100], 1000);
        assert_eq!(s.len(), 10);
        assert_eq!(&s[..5], &[0, 500, 1000, 1500, 2000]);
        assert_eq!(&s[5..], &[3500, 4000, 4500, 5000, 5500]);
        // No stages: a straight line.
        assert_eq!(ramp_schedule(3, 10.0, &[], 5000), vec![0, 100, 200]);
        // Monotonic for the default staging.
        let d = ramp_schedule(10_000, 200.0, &[25, 50, 75, 100], 15_000);
        assert!(d.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(d[9_999], 49_995 + 3 * 15_000);
        assert!(ramp_schedule(0, 200.0, &[50], 10).is_empty());
    }

    #[test]
    fn prometheus_text_deltas() {
        let before = "# HELP x\nironmesh_authz_decisions_total{action=\"publish\",result=\"allow\"} 10\nprocess_cpu_seconds_total 1.5\n";
        let after = "ironmesh_authz_decisions_total{action=\"publish\",result=\"allow\"} 110\n\
                     ironmesh_authz_decisions_total{action=\"publish\",result=\"deny\"} 2\n\
                     process_cpu_seconds_total 4\ngo_goroutines 12\n";
        let d = prometheus_deltas(before, after, &["ironmesh_", "process_cpu"]);
        assert_eq!(d.len(), 3);
        assert_eq!(delta_sum(&d, "ironmesh_authz_decisions_total", "result=\"allow\""), 100.0);
        assert_eq!(delta_sum(&d, "ironmesh_authz_decisions_total", ""), 102.0);
        assert_eq!(delta_sum(&d, "process_cpu_seconds_total", ""), 2.5);
        assert_eq!(delta_sum(&d, "go_goroutines", ""), 0.0, "filtered by prefix");
        assert!(delta_sum(&d, "missing", "").is_sign_positive(), "no -0.0 in reports");
        assert_eq!(prometheus_samples("a 1\nb{x=\"y z\"} 2\nbad\n").len(), 2);
    }
}
