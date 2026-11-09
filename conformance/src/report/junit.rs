//! JUnit XML (the Jenkins/GitLab/GitHub flavour: `testsuites > testsuite > testcase` with
//! `failure`, `error`, `skipped` and `system-out`).

use std::fmt::Write as _;

use super::RunReport;
use crate::util::xml_escape as x;

fn family(id: &str) -> String {
    id.split('-').nth(1).unwrap_or("misc").to_ascii_lowercase()
}

/// Render the report.
#[must_use]
pub fn render(r: &RunReport) -> String {
    let (passed, failed, na, errors) = r.counts();
    let total = passed + failed + na + errors;
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        s,
        "<testsuites name=\"ironmesh-conformance\" tests=\"{total}\" failures=\"{failed}\" errors=\"{errors}\" skipped=\"{na}\" time=\"{:.3}\">",
        r.seconds
    );
    let _ = writeln!(
        s,
        "  <testsuite name=\"ironmesh-conformance.{}\" tests=\"{total}\" failures=\"{failed}\" errors=\"{errors}\" skipped=\"{na}\" time=\"{:.3}\" timestamp=\"{}\" hostname=\"{}\">",
        x(&r.target),
        r.seconds,
        x(&r.started_at),
        x(&r.host)
    );
    s.push_str("    <properties>\n");
    for (k, v) in [("target", r.target.as_str()), ("mode", r.mode.as_str()), ("git_commit", r.git_commit.as_str())]
        .into_iter()
        .chain(r.environment.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    {
        let _ = writeln!(s, "      <property name=\"{}\" value=\"{}\"/>", x(k), x(v));
    }
    s.push_str("    </properties>\n");
    for c in &r.results {
        let _ = writeln!(
            s,
            "    <testcase classname=\"conformance.{}.{}\" name=\"{} {}\" time=\"{:.3}\">",
            x(&r.target),
            family(&c.id),
            x(&c.id),
            x(&c.title),
            c.seconds
        );
        match c.verdict.as_str() {
            "failed" => {
                let _ =
                    writeln!(s, "      <failure type=\"conformance\" message=\"{}\">{}</failure>", x(&first_line(&c.reason)), x(&c.reason));
            }
            "error" => {
                let _ = writeln!(s, "      <error type=\"harness\" message=\"{}\">{}</error>", x(&first_line(&c.reason)), x(&c.reason));
            }
            "not_applicable" => {
                let _ = writeln!(s, "      <skipped message=\"not applicable: {}\"/>", x(&c.reason));
            }
            _ => {}
        }
        let mut out = format!("criterion: {}\n", c.criterion);
        for (k, v) in &c.measurements {
            let _ = writeln!(out, "measure {k} = {v}");
        }
        for e in &c.evidence {
            let _ = writeln!(out, "evidence: {e}");
        }
        for w in &c.warnings {
            let _ = writeln!(out, "warning: {w}");
        }
        let _ = writeln!(s, "      <system-out>{}</system-out>", x(&out));
        s.push_str("    </testcase>\n");
    }
    s.push_str("  </testsuite>\n</testsuites>\n");
    s
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::StoredResult;

    #[test]
    fn junit_structure_and_escaping() {
        let mk = |id: &str, verdict: &str, reason: &str| StoredResult {
            id: id.into(),
            title: "t <&>".into(),
            criterion: "c".into(),
            verdict: verdict.into(),
            reason: reason.into(),
            measurements: vec![("m".into(), "1".into())],
            evidence: vec!["e \"q\"".into()],
            warnings: vec![],
            seconds: 1.5,
            series: vec![],
        };
        let r = RunReport {
            target: "agent-rs".into(),
            mode: "hermetic".into(),
            started_at: "2026-01-01T00:00:00Z".into(),
            seconds: 4.5,
            git_commit: "abc".into(),
            host: "h".into(),
            environment: vec![("k".into(), "v&".into())],
            results: vec![
                mk("C-TLS-1", "passed", ""),
                mk("C-OTA-2", "failed", "bad <hash>"),
                mk("C-HOOK-1", "not_applicable", "esp32"),
                mk("C-X-1", "error", "boom"),
            ],
        };
        let xml = render(&r);
        assert!(xml.contains("tests=\"4\" failures=\"1\" errors=\"1\" skipped=\"1\""));
        assert!(xml.contains("<failure type=\"conformance\" message=\"bad &lt;hash&gt;\">"));
        assert!(xml.contains("<skipped message=\"not applicable: esp32\"/>"));
        assert!(xml.contains("classname=\"conformance.agent-rs.ota\""));
        assert!(xml.contains("name=\"C-TLS-1 t &lt;&amp;&gt;\""));
        assert!(xml.contains("value=\"v&amp;\""));
        assert_eq!(xml.matches("<testcase ").count(), 4);
        assert_eq!(xml.matches("</testcase>").count(), 4);
    }
}
