//! Certificate renewal schedule (contract §2): renew at `notBefore + 50 % lifetime` plus a random
//! jitter of up to 10 % of the lifetime; on failure retry with exponential backoff (base 60 s,
//! cap 6 h, full jitter) until expiry; after expiry fall back to bootstrap enrollment.

use std::time::Duration;

use crate::mqtt::Backoff;

/// What the renewal scheduler should do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalAction {
    /// Nothing to do until this unix time.
    WaitUntil(u64),
    /// Run `simplereenroll` now.
    Renew,
    /// The certificate expired: enroll again with the bootstrap identity.
    Bootstrap,
}

/// Renewal time for a certificate; `jitter` in `[0, 1]` scales the up-to-10 % jitter.
#[must_use]
pub fn renewal_time(not_before: u64, not_after: u64, jitter: f64) -> u64 {
    let lifetime = not_after.saturating_sub(not_before);
    let jitter = jitter.clamp(0.0, 1.0);
    let jitter_s = ((lifetime as f64) * 0.10 * jitter) as u64;
    not_before.saturating_add(lifetime / 2).saturating_add(jitter_s)
}

/// Decide based on the current time and the (jittered) renewal time.
#[must_use]
pub fn decide(now: u64, renew_at: u64, not_after: u64) -> RenewalAction {
    if now >= not_after {
        RenewalAction::Bootstrap
    } else if now >= renew_at {
        RenewalAction::Renew
    } else {
        RenewalAction::WaitUntil(renew_at)
    }
}

/// Retry backoff for failed renewals (base 60 s, factor 2, cap 6 h, full jitter).
#[must_use]
pub fn retry_backoff() -> Backoff {
    Backoff::new(Duration::from_secs(60), 2, Duration::from_secs(6 * 3600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule() {
        let nb = 1_000;
        let na = nb + 14 * 86_400;
        assert_eq!(renewal_time(nb, na, 0.0), nb + 7 * 86_400);
        let max = renewal_time(nb, na, 1.0);
        assert_eq!(max, nb + 7 * 86_400 + 120_960);
        assert_eq!(renewal_time(nb, na, 7.0), max);
        assert_eq!(decide(nb, max, na), RenewalAction::WaitUntil(max));
        assert_eq!(decide(max, max, na), RenewalAction::Renew);
        assert_eq!(decide(na, max, na), RenewalAction::Bootstrap);
        let b = retry_backoff();
        assert_eq!(b.ceiling(), Duration::from_secs(60));
        let mut b = retry_backoff();
        for _ in 0..20 {
            b.next_delay();
        }
        assert_eq!(b.ceiling(), Duration::from_secs(6 * 3600));
    }
}
