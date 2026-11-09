//! Time source.

use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current time. [`OAuthClient`](crate::OAuthClient) uses it
/// for the lifetime of a login attempt and the expiry of `id_token`s; swap it
/// with [`OAuthClient::with_clock`](crate::OAuthClient::with_clock) in tests.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// The operating system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        now()
    }
}

impl<F: Fn() -> u64 + Send + Sync> Clock for F {
    fn now(&self) -> u64 {
        self()
    }
}

/// Seconds since the Unix epoch, from the system clock.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
