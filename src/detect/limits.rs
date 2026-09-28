use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONNECT_SPACING: Duration = Duration::from_millis(500);
const JITTER_MIN_MS: u64 = 250;
const JITTER_MAX_MS: u64 = 750;

pub(crate) struct RateLimiter {
    next_slot: Mutex<Instant>,
    spacing: Duration,
}

impl RateLimiter {
    pub(crate) fn new() -> Self {
        Self::with_spacing(CONNECT_SPACING)
    }

    fn with_spacing(spacing: Duration) -> Self {
        Self {
            next_slot: Mutex::new(Instant::now()),
            spacing,
        }
    }

    pub(crate) fn acquire(&self) {
        let wait = {
            let mut next = self.next_slot.lock().unwrap();
            let now = Instant::now();
            let start = (*next).max(now);
            *next = start + self.spacing;
            start - now
        };
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }
}

pub(crate) struct Limits {
    pub(crate) limiter: RateLimiter,
    pub(crate) host_locks: HostLocks,
}

pub(crate) struct HostLocks {
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl HostLocks {
    pub(crate) fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn with_host<R>(&self, host: &str, probe: impl FnOnce() -> R) -> R {
        let entry = self
            .locks
            .lock()
            .unwrap()
            .entry(host.to_string())
            .or_default()
            .clone();
        let _guard = entry.lock().unwrap();
        probe()
    }
}

thread_local! {
    static RNG: Cell<u64> = const { Cell::new(0) };
}

pub(crate) fn jitter_sleep() {
    RNG.with(|cell| {
        let mut state = cell.get();
        if state == 0 {
            state = seed();
        }
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        cell.set(state);
        let span = JITTER_MAX_MS - JITTER_MIN_MS + 1;
        let ms = JITTER_MIN_MS + state % span;
        std::thread::sleep(Duration::from_millis(ms));
    });
}

fn seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    nanos | 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn acquire_calls_are_spaced_apart() {
        let spacing = Duration::from_millis(60);
        let limiter = RateLimiter::with_spacing(spacing);

        let start = Instant::now();
        for _ in 0..4 {
            limiter.acquire();
        }
        let elapsed = start.elapsed();

        assert!(elapsed >= spacing * 3 - Duration::from_millis(5));
        assert!(elapsed < Duration::from_secs(5));
    }
    #[test]
    fn host_locks_serialize_the_same_host() {
        let locks = Arc::new(HostLocks::new());
        let inside = Arc::new(AtomicUsize::new(0));
        let max_inside = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for _ in 0..2 {
                let locks = &locks;
                let inside = &inside;
                let max_inside = &max_inside;
                scope.spawn(move || {
                    locks.with_host("mx.example.com", || {
                        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        max_inside.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(50));
                        inside.fetch_sub(1, Ordering::SeqCst);
                    });
                });
            }
        });

        assert_eq!(max_inside.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn host_locks_do_not_cross_hosts() {
        let locks = Arc::new(HostLocks::new());
        let (sender, receiver) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            {
                let locks = &locks;
                scope.spawn(move || {
                    locks.with_host("mx1.example.com", || {
                        std::thread::sleep(Duration::from_millis(400));
                    });
                });
            }
            std::thread::sleep(Duration::from_millis(100));
            {
                let locks = &locks;
                scope.spawn(move || {
                    locks.with_host("mx2.example.com", || {
                        sender.send(()).expect("send signal");
                    });
                });
            }
        });

        assert!(receiver.recv_timeout(Duration::from_millis(250)).is_ok());
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..5 {
            let start = Instant::now();
            jitter_sleep();
            let elapsed = start.elapsed();
            assert!(elapsed >= Duration::from_millis(JITTER_MIN_MS));
            assert!(elapsed <= Duration::from_millis(JITTER_MAX_MS + 250));
        }
    }
}
