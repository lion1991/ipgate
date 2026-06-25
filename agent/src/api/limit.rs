//! 朴素 per-IP 限流（固定窗口计数）。无第三方依赖，够挡探测/刷量/暴力。
//!
//! 合法客户端只是偶尔轮询，配额给得很宽；超额的基本只有扫描器/爆破。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 固定窗口限流器：每个源 IP 在 `window` 内最多 `max` 次。
pub struct RateLimiter {
    max: u32,
    window: Duration,
    inner: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max: max_per_window,
            window,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// `true` = 放行；`false` = 超限。`max == 0` 表示不限流。
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        if self.max == 0 {
            return true;
        }
        let mut m = self.inner.lock().unwrap();
        // 内存兜底：表过大时顺手清掉过期窗口（避免被海量伪造源 IP 撑爆）。
        if m.len() > 10_000 {
            m.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let e = m.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= self.window {
            *e = (now, 0); // 窗口翻篇，计数清零
        }
        e.1 += 1;
        e.1 <= self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_blocks() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.allow(ip, t0));
        assert!(rl.allow(ip, t0));
        assert!(rl.allow(ip, t0));
        assert!(!rl.allow(ip, t0), "第 4 次应超限");
    }

    #[test]
    fn window_resets() {
        let rl = RateLimiter::new(1, Duration::from_secs(10));
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.allow(ip, t0));
        assert!(!rl.allow(ip, t0));
        let later = t0 + Duration::from_secs(11);
        assert!(rl.allow(ip, later), "新窗口应放行");
    }

    #[test]
    fn zero_means_unlimited() {
        let rl = RateLimiter::new(0, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert!(rl.allow(ip, t0));
        }
    }

    #[test]
    fn per_ip_isolated() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let a: IpAddr = "203.0.113.8".parse().unwrap();
        let b: IpAddr = "203.0.113.9".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.allow(a, t0));
        assert!(rl.allow(b, t0), "另一个 IP 不受影响");
        assert!(!rl.allow(a, t0));
    }
}
