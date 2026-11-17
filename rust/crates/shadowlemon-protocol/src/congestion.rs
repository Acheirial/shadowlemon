//! CUBIC congestion control (RFC 8312) and RTT estimation (RFC 6298).
//!
//! The constants and the order of operations mirror the Go implementation
//! (`pkg/congestion/cubic.go` and `rtt.go`). `cwnd` is measured in segments;
//! the default bounds are `MIN_CWND = 16` and `MAX_CWND = 4096`.
//!
//! RTT estimation lives in [`RttStats`], separate from [`Cubic`], so the caller
//! can feed the smoothed RTT into `Cubic::on_ack` exactly like the Go session
//! layer does. [`retransmission_timeout`] implements the session-layer
//! `min(RTO * 1.5^tx_count, 10s)` backoff.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

/// Default (minimum) congestion window, in segments.
pub const MIN_CWND: u32 = 16;
/// Maximum congestion window, in segments.
pub const MAX_CWND: u32 = 4096;

/// `beta_cubic`, the multiplicative decrease factor (RFC 8312 §4.5).
pub const CUBIC_BETA: f64 = 0.7;
/// `C`, the scaling factor of the CUBIC growth function (RFC 8312 §4.1).
pub const CUBIC_C: f64 = 0.4;
/// AIMD alpha of the TCP-friendly flow that `W_est` emulates:
/// `3 * (1 - beta) / (1 + beta)`.
pub const CUBIC_AIMD_ALPHA: f64 = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);
/// Divisor applied to `cwnd` to obtain `ssthresh` after a timeout.
pub const TIMEOUT_SSTHRESH_DIVISOR: u32 = 2;
/// RTT estimator smoothing factor (`alpha` of RFC 6298).
pub const RTT_ALPHA: f64 = 0.125;
/// RTT deviation smoothing factor (`beta` of RFC 6298).
pub const RTT_BETA: f64 = 0.25;
/// RTT estimate used when no measurement is available yet.
pub const DEFAULT_INITIAL_RTT: Duration = Duration::from_secs(1);
/// Lower bound of the computed retransmission timeout.
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// Maximum ACK delay added to the RTO (session's `packet_ack_delay`).
pub const MAX_ACK_DELAY: Duration = Duration::from_millis(1);
/// Session-level RTO multiplier (left at 1.0 so backoff is not applied twice).
pub const RTO_MULTIPLIER: f64 = 1.0;
/// Multiplier applied per retransmission (`txTimeout = RTO * 1.5^txCount`).
pub const TX_TIMEOUT_BACKOFF: f64 = 1.5;
/// Upper bound of the retransmission timeout after backoff.
pub const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(10);

/// retransmission timeout after `tx_count` retransmissions, capped at 10s.
///
/// The exponent is clamped so a large `tx_count` cannot overflow the
/// floating-point multiplication.
#[must_use]
pub fn retransmission_timeout(rto: Duration, tx_count: u32) -> Duration {
    let exponent = tx_count.min(64);
    let scaled = rto.mul_f64(TX_TIMEOUT_BACKOFF.powi(exponent as i32));
    scaled.min(MAX_BACKOFF_DURATION)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CubicMode {
    SlowStart,
    Normal,
}

#[derive(Debug)]
struct CubicState {
    mode: CubicMode,
    min_window: u32,
    max_window: u32,
    cwnd: u32,
    ssthresh: u32,
    /// `W_max` of RFC 8312: window just before the last reduction.
    w_max: u32,
    /// `K` of RFC 8312 Eq. 2, constant for one congestion avoidance epoch.
    epoch_k: f64,
    /// Start of the current congestion avoidance epoch.
    epoch_start: Option<Instant>,
    /// Most recent positive RTT passed to `on_ack`.
    last_rtt: Duration,
}

/// CUBIC sender window, safe to share behind an `Arc`.
///
/// All state is behind a mutex, so `on_ack`, `on_loss` and `cwnd` take `&self`.
/// `now` is supplied by the caller, which keeps tests deterministic.
#[derive(Debug)]
pub struct Cubic {
    state: Mutex<CubicState>,
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new(MIN_CWND, MAX_CWND)
    }
}

impl Cubic {
    /// Create a CUBIC instance with explicit window bounds (in segments).
    ///
    /// # Panics
    /// Panics when `min_window > max_window`.
    #[must_use]
    pub fn new(min_window: u32, max_window: u32) -> Self {
        assert!(
            min_window <= max_window,
            "minimum congestion window is greater than maximum congestion window"
        );
        Self {
            state: Mutex::new(CubicState {
                mode: CubicMode::SlowStart,
                min_window,
                max_window,
                cwnd: min_window,
                ssthresh: max_window,
                w_max: 0,
                epoch_k: 0.0,
                epoch_start: None,
                last_rtt: Duration::ZERO,
            }),
        }
    }

    /// Current congestion window, in segments.
    #[must_use]
    pub fn cwnd(&self) -> u32 {
        self.lock().cwnd
    }

    /// Whether the algorithm is still in slow start.
    #[must_use]
    pub fn in_slow_start(&self) -> bool {
        self.lock().mode == CubicMode::SlowStart
    }

    /// Most recent positive RTT supplied by the caller.
    #[must_use]
    pub fn last_rtt(&self) -> Duration {
        self.lock().last_rtt
    }

    /// Update the window from an acknowledgement.
    ///
    /// `bytes_acked` is the number of segments acknowledged by this ACK and is
    /// at least one; passing `1` reproduces the Go implementation exactly.
    /// A non-positive `rtt` reuses the last RTT, falling back to one second.
    pub fn on_ack(&self, bytes_acked: u32, rtt: Duration, now: Instant) -> u32 {
        let mut state = self.lock();
        let mut rtt = rtt;
        if rtt.is_zero() {
            rtt = state.last_rtt;
        }
        if rtt.is_zero() {
            rtt = DEFAULT_INITIAL_RTT;
        }
        state.last_rtt = rtt;

        if state.mode == CubicMode::SlowStart {
            let (min, max) = (state.min_window, state.max_window);
            state.cwnd = state.cwnd.saturating_add(bytes_acked.max(1));
            clamp(&mut state.cwnd, min, max);
            if state.cwnd > state.ssthresh {
                let crossed = state.cwnd;
                state.mode = CubicMode::Normal;
                start_epoch(&mut state, crossed, 0.0, now);
            }
            return state.cwnd;
        }

        let t = epoch_seconds(&state, now);
        let (min, max) = (state.min_window, state.max_window);
        let w = w_cubic(&state, t)
            .max(w_est(&state, t, rtt))
            .max(0.0)
            .min(max as f64);
        state.cwnd = w.round() as u32;
        clamp(&mut state.cwnd, min, max);
        state.cwnd
    }

    /// React to a loss (duplicate ACK / early retransmission): reduce the
    /// window by `beta_cubic` and start a new CUBIC epoch.
    pub fn on_loss(&self, now: Instant) -> u32 {
        let mut state = self.lock();
        let (min, max) = (state.min_window, state.max_window);
        let w_max = state.cwnd;
        let reduced = ((w_max as f64) * CUBIC_BETA).round() as u32;
        state.ssthresh = reduced.max(min);
        state.cwnd = state.ssthresh;
        state.mode = CubicMode::Normal;
        let k = ((w_max as f64) * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        start_epoch(&mut state, w_max, k, now);
        clamp(&mut state.cwnd, min, max);
        state.cwnd
    }

    /// React to a retransmission timeout: halve `ssthresh` and restart slow
    /// start from the minimum window.
    pub fn on_timeout(&self) -> u32 {
        let mut state = self.lock();
        let min = state.min_window;
        state.ssthresh = (state.cwnd / TIMEOUT_SSTHRESH_DIVISOR).max(min);
        state.cwnd = min;
        state.mode = CubicMode::SlowStart;
        state.w_max = 0;
        state.epoch_k = 0.0;
        state.epoch_start = None;
        state.cwnd
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CubicState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn clamp(cwnd: &mut u32, min: u32, max: u32) {
    if *cwnd < min {
        *cwnd = min;
    } else if *cwnd > max {
        *cwnd = max;
    }
}

fn start_epoch(state: &mut CubicState, w_max: u32, k: f64, now: Instant) {
    state.w_max = w_max;
    state.epoch_k = k;
    state.epoch_start = Some(now);
}

fn epoch_seconds(state: &CubicState, now: Instant) -> f64 {
    match state.epoch_start {
        Some(start) => now.saturating_duration_since(start).as_secs_f64(),
        None => 0.0,
    }
}

fn w_cubic(state: &CubicState, t: f64) -> f64 {
    let d = t - state.epoch_k;
    CUBIC_C * d * d * d + state.w_max as f64
}

fn w_est(state: &CubicState, t: f64, rtt: Duration) -> f64 {
    let rtt_secs = rtt.as_secs_f64().max(f64::EPSILON);
    (state.w_max as f64) * CUBIC_BETA + CUBIC_AIMD_ALPHA * (t / rtt_secs)
}

/// Smoothed RTT, mean deviation and retransmission timeout of RFC 6298 §2.
///
/// Like the Go `RTTStats`, the first valid sample seeds the estimators
/// (`srtt = sample`, `rttvar = sample / 2`); later samples use the 1/8 and 1/4
/// weights with microsecond-resolution arithmetic.
#[derive(Debug)]
pub struct RttStats {
    state: Mutex<RttState>,
}

#[derive(Debug)]
struct RttState {
    has_measurement: bool,
    latest_rtt: Duration,
    smoothed_rtt: Duration,
    mean_deviation: Duration,
    max_ack_delay: Duration,
    rto_multiplier: f64,
}

impl Default for RttStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RttStats {
    /// Create an estimator with no measurement and an RTO multiplier of 1.0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RttState {
                has_measurement: false,
                latest_rtt: Duration::ZERO,
                smoothed_rtt: Duration::ZERO,
                mean_deviation: Duration::ZERO,
                max_ack_delay: MAX_ACK_DELAY,
                rto_multiplier: RTO_MULTIPLIER,
            }),
        }
    }

    /// Most recent valid RTT sample, or zero before the first one.
    #[must_use]
    pub fn latest_rtt(&self) -> Duration {
        self.lock().latest_rtt
    }

    /// Smoothed RTT (SRTT), or zero before the first sample.
    #[must_use]
    pub fn smoothed_rtt(&self) -> Duration {
        self.lock().smoothed_rtt
    }

    /// Mean RTT deviation (RTTVAR).
    #[must_use]
    pub fn rttvar(&self) -> Duration {
        self.lock().mean_deviation
    }

    /// Whether at least one valid sample has been recorded.
    #[must_use]
    pub fn has_measurement(&self) -> bool {
        self.lock().has_measurement
    }

    /// Retransmission timeout: `SRTT + max(4*RTTVAR, 10ms) + max_ack_delay`,
    /// multiplied by the RTO multiplier and floored at 200ms. With no sample
    /// the conservative `2 * DEFAULT_INITIAL_RTT` (2s) is returned.
    #[must_use]
    pub fn rto(&self) -> Duration {
        let state = self.lock();
        if state.smoothed_rtt.is_zero() {
            return DEFAULT_INITIAL_RTT * 2;
        }
        let deviation = (state.mean_deviation * 4).max(Duration::from_millis(10));
        let rto = state.smoothed_rtt + deviation + state.max_ack_delay;
        rto.mul_f64(state.rto_multiplier).max(MIN_RTO)
    }

    /// Record an RTT sample. Zero and `Duration::MAX` samples are ignored.
    pub fn update_rtt(&self, sample: Duration) {
        let mut state = self.lock();
        if sample.is_zero() || sample == Duration::MAX {
            return;
        }
        state.latest_rtt = sample;
        if !state.has_measurement {
            state.has_measurement = true;
            state.smoothed_rtt = sample;
            state.mean_deviation = sample / 2;
            return;
        }
        // The Go code converts to float32 microseconds before each operation.
        let srtt_us = state.smoothed_rtt.as_micros() as f32;
        let deviation_us = state.mean_deviation.as_micros() as f32;
        let sample_us = sample.as_micros() as f32;
        let diff_us = (srtt_us - sample_us).abs();
        state.mean_deviation =
            micros((1.0 - RTT_BETA) as f32 * deviation_us + RTT_BETA as f32 * diff_us);
        state.smoothed_rtt =
            micros(srtt_us * (1.0 - RTT_ALPHA) as f32 + sample_us * RTT_ALPHA as f32);
    }

    /// Replace the maximum ACK delay added to the RTO.
    pub fn set_max_ack_delay(&self, delay: Duration) {
        self.lock().max_ack_delay = delay;
    }

    /// Replace the RTO multiplier. Returns `false` for a non-positive value.
    pub fn set_rto_multiplier(&self, multiplier: f64) -> bool {
        if !multiplier.is_finite() || multiplier <= 0.0 {
            return false;
        }
        self.lock().rto_multiplier = multiplier;
        true
    }

    /// Seed the estimator before the first sample. Returns `false` once a
    /// measurement has been recorded.
    pub fn set_initial_rtt(&self, rtt: Duration) -> bool {
        let mut state = self.lock();
        if state.has_measurement {
            return false;
        }
        state.smoothed_rtt = rtt;
        state.latest_rtt = rtt;
        true
    }

    /// Clear all estimates while preserving `max_ack_delay` and multiplier.
    pub fn reset(&self) {
        let mut state = self.lock();
        state.has_measurement = false;
        state.latest_rtt = Duration::ZERO;
        state.smoothed_rtt = Duration::ZERO;
        state.mean_deviation = Duration::ZERO;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RttState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn micros(value: f32) -> Duration {
    if !value.is_finite() || value <= 0.0 {
        Duration::ZERO
    } else {
        Duration::from_micros(value as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwnd_growth_curve_and_epoch_transition() {
        let cubic = Cubic::default();
        let t0 = Instant::now();
        assert_eq!(cubic.cwnd(), MIN_CWND);
        assert!(cubic.in_slow_start());

        // Slow start adds one segment per acknowledged segment. ssthresh
        // initially equals max_window, so the flow stays in slow start until a
        // loss or timeout lowers the threshold.
        for i in 1..=100 {
            assert_eq!(cubic.on_ack(1, Duration::from_millis(50), t0), MIN_CWND + i);
            assert!(cubic.in_slow_start());
        }

        // A loss lowers ssthresh and switches to congestion avoidance.
        assert_eq!(cubic.on_loss(t0), 81);
        assert!(!cubic.in_slow_start());

        // In congestion avoidance the window tracks max(W_cubic, W_est).
        let later = t0 + Duration::from_secs(1);
        let cwnd = cubic.on_ack(1, Duration::from_millis(50), later);
        assert!((81..=MAX_CWND).contains(&cwnd));
        assert_eq!(cwnd, cubic.cwnd());
    }

    #[test]
    fn slow_start_crosses_threshold_after_timeout() {
        let cubic = Cubic::default();
        let t0 = Instant::now();
        for _ in 0..100 {
            cubic.on_ack(1, Duration::from_millis(20), t0);
        }
        // cwnd = 116, timeout sets ssthresh = 58 and cwnd = 16.
        assert_eq!(cubic.on_timeout(), MIN_CWND);
        for i in 1..=42 {
            assert_eq!(cubic.on_ack(1, Duration::from_millis(20), t0), MIN_CWND + i);
        }
        assert!(cubic.in_slow_start());
        assert_eq!(cubic.on_ack(1, Duration::from_millis(20), t0), 59);
        assert!(!cubic.in_slow_start());
    }

    #[test]
    fn loss_halves_window_and_timeout_restarts_slow_start() {
        let cubic = Cubic::default();
        let t0 = Instant::now();
        for _ in 0..100 {
            cubic.on_ack(1, Duration::from_millis(20), t0);
        }
        let before = cubic.cwnd();
        assert_eq!(before, MIN_CWND + 100);
        let after_loss = cubic.on_loss(t0 + Duration::from_secs(1));
        assert_eq!(
            after_loss,
            ((before as f64 * CUBIC_BETA).round() as u32).max(MIN_CWND)
        );
        assert_eq!(cubic.cwnd(), after_loss);
        assert!(!cubic.in_slow_start());

        assert_eq!(cubic.on_timeout(), MIN_CWND);
        assert!(cubic.in_slow_start());
        assert_eq!(cubic.cwnd(), MIN_CWND);
    }

    #[test]
    fn rto_backoff_is_one_point_five_capped_at_ten_seconds() {
        let rtt = RttStats::new();
        assert_eq!(rtt.rto(), Duration::from_secs(2));
        rtt.update_rtt(Duration::from_millis(100));
        assert_eq!(rtt.latest_rtt(), Duration::from_millis(100));
        assert_eq!(rtt.smoothed_rtt(), Duration::from_millis(100));
        assert_eq!(rtt.rttvar(), Duration::from_millis(50));
        // 100ms + max(200ms, 10ms) + 1ms = 301ms.
        assert_eq!(rtt.rto(), Duration::from_millis(301));

        let base = Duration::from_secs(2);
        assert_eq!(retransmission_timeout(base, 0), base);
        assert_eq!(retransmission_timeout(base, 1), Duration::from_secs(3));
        assert_eq!(retransmission_timeout(base, 2), Duration::from_millis(4500));
        assert_eq!(retransmission_timeout(base, 4), MAX_BACKOFF_DURATION);
        assert_eq!(retransmission_timeout(base, u32::MAX), MAX_BACKOFF_DURATION);
    }

    #[test]
    fn all_zero_rtt_is_safe() {
        let cubic = Cubic::default();
        let t0 = Instant::now();
        for _ in 0..100 {
            let cwnd = cubic.on_ack(1, Duration::ZERO, t0);
            assert!((MIN_CWND..=MAX_CWND).contains(&cwnd));
        }
        assert!(cubic.in_slow_start());
        assert_eq!(
            cubic.on_loss(t0),
            ((116.0 * CUBIC_BETA).round() as u32).max(MIN_CWND)
        );

        let rtt = RttStats::new();
        rtt.update_rtt(Duration::ZERO);
        rtt.update_rtt(Duration::MAX);
        assert!(!rtt.has_measurement());
        assert_eq!(rtt.smoothed_rtt(), Duration::ZERO);
        assert_eq!(rtt.rto(), Duration::from_secs(2));

        // After switching to congestion avoidance, zero RTT must still use the
        // one-second fallback in W_est rather than dividing by zero.
        let fast = Cubic::new(16, 17);
        fast.on_ack(1, Duration::ZERO, t0);
        fast.on_loss(t0);
        assert!(!fast.in_slow_start());
        for millis in [0, 1, 10, 100, 1000] {
            let cwnd = fast.on_ack(1, Duration::ZERO, t0 + Duration::from_millis(millis));
            assert!((MIN_CWND..=MAX_CWND).contains(&cwnd));
        }
    }
}
