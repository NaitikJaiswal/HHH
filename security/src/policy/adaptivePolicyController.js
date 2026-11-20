/**
 * @module adaptivePolicyController
 * @description Adaptive Risk Policy Controller for Forward-Secure Logging.
 *
 * Implements the adaptive key evolution policy:
 *   - NORMAL mode: configurable signing epoch (default: 8 hours = 28,800,000 ms)
 *   - ELEVATED mode: configurable signing epoch (default: 5 minutes = 300,000 ms)
 *   - EMERGENCY mode: immediate signing freeze, zeroization, revocation
 *
 * Core security requirements:
 *   - Immediate eager evolution upon transition from NORMAL -> ELEVATED
 *   - Hysteresis / Anti-oscillation cooldown (default: 30 minutes clean) before de-escalation
 *   - Sliding window anomaly detection (e.g., >= 5 auth failures in 60s)
 *   - Strict monotonicity: epoch counters never decrease
 */

export const POLICY_MODES = {
  NORMAL: 'NORMAL',
  ELEVATED: 'ELEVATED',
  EMERGENCY: 'EMERGENCY',
};

export const ANOMALY_TYPES = {
  AUTH_FAILURE: 'AUTH_FAILURE',
  HASH_CHAIN_GAP: 'HASH_CHAIN_GAP',
  SEQUENCE_DUPLICATE: 'SEQUENCE_DUPLICATE',
  PREVIOUS_HASH_MISMATCH: 'PREVIOUS_HASH_MISMATCH',
  TAMPER_DETECTED: 'TAMPER_DETECTED',
  SOC_ALERT: 'SOC_ALERT',
  COMPROMISE_CONFIRMED: 'COMPROMISE_CONFIRMED',
};

export class AdaptivePolicyController {
  /**
   * @param {object} [options={}]
   * @param {number} [options.normalEpochMs=28800000] - 8 hours in ms.
   * @param {number} [options.elevatedEpochMs=300000] - 5 minutes in ms.
   * @param {number} [options.authFailureThreshold=5] - Failures in window to elevate.
   * @param {number} [options.slidingWindowMs=60000] - 60 seconds sliding window.
   * @param {number} [options.cooldownMs=1800000] - 30 minutes cooldown before returning to NORMAL.
   * @param {Function} [options.onEagerEvolutionTrigger=null] - Callback when eager evolution is triggered.
   * @param {Function} [options.onEmergencyTrigger=null] - Callback when emergency is triggered.
   */
  constructor(options = {}) {
    this.normalEpochMs = options.normalEpochMs ?? (8 * 60 * 60 * 1000);
    this.elevatedEpochMs = options.elevatedEpochMs ?? (5 * 60 * 1000);
    this.authFailureThreshold = options.authFailureThreshold ?? 5;
    this.slidingWindowMs = options.slidingWindowMs ?? (60 * 1000);
    this.cooldownMs = options.cooldownMs ?? (30 * 60 * 1000);

    this.onEagerEvolutionTrigger = options.onEagerEvolutionTrigger ?? null;
    this.onEmergencyTrigger = options.onEmergencyTrigger ?? null;

    this.mode = POLICY_MODES.NORMAL;
    this.authFailureTimestamps = [];
    this.anomalyHistory = [];
    this.lastAnomalyTime = 0;
    this.lastTransitionTime = Date.now();
    this.lastEvolutionTime = Date.now();
    this.emergencyReason = null;
    this.pendingEagerEvolution = false;
  }

  /**
   * Current operating mode.
   * @returns {string} 'NORMAL' | 'ELEVATED' | 'EMERGENCY'
   */
  getMode() {
    return this.mode;
  }

  /**
   * Current configured epoch duration in milliseconds.
   * @returns {number}
   */
  getCurrentEpochDurationMs() {
    if (this.mode === POLICY_MODES.EMERGENCY) return 0;
    if (this.mode === POLICY_MODES.ELEVATED) return this.elevatedEpochMs;
    return this.normalEpochMs;
  }

  /**
   * Record an authentication failure event.
   *
   * @param {number} [now=Date.now()]
   * @returns {boolean} True if this event triggered a state escalation.
   */
  recordAuthFailure(now = Date.now()) {
    if (this.mode === POLICY_MODES.EMERGENCY) {
      return false;
    }

    // Purge failures outside the sliding window
    const windowStart = now - this.slidingWindowMs;
    this.authFailureTimestamps = this.authFailureTimestamps.filter((ts) => ts >= windowStart);
    this.authFailureTimestamps.push(now);
    this.lastAnomalyTime = now;

    if (this.authFailureTimestamps.length >= this.authFailureThreshold) {
      if (this.mode === POLICY_MODES.NORMAL) {
        return this._escalateToElevated('AUTH_FAILURE_THRESHOLD_EXCEEDED', now);
      }
    }
    return false;
  }

  /**
   * Record a security anomaly or integrity alert.
   *
   * @param {string} anomalyType - Member of ANOMALY_TYPES.
   * @param {object} [details={}] - Additional diagnostic info.
   * @param {number} [now=Date.now()]
   * @returns {boolean} True if state changed.
   */
  recordAnomaly(anomalyType, details = {}, now = Date.now()) {
    this.lastAnomalyTime = now;
    this.anomalyHistory.push({ type: anomalyType, details, timestamp: now });

    if (anomalyType === ANOMALY_TYPES.COMPROMISE_CONFIRMED) {
      return this.triggerEmergency('Host compromise confirmed', details, now);
    }

    if (this.mode === POLICY_MODES.NORMAL) {
      return this._escalateToElevated(`ANOMALY_${anomalyType}`, now);
    }

    return false;
  }

  /**
   * Escalate operating state from NORMAL to ELEVATED.
   * Triggers immediate eager key evolution.
   *
   * @private
   */
  _escalateToElevated(reason, now = Date.now()) {
    if (this.mode === POLICY_MODES.EMERGENCY) return false;

    this.mode = POLICY_MODES.ELEVATED;
    this.lastTransitionTime = now;
    this.pendingEagerEvolution = true;

    if (typeof this.onEagerEvolutionTrigger === 'function') {
      try {
        this.onEagerEvolutionTrigger({ reason, timestamp: now });
      } catch {
        // Suppress callback failure from aborting policy state
      }
    }
    return true;
  }

  /**
   * Transition to EMERGENCY state (signing freeze, revocation).
   *
   * @param {string} reason
   * @param {object} [details={}]
   * @param {number} [now=Date.now()]
   * @returns {boolean}
   */
  triggerEmergency(reason, details = {}, now = Date.now()) {
    if (this.mode === POLICY_MODES.EMERGENCY) return false;

    this.mode = POLICY_MODES.EMERGENCY;
    this.emergencyReason = reason;
    this.lastTransitionTime = now;
    this.pendingEagerEvolution = false;

    if (typeof this.onEmergencyTrigger === 'function') {
      try {
        this.onEmergencyTrigger({ reason, details, timestamp: now });
      } catch {
        // Suppress callback failure
      }
    }
    return true;
  }

  /**
   * Evaluate whether key evolution should occur at the given time.
   *
   * Key evolution occurs if:
   *   1. Eager evolution was flagged upon entering ELEVATED mode.
   *   2. Elapsed time since last evolution >= current epoch duration.
   *
   * @param {number} [now=Date.now()]
   * @returns {{ shouldEvolve: boolean, reason?: string, eager?: boolean }}
   */
  shouldEvolve(now = Date.now()) {
    if (this.mode === POLICY_MODES.EMERGENCY) {
      return { shouldEvolve: false, reason: 'EMERGENCY_SIGNING_FROZEN' };
    }

    // 1. Eager evolution triggered by escalation
    if (this.pendingEagerEvolution) {
      return { shouldEvolve: true, reason: 'EAGER_RISK_ESCALATION', eager: true };
    }

    // 2. Periodic scheduled evolution
    const duration = this.getCurrentEpochDurationMs();
    const elapsed = now - this.lastEvolutionTime;
    if (elapsed >= duration) {
      return {
        shouldEvolve: true,
        reason: 'SCHEDULED_EPOCH_EXPIRATION',
        eager: false,
        elapsedMs: elapsed,
      };
    }

    return { shouldEvolve: false, remainingMs: duration - elapsed };
  }

  /**
   * Notify the controller that key evolution has successfully completed.
   *
   * @param {number} newEpoch - The new integer epoch index.
   * @param {number} [now=Date.now()]
   */
  onEvolutionComplete(newEpoch, now = Date.now()) {
    this.lastEvolutionTime = now;
    this.pendingEagerEvolution = false;
  }

  /**
   * Check and apply de-escalation from ELEVATED back to NORMAL
   * if the cooldown period has elapsed without any anomalies.
   *
   * @param {number} [now=Date.now()]
   * @returns {boolean} True if de-escalation occurred.
   */
  evaluateCooldown(now = Date.now()) {
    if (this.mode !== POLICY_MODES.ELEVATED) {
      return false;
    }

    const timeSinceLastAnomaly = now - this.lastAnomalyTime;
    if (timeSinceLastAnomaly >= this.cooldownMs) {
      this.mode = POLICY_MODES.NORMAL;
      this.lastTransitionTime = now;
      this.authFailureTimestamps = [];
      return true;
    }

    return false;
  }

  /**
   * Get full state representation of the policy controller.
   *
   * @param {number} [now=Date.now()]
   * @returns {object}
   */
  getPolicySummary(now = Date.now()) {
    return {
      mode: this.mode,
      currentEpochDurationMs: this.getCurrentEpochDurationMs(),
      lastTransitionTime: new Date(this.lastTransitionTime).toISOString(),
      lastEvolutionTime: new Date(this.lastEvolutionTime).toISOString(),
      lastAnomalyTime: this.lastAnomalyTime ? new Date(this.lastAnomalyTime).toISOString() : null,
      pendingEagerEvolution: this.pendingEagerEvolution,
      emergencyReason: this.emergencyReason,
      recentAuthFailures: this.authFailureTimestamps.length,
      cooldownRemainingMs: this.mode === POLICY_MODES.ELEVATED
        ? Math.max(0, this.cooldownMs - (now - this.lastAnomalyTime))
        : 0,
    };
  }
}

export default {
  POLICY_MODES,
  ANOMALY_TYPES,
  AdaptivePolicyController,
};
