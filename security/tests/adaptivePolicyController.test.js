/**
 * @file adaptivePolicyController.test.js
 * @description Unit tests for Adaptive Risk Policy Controller.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  AdaptivePolicyController,
  POLICY_MODES,
  ANOMALY_TYPES,
} from '../src/policy/adaptivePolicyController.js';

describe('Adaptive Risk Policy Controller', () => {
  it('1. Initializes in NORMAL mode with 8-hour epoch duration', () => {
    const controller = new AdaptivePolicyController();
    assert.equal(controller.getMode(), POLICY_MODES.NORMAL);
    assert.equal(controller.getCurrentEpochDurationMs(), 8 * 60 * 60 * 1000);

    const check = controller.shouldEvolve(Date.now());
    assert.equal(check.shouldEvolve, false);
  });

  it('2. Escalates to ELEVATED upon >= 5 auth failures within 60-second sliding window', () => {
    let eagerTriggerFired = false;
    const controller = new AdaptivePolicyController({
      authFailureThreshold: 5,
      slidingWindowMs: 60000,
      onEagerEvolutionTrigger: () => {
        eagerTriggerFired = true;
      },
    });

    const baseTime = 1000000;
    // 4 failures within 30s
    for (let i = 0; i < 4; i++) {
      const escalated = controller.recordAuthFailure(baseTime + i * 5000);
      assert.equal(escalated, false);
      assert.equal(controller.getMode(), POLICY_MODES.NORMAL);
    }
    assert.equal(eagerTriggerFired, false);

    // 5th failure at 25s into window -> triggers escalation
    const escalated = controller.recordAuthFailure(baseTime + 25000);
    assert.equal(escalated, true);
    assert.equal(controller.getMode(), POLICY_MODES.ELEVATED);
    assert.equal(eagerTriggerFired, true);

    // Immediately requires eager evolution
    const evalResult = controller.shouldEvolve(baseTime + 25001);
    assert.equal(evalResult.shouldEvolve, true);
    assert.equal(evalResult.eager, true);
    assert.equal(evalResult.reason, 'EAGER_RISK_ESCALATION');
  });

  it('3. Ignores stale auth failures outside the sliding window', () => {
    const controller = new AdaptivePolicyController({
      authFailureThreshold: 5,
      slidingWindowMs: 60000,
    });

    const t0 = 1000000;
    // 4 failures at t0
    for (let i = 0; i < 4; i++) {
      controller.recordAuthFailure(t0);
    }

    // 5th failure 70 seconds later (window expired) -> should not escalate
    const escalated = controller.recordAuthFailure(t0 + 70000);
    assert.equal(escalated, false);
    assert.equal(controller.getMode(), POLICY_MODES.NORMAL);
  });

  it('4. Triggers eager evolution and shifts epoch duration to 5 minutes in ELEVATED mode', () => {
    const controller = new AdaptivePolicyController({
      elevatedEpochMs: 300000, // 5 min
    });

    const now = 5000000;
    controller.recordAnomaly(ANOMALY_TYPES.HASH_CHAIN_GAP, { missingSeq: 42 }, now);

    assert.equal(controller.getMode(), POLICY_MODES.ELEVATED);
    assert.equal(controller.getCurrentEpochDurationMs(), 300000);

    // First check triggers eager evolution
    const check1 = controller.shouldEvolve(now + 10);
    assert.equal(check1.shouldEvolve, true);
    assert.equal(check1.eager, true);

    // Evolution complete
    controller.onEvolutionComplete(1, now + 50);

    // Check again at 2 minutes: should NOT evolve yet
    const check2 = controller.shouldEvolve(now + 50 + 120000);
    assert.equal(check2.shouldEvolve, false);

    // Check at 5 minutes + 1 second: scheduled evolution triggers
    const check3 = controller.shouldEvolve(now + 50 + 300001);
    assert.equal(check3.shouldEvolve, true);
    assert.equal(check3.eager, false);
    assert.equal(check3.reason, 'SCHEDULED_EPOCH_EXPIRATION');
  });

  it('5. Enforces 30-minute cooldown before de-escalating from ELEVATED back to NORMAL', () => {
    const controller = new AdaptivePolicyController({
      cooldownMs: 1800000, // 30 min
    });

    const tEscalate = 10000000;
    controller.recordAnomaly(ANOMALY_TYPES.SOC_ALERT, {}, tEscalate);
    assert.equal(controller.getMode(), POLICY_MODES.ELEVATED);

    // 15 minutes later: cooldown not satisfied
    const deescalatedEarly = controller.evaluateCooldown(tEscalate + 900000);
    assert.equal(deescalatedEarly, false);
    assert.equal(controller.getMode(), POLICY_MODES.ELEVATED);

    // Another anomaly at 20 min resets cooldown timer
    controller.recordAnomaly(ANOMALY_TYPES.AUTH_FAILURE, {}, tEscalate + 1200000);

    // 15 minutes after second anomaly (35 min from start, but only 15 min from last anomaly)
    const deescalatedMid = controller.evaluateCooldown(tEscalate + 2100000);
    assert.equal(deescalatedEarly, false);
    assert.equal(controller.getMode(), POLICY_MODES.ELEVATED);

    // Full 30 clean minutes after last anomaly
    const deescalatedClean = controller.evaluateCooldown(tEscalate + 1200000 + 1800001);
    assert.equal(deescalatedClean, true);
    assert.equal(controller.getMode(), POLICY_MODES.NORMAL);
    assert.equal(controller.getCurrentEpochDurationMs(), 8 * 60 * 60 * 1000);
  });

  it('6. Transitions to EMERGENCY mode on confirmed compromise, freezing signing', () => {
    let emergencyFired = false;
    const controller = new AdaptivePolicyController({
      onEmergencyTrigger: () => {
        emergencyFired = true;
      },
    });

    const tCompromise = 20000000;
    const escalated = controller.recordAnomaly(
      ANOMALY_TYPES.COMPROMISE_CONFIRMED,
      { rootShellDetected: true },
      tCompromise
    );

    assert.equal(escalated, true);
    assert.equal(emergencyFired, true);
    assert.equal(controller.getMode(), POLICY_MODES.EMERGENCY);
    assert.equal(controller.getCurrentEpochDurationMs(), 0);

    // Signing is permanently frozen
    const check = controller.shouldEvolve(tCompromise + 1000);
    assert.equal(check.shouldEvolve, false);
    assert.equal(check.reason, 'EMERGENCY_SIGNING_FROZEN');

    // Cannot de-escalate from emergency
    const tryCooldown = controller.evaluateCooldown(tCompromise + 99999999);
    assert.equal(tryCooldown, false);
    assert.equal(controller.getMode(), POLICY_MODES.EMERGENCY);
  });
});
