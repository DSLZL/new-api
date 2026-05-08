/*
Copyright (C) 2025 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildFingerprintBaseReportPayload,
  buildFingerprintBehaviorReportPayload,
  buildFingerprintReportPostConfig,
  createBehaviorRetryReportController,
  getFingerprintReportDelayMs,
  markFreshLoginKeystrokeSeed,
  resetFingerprintRuntimeState,
  shouldPreserveFreshLoginKeystrokeSeed,
  submitFingerprintReports,
  getFingerprintBehaviorReportedKey,
  getFingerprintKeystrokeSeedKey,
  getFingerprintSessionReportedKey,
  hasFingerprintUserChanged,
  isKeystrokeCaptureTarget,
  resetFingerprintCollectorState,
  shouldReportBehaviorKeystroke,
  shouldRetryBehaviorReport,
  shouldSkipBaseFingerprintReport,
  shouldSkipFingerprintReportAttempt,
} from './useFingerprint.helpers.js';

test('hasFingerprintUserChanged returns true for guest to user login', () => {
  assert.equal(hasFingerprintUserChanged(0, 101), true);
});

test('hasFingerprintUserChanged returns true for direct user switch', () => {
  assert.equal(hasFingerprintUserChanged(101, 202), true);
});

test('hasFingerprintUserChanged returns false for same user or logout', () => {
  assert.equal(hasFingerprintUserChanged(101, 101), false);
  assert.equal(hasFingerprintUserChanged(101, 0), false);
  assert.equal(hasFingerprintUserChanged(0, 0), false);
});

test('getFingerprintReportDelayMs waits when dns probe exists', () => {
  assert.equal(
    getFingerprintReportDelayMs({ dns_probe_id: 'probe-123' }),
    1500,
  );
});

test('getFingerprintReportDelayMs skips wait without dns probe', () => {
  assert.equal(getFingerprintReportDelayMs({ dns_probe_id: '' }), 0);
  assert.equal(getFingerprintReportDelayMs(null), 0);
});

test('getFingerprintSessionReportedKey is user-scoped', () => {
  assert.equal(getFingerprintSessionReportedKey(101), '_napi_fp_reported:101');
  assert.equal(
    getFingerprintSessionReportedKey('202'),
    '_napi_fp_reported:202',
  );
  assert.notEqual(
    getFingerprintSessionReportedKey(101),
    getFingerprintSessionReportedKey(202),
  );
});

test('getFingerprintBehaviorReportedKey is user-scoped', () => {
  assert.equal(
    getFingerprintBehaviorReportedKey(101),
    '_napi_fp_behavior_reported:101',
  );
  assert.equal(
    getFingerprintBehaviorReportedKey('202'),
    '_napi_fp_behavior_reported:202',
  );
  assert.notEqual(
    getFingerprintBehaviorReportedKey(101),
    getFingerprintBehaviorReportedKey(202),
  );
});

test('getFingerprintBehaviorReportedKey supports behavior-type scope', () => {
  assert.equal(
    getFingerprintBehaviorReportedKey(101, 'mouse'),
    '_napi_fp_behavior_reported:101:mouse',
  );
  assert.notEqual(
    getFingerprintBehaviorReportedKey(101),
    getFingerprintBehaviorReportedKey(101, 'mouse'),
  );
});

test('getFingerprintSessionReportedKey normalizes empty user id to 0', () => {
  assert.equal(getFingerprintSessionReportedKey(), '_napi_fp_reported:0');
  assert.equal(getFingerprintSessionReportedKey(''), '_napi_fp_reported:0');
  assert.equal(getFingerprintSessionReportedKey(null), '_napi_fp_reported:0');
});

test('getFingerprintKeystrokeSeedKey returns stable storage key', () => {
  assert.equal(getFingerprintKeystrokeSeedKey(), '_napi_fp_keystroke_seed');
});

test('markFreshLoginKeystrokeSeed marks valid seed only', () => {
  assert.deepEqual(
    markFreshLoginKeystrokeSeed({ sampleCount: 12, typingSpeed: 3.1 }),
    {
      sampleCount: 12,
      typingSpeed: 3.1,
      __fresh_login_seed: true,
    },
  );
  assert.equal(markFreshLoginKeystrokeSeed({ sampleCount: 0 }), null);
  assert.equal(markFreshLoginKeystrokeSeed(null), null);
});

test('shouldPreserveFreshLoginKeystrokeSeed only keeps flagged positive seed', () => {
  assert.equal(
    shouldPreserveFreshLoginKeystrokeSeed({
      sampleCount: 12,
      __fresh_login_seed: true,
    }),
    true,
  );
  assert.equal(
    shouldPreserveFreshLoginKeystrokeSeed({
      sampleCount: 12,
      __fresh_login_seed: false,
    }),
    false,
  );
  assert.equal(
    shouldPreserveFreshLoginKeystrokeSeed({
      sampleCount: 0,
      __fresh_login_seed: true,
    }),
    false,
  );
});

test('resetFingerprintRuntimeState clears inflight and restarts mouse capture', () => {
  const calls = [];
  resetFingerprintRuntimeState({
    collector: {
      resetSessionState: () => calls.push('session'),
      resetBehaviorState: () => calls.push('behavior'),
    },
    inFlightStore: {
      clear: (userId) => calls.push(`clear:${userId}`),
    },
    userId: '101',
    restartMouseCapture: () => calls.push('mouse'),
  });

  assert.deepEqual(calls, ['session', 'behavior', 'clear:101', 'mouse']);
});

test('buildFingerprintBaseReportPayload strips behavior fields', () => {
  assert.deepEqual(
    buildFingerprintBaseReportPayload({
      canvas_hash: 'canvas-1',
      session_id: 'session-1',
      keystroke: { sampleCount: 120 },
      mouse: { sampleCount: 64 },
    }),
    {
      canvas_hash: 'canvas-1',
      session_id: 'session-1',
    },
  );
});

test('buildFingerprintBehaviorReportPayload keeps only selected behavior fields', () => {
  assert.deepEqual(
    buildFingerprintBehaviorReportPayload(
      {
        canvas_hash: 'canvas-1',
        session_id: 'session-1',
        session_start_at: 11,
        session_end_at: 22,
        keystroke: { sampleCount: 120 },
        mouse: { sampleCount: 64 },
      },
      { shouldReportKeystroke: true, shouldReportMouse: false },
    ),
    {
      session_id: 'session-1',
      session_start_at: 11,
      session_end_at: 22,
      keystroke: { sampleCount: 120 },
    },
  );

  assert.deepEqual(
    buildFingerprintBehaviorReportPayload(
      {
        session_id: 'session-1',
        keystroke: { sampleCount: 120 },
        mouse: { sampleCount: 64 },
      },
      { shouldReportKeystroke: false, shouldReportMouse: true },
    ),
    {
      session_id: 'session-1',
      mouse: { sampleCount: 64 },
    },
  );
});

test('buildFingerprintBehaviorReportPayload returns null when no behavior selected', () => {
  assert.equal(
    buildFingerprintBehaviorReportPayload(
      {
        session_id: 'session-1',
        keystroke: { sampleCount: 120 },
        mouse: { sampleCount: 64 },
      },
      { shouldReportKeystroke: false, shouldReportMouse: false },
    ),
    null,
  );
});

test('buildFingerprintReportPostConfig keeps collected user id in request headers', () => {
  assert.deepEqual(buildFingerprintReportPostConfig('101'), {
    headers: {
      'New-API-User': '101',
    },
  });
});

test('buildFingerprintReportPostConfig skips header for empty user id', () => {
  assert.deepEqual(buildFingerprintReportPostConfig(), {});
  assert.deepEqual(buildFingerprintReportPostConfig(''), {});
  assert.deepEqual(buildFingerprintReportPostConfig(0), {});
});

test('submitFingerprintReports posts base and behavior payloads separately and persists report markers', async () => {
  const calls = [];
  const local = new Map();
  const session = new Map();
  const setStorageItem = (storage, key, value) => {
    storage.set(key, value);
  };

  const result = await submitFingerprintReports(
    {
      canvas_hash: 'canvas-1',
      session_id: 'session-1',
      session_start_at: 11,
      keystroke: { sampleCount: 120 },
      mouse: { sampleCount: 64 },
    },
    {
      skipBaseReport: false,
      currentUid: '101',
      shouldReportKeystroke: true,
      shouldReportMouse: false,
      postReport: async (url, payload, config) => {
        calls.push({ url, payload, config });
      },
      setStorageItem,
      localStorageRef: local,
      sessionStorageRef: session,
      baseReportStorageTsKey: '_base_ts',
      baseReportStorageUidKey: '_base_uid',
      reportedKey: '_reported',
      keystrokeReportedKey: '_key_reported',
      mouseReportedKey: '_mouse_reported',
      now: () => 22000,
    },
  );

  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], {
    url: '/api/fingerprint/report',
    payload: {
      canvas_hash: 'canvas-1',
      session_id: 'session-1',
      session_start_at: 11,
      session_end_at: 22,
    },
    config: {
      headers: {
        'New-API-User': '101',
      },
    },
  });
  assert.deepEqual(calls[1], {
    url: '/api/fingerprint/behavior',
    payload: {
      session_id: 'session-1',
      session_start_at: 11,
      session_end_at: 22,
      keystroke: { sampleCount: 120 },
    },
    config: {
      headers: {
        'New-API-User': '101',
      },
    },
  });
  assert.equal(local.get('_base_ts'), '22000');
  assert.equal(local.get('_base_uid'), '101');
  assert.equal(session.get('_reported'), '1');
  assert.equal(session.get('_key_reported'), '1');
  assert.equal(session.has('_mouse_reported'), false);
  assert.equal(result.postedBase, true);
  assert.equal(result.postedBehavior, true);
  assert.equal(result.preparedFingerprint.session_end_at, 22);
});

test('submitFingerprintReports skips base but still sends mouse-only behavior payload', async () => {
  const calls = [];
  const local = new Map();
  const session = new Map();

  await submitFingerprintReports(
    {
      canvas_hash: 'canvas-1',
      session_id: 'session-1',
      session_start_at: 11,
      keystroke: { sampleCount: 120 },
      mouse: { sampleCount: 64 },
    },
    {
      skipBaseReport: true,
      currentUid: '101',
      shouldReportKeystroke: false,
      shouldReportMouse: true,
      postReport: async (url, payload, config) => {
        calls.push({ url, payload, config });
      },
      setStorageItem: (storage, key, value) => storage.set(key, value),
      localStorageRef: local,
      sessionStorageRef: session,
      baseReportStorageTsKey: '_base_ts',
      baseReportStorageUidKey: '_base_uid',
      reportedKey: '_reported',
      keystrokeReportedKey: '_key_reported',
      mouseReportedKey: '_mouse_reported',
      now: () => 33000,
    },
  );

  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], {
    url: '/api/fingerprint/behavior',
    payload: {
      session_id: 'session-1',
      session_start_at: 11,
      session_end_at: 33,
      mouse: { sampleCount: 64 },
    },
    config: {
      headers: {
        'New-API-User': '101',
      },
    },
  });
  assert.equal(local.size, 0);
  assert.equal(session.has('_reported'), false);
  assert.equal(session.has('_key_reported'), false);
  assert.equal(session.get('_mouse_reported'), '1');
});

test('submitFingerprintReports does not mark behavior storage when nothing is selected', async () => {
  const calls = [];
  const local = new Map();
  const session = new Map();

  const result = await submitFingerprintReports(
    {
      canvas_hash: 'canvas-1',
      session_id: 'session-1',
      session_start_at: 11,
      keystroke: { sampleCount: 120 },
      mouse: { sampleCount: 64 },
    },
    {
      skipBaseReport: true,
      currentUid: '101',
      shouldReportKeystroke: false,
      shouldReportMouse: false,
      postReport: async (url, payload, config) => {
        calls.push({ url, payload, config });
      },
      setStorageItem: (storage, key, value) => storage.set(key, value),
      localStorageRef: local,
      sessionStorageRef: session,
      baseReportStorageTsKey: '_base_ts',
      baseReportStorageUidKey: '_base_uid',
      reportedKey: '_reported',
      keystrokeReportedKey: '_key_reported',
      mouseReportedKey: '_mouse_reported',
      now: () => 33000,
    },
  );

  assert.equal(calls.length, 0);
  assert.equal(local.size, 0);
  assert.equal(session.size, 0);
  assert.equal(result.postedBase, false);
  assert.equal(result.postedBehavior, false);
  assert.equal(result.behaviorPayload, null);
});

test('shouldSkipBaseFingerprintReport only skips same user inside interval', () => {
  const now = 1710000000000;
  const intervalMs = 24 * 60 * 60 * 1000;

  assert.equal(
    shouldSkipBaseFingerprintReport({
      lastReport: String(now - 1000),
      lastUid: '101',
      currentUid: '101',
      now,
      intervalMs,
    }),
    true,
  );

  assert.equal(
    shouldSkipBaseFingerprintReport({
      lastReport: String(now - 1000),
      lastUid: '202',
      currentUid: '101',
      now,
      intervalMs,
    }),
    false,
  );

  assert.equal(
    shouldSkipBaseFingerprintReport({
      lastReport: String(now - intervalMs - 1),
      lastUid: '101',
      currentUid: '101',
      now,
      intervalMs,
    }),
    false,
  );
});

test('shouldReportBehaviorKeystroke uses strict >100 threshold', () => {
  assert.equal(
    shouldReportBehaviorKeystroke({
      behaviorAlreadyReported: false,
      sampleCount: 100,
      threshold: 100,
    }),
    false,
  );

  assert.equal(
    shouldReportBehaviorKeystroke({
      behaviorAlreadyReported: false,
      sampleCount: 101,
      threshold: 100,
    }),
    true,
  );

  assert.equal(
    shouldReportBehaviorKeystroke({
      behaviorAlreadyReported: true,
      sampleCount: 1000,
      threshold: 100,
    }),
    false,
  );
});

test('shouldRetryBehaviorReport supports mouse-only retry path', () => {
  assert.equal(
    shouldRetryBehaviorReport({
      keystrokeAlreadyReported: false,
      mouseAlreadyReported: false,
      keystrokeSampleCount: 0,
      mouseSampleCount: 51,
      keystrokeThreshold: 100,
      mouseThreshold: 50,
    }),
    true,
  );

  assert.equal(
    shouldRetryBehaviorReport({
      keystrokeAlreadyReported: true,
      mouseAlreadyReported: false,
      keystrokeSampleCount: 1000,
      mouseSampleCount: 50,
      keystrokeThreshold: 100,
      mouseThreshold: 50,
    }),
    false,
  );
});

test('isKeystrokeCaptureTarget validates input and textarea elements', () => {
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'INPUT',
      type: 'text',
      disabled: false,
      readOnly: false,
    }),
    true,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'TEXTAREA',
      disabled: false,
      readOnly: false,
    }),
    true,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'INPUT',
      type: 'hidden',
      disabled: false,
      readOnly: false,
    }),
    false,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'INPUT',
      type: 'password',
      disabled: false,
      readOnly: false,
    }),
    false,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'INPUT',
      type: 'text',
      name: 'password',
      disabled: false,
      readOnly: false,
    }),
    false,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'INPUT',
      type: 'text',
      autoComplete: 'current-password',
      disabled: false,
      readOnly: false,
    }),
    false,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'INPUT',
      type: 'text',
      disabled: true,
      readOnly: false,
    }),
    false,
  );
  assert.equal(
    isKeystrokeCaptureTarget({
      tagName: 'DIV',
      type: 'text',
      disabled: false,
      readOnly: false,
    }),
    false,
  );
});

test('shouldSkipFingerprintReportAttempt allows behavior-only retry', () => {
  assert.equal(
    shouldSkipFingerprintReportAttempt({
      baseAlreadyReported: true,
      behaviorAlreadyReported: false,
      skipBaseReport: true,
      shouldReportBehavior: true,
    }),
    false,
  );

  assert.equal(
    shouldSkipFingerprintReportAttempt({
      baseAlreadyReported: true,
      behaviorAlreadyReported: false,
      skipBaseReport: true,
      shouldReportBehavior: false,
    }),
    true,
  );

  assert.equal(
    shouldSkipFingerprintReportAttempt({
      baseAlreadyReported: false,
      behaviorAlreadyReported: false,
      skipBaseReport: false,
      shouldReportBehavior: false,
    }),
    false,
  );

  assert.equal(
    shouldSkipFingerprintReportAttempt({
      baseAlreadyReported: true,
      behaviorAlreadyReported: true,
      skipBaseReport: true,
      shouldReportBehavior: true,
    }),
    true,
  );
});

test('createBehaviorRetryReportController triggers one behavior-only retry after threshold crossing', async () => {
  let sampleCount = 90;
  let behaviorAlreadyReported = false;
  const triggers = [];

  const controller = createBehaviorRetryReportController({
    threshold: 100,
    debounceMs: 0,
    getSampleCount: () => sampleCount,
    isBehaviorReported: () => behaviorAlreadyReported,
    triggerReport: () => {
      triggers.push(sampleCount);
      behaviorAlreadyReported = true;
      return Promise.resolve();
    },
  });

  controller.handleKeystrokeEvent();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(triggers.length, 0);

  sampleCount = 101;
  controller.handleKeystrokeEvent();
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(triggers.length, 1);
  assert.equal(triggers[0], 101);

  sampleCount = 180;
  controller.handleKeystrokeEvent();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(triggers.length, 1);

  controller.dispose();
});

test('createBehaviorRetryReportController does not call report concurrently for bursts', async () => {
  let pendingResolve;
  const calls = [];
  const controller = createBehaviorRetryReportController({
    threshold: 100,
    debounceMs: 0,
    getSampleCount: () => 120,
    isBehaviorReported: () => false,
    triggerReport: async () => {
      calls.push('triggered');
      await new Promise((resolve) => {
        pendingResolve = resolve;
      });
    },
  });

  controller.handleKeystrokeEvent();
  controller.handleKeystrokeEvent();
  controller.handleKeystrokeEvent();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.length, 1);

  pendingResolve();
  await new Promise((resolve) => setTimeout(resolve, 0));

  controller.dispose();
});

test('resetFingerprintCollectorState clears both session and behavior collectors', () => {
  const calls = [];
  resetFingerprintCollectorState({
    resetSessionState: () => calls.push('session'),
    resetBehaviorState: () => calls.push('behavior'),
  });

  assert.deepEqual(calls, ['session', 'behavior']);
});
