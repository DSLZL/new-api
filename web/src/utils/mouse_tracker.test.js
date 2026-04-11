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

import { MouseBehaviorTracker } from './mouse_tracker.js';

function createFakeEventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, handler) {
      if (!listeners.has(type)) {
        listeners.set(type, new Set());
      }
      listeners.get(type).add(handler);
    },
    removeEventListener(type, handler) {
      if (!listeners.has(type)) {
        return;
      }
      listeners.get(type).delete(handler);
    },
    dispatch(type, event) {
      if (!listeners.has(type)) {
        return;
      }
      const handlers = Array.from(listeners.get(type));
      handlers.forEach((handler) => handler(event));
    },
    listenerCount(type) {
      return listeners.has(type) ? listeners.get(type).size : 0;
    },
  };
}

function buildMouseEvent(overrides = {}) {
  return {
    clientX: 0,
    clientY: 0,
    timeStamp: 0,
    buttons: 0,
    defaultPrevented: false,
    view: {
      innerWidth: 200,
      innerHeight: 200,
    },
    ...overrides,
  };
}

function buildWheelEvent(overrides = {}) {
  return {
    deltaY: 120,
    deltaMode: 0,
    defaultPrevented: false,
    ...overrides,
  };
}

test('MouseBehaviorTracker computes behavior stats without leaking raw coordinates', () => {
  const tracker = new MouseBehaviorTracker();
  const target = createFakeEventTarget();

  tracker.start(target);

  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 0, clientY: 0, timeStamp: 0 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 60, clientY: 0, timeStamp: 55 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 60, clientY: 60, timeStamp: 110 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 120, clientY: 60, timeStamp: 165 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 120, clientY: 120, timeStamp: 220 }),
  );

  target.dispatch('wheel', buildWheelEvent({ deltaY: 80, deltaMode: 0 }));
  target.dispatch('wheel', buildWheelEvent({ deltaY: 100, deltaMode: 0 }));
  target.dispatch('wheel', buildWheelEvent({ deltaY: 240, deltaMode: 1 }));

  target.dispatch(
    'click',
    buildMouseEvent({ clientX: 10, clientY: 10, timeStamp: 240 }),
  );
  target.dispatch(
    'click',
    buildMouseEvent({ clientX: 190, clientY: 10, timeStamp: 250 }),
  );
  target.dispatch(
    'click',
    buildMouseEvent({ clientX: 10, clientY: 190, timeStamp: 260 }),
  );
  target.dispatch(
    'click',
    buildMouseEvent({ clientX: 190, clientY: 190, timeStamp: 270 }),
  );

  const fingerprint = tracker.getFingerprint();
  const serialized = JSON.stringify(fingerprint);

  assert.equal(fingerprint.sampleCount, 5);
  assert.ok(fingerprint.avgSpeed > 1000);
  assert.ok(fingerprint.maxSpeed >= fingerprint.avgSpeed);
  assert.ok(fingerprint.speedStd >= 0);
  assert.ok(fingerprint.avgAcceleration >= 0);
  assert.ok(fingerprint.accStd >= 0);
  assert.ok(fingerprint.directionChangeRate > 0.4);
  assert.equal(fingerprint.scrollDeltaMode, 0);
  assert.ok(fingerprint.avgScrollDelta > 100);
  assert.deepEqual(fingerprint.clickDistribution, {
    topLeft: 0.25,
    topRight: 0.25,
    bottomLeft: 0.25,
    bottomRight: 0.25,
  });
  assert.equal(serialized.includes('clientX'), false);
  assert.equal(serialized.includes('clientY'), false);
});

test('MouseBehaviorTracker start is idempotent, throttles samples, and stop detaches listeners', () => {
  const tracker = new MouseBehaviorTracker();
  const target = createFakeEventTarget();

  tracker.start(target);
  tracker.start(target);

  assert.equal(target.listenerCount('mousemove'), 1);
  assert.equal(target.listenerCount('click'), 1);
  assert.equal(target.listenerCount('wheel'), 1);

  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 0, clientY: 0, timeStamp: 0 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 20, clientY: 0, timeStamp: 20 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 80, clientY: 0, timeStamp: 70 }),
  );

  assert.equal(tracker.getFingerprint().sampleCount, 2);

  tracker.stop();
  assert.equal(target.listenerCount('mousemove'), 0);
  assert.equal(target.listenerCount('click'), 0);
  assert.equal(target.listenerCount('wheel'), 0);
});

test('MouseBehaviorTracker reset clears state and ignores invalid motion data', () => {
  const tracker = new MouseBehaviorTracker();
  const target = createFakeEventTarget();

  tracker.start(target);
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 0, clientY: 0, timeStamp: 0 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 0, clientY: 0, timeStamp: 0 }),
  );
  target.dispatch(
    'mousemove',
    buildMouseEvent({ clientX: 40, clientY: 0, timeStamp: 60 }),
  );
  target.dispatch(
    'wheel',
    buildWheelEvent({ deltaY: Number.NaN, deltaMode: 0 }),
  );

  const fingerprint = tracker.getFingerprint();
  assert.equal(Number.isFinite(fingerprint.avgSpeed), true);
  assert.equal(Number.isFinite(fingerprint.avgAcceleration), true);

  tracker.reset();
  assert.deepEqual(tracker.getFingerprint(), {
    avgSpeed: 0,
    maxSpeed: 0,
    speedStd: 0,
    avgAcceleration: 0,
    accStd: 0,
    directionChangeRate: 0,
    avgScrollDelta: 0,
    scrollDeltaMode: 0,
    clickDistribution: {
      topLeft: 0,
      topRight: 0,
      bottomLeft: 0,
      bottomRight: 0,
    },
    sampleCount: 0,
  });
});
