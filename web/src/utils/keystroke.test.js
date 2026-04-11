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

import { KeystrokeDynamics } from './keystroke.js';

function createFakeInputElement(overrides = {}) {
  const listeners = new Map();
  return {
    tagName: 'INPUT',
    type: 'text',
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
    ...overrides,
  };
}

function buildKeyEvent({ code, key, timeStamp }) {
  return {
    code,
    key,
    timeStamp,
    isComposing: false,
    defaultPrevented: false,
  };
}

test('KeystrokeDynamics computes hold/flight/digraph/typingSpeed', () => {
  const recorder = new KeystrokeDynamics();
  const input = createFakeInputElement();

  recorder.startCapture(input);

  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'KeyA', key: 'a', timeStamp: 0 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'KeyA', key: 'a', timeStamp: 100 }),
  );
  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'Digit1', key: '1', timeStamp: 180 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'Digit1', key: '1', timeStamp: 260 }),
  );
  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'KeyB', key: 'b', timeStamp: 340 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'KeyB', key: 'b', timeStamp: 430 }),
  );

  const fingerprint = recorder.getFingerprint();

  assert.equal(fingerprint.sampleCount, 3);
  assert.equal(fingerprint.commonDigraphs.length, 2);
  assert.ok(fingerprint.avgHoldTime > 85 && fingerprint.avgHoldTime < 95);
  assert.ok(fingerprint.stdHoldTime > 5 && fingerprint.stdHoldTime < 10);
  assert.ok(fingerprint.avgFlightTime > 165 && fingerprint.avgFlightTime < 175);
  assert.ok(fingerprint.stdFlightTime > 9 && fingerprint.stdFlightTime < 11);
  assert.ok(fingerprint.typingSpeed > 6.5 && fingerprint.typingSpeed < 7.5);

  assert.deepEqual(
    fingerprint.commonDigraphs.map((item) => item.digraph),
    ['alpha->digit', 'digit->alpha'],
  );
});

test('KeystrokeDynamics does not leak raw key content for unicode or symbols', () => {
  const recorder = new KeystrokeDynamics();
  const input = createFakeInputElement();

  recorder.startCapture(input);

  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'KeyU', key: '你', timeStamp: 0 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'KeyU', key: '你', timeStamp: 40 }),
  );
  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'KeyEmoji', key: '🙂', timeStamp: 100 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'KeyEmoji', key: '🙂', timeStamp: 140 }),
  );

  const fingerprint = recorder.getFingerprint();
  const serialized = JSON.stringify(fingerprint.commonDigraphs);

  assert.equal(fingerprint.sampleCount, 2);
  assert.equal(serialized.includes('你'), false);
  assert.equal(serialized.includes('🙂'), false);
});

test('KeystrokeDynamics startCapture is idempotent per input element', () => {
  const recorder = new KeystrokeDynamics();
  const input = createFakeInputElement();

  recorder.startCapture(input);
  recorder.startCapture(input);

  assert.equal(input.listenerCount('keydown'), 1);
  assert.equal(input.listenerCount('keyup'), 1);

  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'KeyA', key: 'a', timeStamp: 0 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'KeyA', key: 'a', timeStamp: 60 }),
  );

  assert.equal(recorder.getFingerprint().sampleCount, 1);
});

test('KeystrokeDynamics reset clears all captured state', () => {
  const recorder = new KeystrokeDynamics();
  const input = createFakeInputElement();

  recorder.startCapture(input);
  input.dispatch(
    'keydown',
    buildKeyEvent({ code: 'KeyA', key: 'a', timeStamp: 0 }),
  );
  input.dispatch(
    'keyup',
    buildKeyEvent({ code: 'KeyA', key: 'a', timeStamp: 100 }),
  );

  assert.equal(recorder.getFingerprint().sampleCount, 1);

  recorder.reset();
  const fingerprint = recorder.getFingerprint();
  assert.equal(fingerprint.sampleCount, 0);
  assert.equal(fingerprint.commonDigraphs.length, 0);
  assert.equal(fingerprint.typingSpeed, 0);
});

test('KeystrokeDynamics does not attach listeners to password inputs', () => {
  const recorder = new KeystrokeDynamics();
  const input = createFakeInputElement({ type: 'password' });

  recorder.startCapture(input);

  assert.equal(input.listenerCount('keydown'), 0);
  assert.equal(input.listenerCount('keyup'), 0);
  assert.equal(recorder.getFingerprint().sampleCount, 0);
});
