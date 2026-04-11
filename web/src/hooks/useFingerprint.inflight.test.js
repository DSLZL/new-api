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
  createFingerprintReportInflightStore,
  runFingerprintReportWithInflight,
} from './useFingerprint.inflight.js';

test('reuses in-flight promise for same user', () => {
  const store = createFingerprintReportInflightStore();
  const promise = Promise.resolve('same-user');

  store.set(101, promise);

  assert.equal(store.get(101), promise);
});

test('isolates in-flight promise across different users', () => {
  const store = createFingerprintReportInflightStore();
  const promiseA = Promise.resolve('user-a');
  const promiseB = Promise.resolve('user-b');

  store.set(101, promiseA);
  store.set(202, promiseB);

  assert.equal(store.get(101), promiseA);
  assert.equal(store.get(202), promiseB);
  assert.notEqual(store.get(101), store.get(202));
});

test('delete only clears matching promise for user', () => {
  const store = createFingerprintReportInflightStore();
  const oldPromise = Promise.resolve('old');
  const newPromise = Promise.resolve('new');

  store.set(101, oldPromise);
  store.set(101, newPromise);
  store.delete(101, oldPromise);

  assert.equal(store.get(101), newPromise);

  store.delete(101, newPromise);
  assert.equal(store.get(101), null);
});

test('runFingerprintReportWithInflight clears entry for sync early-return task', async () => {
  const store = createFingerprintReportInflightStore();

  const result = await runFingerprintReportWithInflight(
    store,
    101,
    () => undefined,
  );

  assert.equal(result, undefined);
  assert.equal(store.get(101), null);
});

test('runFingerprintReportWithInflight reuses same in-flight promise per user', async () => {
  const store = createFingerprintReportInflightStore();
  let calls = 0;
  let resolveTask;
  const task = () => {
    calls += 1;
    return new Promise((resolve) => {
      resolveTask = resolve;
    });
  };

  const promiseA = runFingerprintReportWithInflight(store, 101, task);
  const promiseB = runFingerprintReportWithInflight(store, 101, task);

  assert.equal(promiseA, promiseB);
  assert.equal(calls, 1);
  assert.notEqual(store.get(101), null);

  resolveTask('done');
  const result = await promiseA;

  assert.equal(result, 'done');
  assert.equal(await promiseB, 'done');
  assert.equal(store.get(101), null);
});
