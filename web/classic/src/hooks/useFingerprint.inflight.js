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

export function createFingerprintReportInflightStore() {
  const inflight = new Map();

  return {
    get(userId) {
      return inflight.get(String(userId)) || null;
    },
    set(userId, promise) {
      inflight.set(String(userId), promise);
    },
    delete(userId, promise) {
      const key = String(userId);
      if (inflight.get(key) === promise) {
        inflight.delete(key);
      }
    },
    clear(userId) {
      if (typeof userId === 'undefined') {
        inflight.clear();
        return;
      }
      inflight.delete(String(userId));
    },
  };
}

export function runFingerprintReportWithInflight(store, userId, task) {
  const inFlightReportPromise = store.get(userId);
  if (inFlightReportPromise) {
    return inFlightReportPromise;
  }

  let reportPromise;
  try {
    reportPromise = Promise.resolve(task()).finally(() => {
      store.delete(userId, reportPromise);
    });
  } catch (error) {
    reportPromise = Promise.reject(error).finally(() => {
      store.delete(userId, reportPromise);
    });
  }

  store.set(userId, reportPromise);
  return reportPromise;
}
