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

import { useEffect, useRef } from 'react';
import fingerprintCollector from '../utils/fingerprint';
import { API } from '../helpers';
import {
  submitFingerprintReports,
  createBehaviorRetryReportController,
  getFingerprintBehaviorReportedKey,
  getFingerprintKeystrokeSeedKey,
  getFingerprintReportDelayMs,
  getFingerprintSessionReportedKey,
  hasFingerprintUserChanged,
  isKeystrokeCaptureTarget,
  resetFingerprintRuntimeState,
  shouldPreserveFreshLoginKeystrokeSeed,
  shouldReportBehaviorKeystroke,
  shouldRetryBehaviorReport,
  shouldSkipBaseFingerprintReport,
  shouldSkipFingerprintReportAttempt,
} from './useFingerprint.helpers';
import {
  createFingerprintReportInflightStore,
  runFingerprintReportWithInflight,
} from './useFingerprint.inflight';

const REPORT_INTERVAL = 24 * 60 * 60 * 1000; // 24小时
const KEYSTROKE_SAMPLE_THRESHOLD = 100;
const MOUSE_SAMPLE_THRESHOLD = 50;
const BEHAVIOR_RETRY_DEBOUNCE_MS = 300;
const inFlightReportStore = createFingerprintReportInflightStore();
const BASE_REPORT_STORAGE_TS_KEY = '_napi_fp_ts';
const BASE_REPORT_STORAGE_UID_KEY = '_napi_fp_uid';

function getStorageItem(storage, key) {
  try {
    return storage.getItem(key) || '';
  } catch {
    return '';
  }
}

function setStorageItem(storage, key, value) {
  try {
    storage.setItem(key, value);
  } catch {
    // ignore
  }
}

function removeStorageItem(storage, key) {
  try {
    storage.removeItem(key);
  } catch {
    // ignore
  }
}

function restartMouseBehaviorCapture() {
  attachMouseBehaviorTarget(window);
}

function resetCurrentFingerprintRuntimeState(userId) {
  resetFingerprintRuntimeState({
    collector: fingerprintCollector,
    inFlightStore: inFlightReportStore,
    userId,
    restartMouseCapture: restartMouseBehaviorCapture,
  });
}

function readKeystrokeSeedFromStorage() {
  const key = getFingerprintKeystrokeSeedKey();
  const raw = getStorageItem(sessionStorage, key);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    return parsed;
  } catch {
    removeStorageItem(sessionStorage, key);
    return null;
  }
}

function saveKeystrokeSeedToStorage(seed) {
  if (!seed || typeof seed !== 'object') {
    return;
  }
  if (Number(seed.sampleCount || 0) <= 0) {
    return;
  }

  const key = getFingerprintKeystrokeSeedKey();
  const current = readKeystrokeSeedFromStorage();
  const currentSampleCount = Number(current?.sampleCount || 0);
  const nextSampleCount = Number(seed.sampleCount || 0);
  const shouldReplace =
    !current ||
    shouldPreserveFreshLoginKeystrokeSeed(seed) ||
    nextSampleCount >= currentSampleCount;
  if (!shouldReplace) {
    return;
  }

  try {
    setStorageItem(sessionStorage, key, JSON.stringify(seed));
  } catch {
    // ignore
  }
}

function collectLiveKeystrokeTargets() {
  if (typeof document === 'undefined') {
    return [];
  }

  try {
    return Array.from(document.querySelectorAll('input,textarea'))
      .filter((node) => isKeystrokeCaptureTarget(node))
      .slice(0, 16);
  } catch {
    return [];
  }
}

function attachKeystrokeTarget(target) {
  if (!isKeystrokeCaptureTarget(target)) {
    return;
  }
  const collector = fingerprintCollector?.keystrokeCollector;
  if (!collector || typeof collector.startCapture !== 'function') {
    return;
  }
  collector.startCapture(target);
}

function attachMouseBehaviorTarget(target = window) {
  const collector = fingerprintCollector?.mouseCollector;
  if (!collector || typeof collector.start !== 'function') {
    return;
  }
  collector.start(target);
}

function getCurrentUid() {
  try {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    return String(user.id || '0');
  } catch {
    return '0';
  }
}

async function doReport() {
  const currentUid = getCurrentUid();
  if (currentUid === '0') {
    return null;
  }

  const reportedKey = getFingerprintSessionReportedKey(currentUid);
  const keystrokeReportedKey = getFingerprintBehaviorReportedKey(
    currentUid,
    'keystroke',
  );
  const mouseReportedKey = getFingerprintBehaviorReportedKey(
    currentUid,
    'mouse',
  );
  return runFingerprintReportWithInflight(
    inFlightReportStore,
    currentUid,
    async () => {
      try {
        const keystrokeAlreadyReported = Boolean(
          getStorageItem(sessionStorage, keystrokeReportedKey),
        );
        const mouseAlreadyReported = Boolean(
          getStorageItem(sessionStorage, mouseReportedKey),
        );
        const behaviorAlreadyReported =
          keystrokeAlreadyReported && mouseAlreadyReported;
        const baseAlreadyReported = Boolean(
          getStorageItem(sessionStorage, reportedKey),
        );

        const lastReport = getStorageItem(
          localStorage,
          BASE_REPORT_STORAGE_TS_KEY,
        );
        const lastUid = getStorageItem(
          localStorage,
          BASE_REPORT_STORAGE_UID_KEY,
        );
        const skipBaseReport = shouldSkipBaseFingerprintReport({
          lastReport,
          lastUid,
          currentUid,
          now: Date.now(),
          intervalMs: REPORT_INTERVAL,
        });

        const keystrokeSeed = readKeystrokeSeedFromStorage();
        const liveKeystrokeTargets = collectLiveKeystrokeTargets();
        const normalizedKeystrokeSeed =
          keystrokeSeed && Number(keystrokeSeed.sampleCount || 0) > 0
            ? keystrokeSeed
            : null;
        const fp = await fingerprintCollector.collect({
          userId: currentUid,
          keystroke: normalizedKeystrokeSeed,
          keystrokeSeed: {
            __captureTargets: liveKeystrokeTargets,
          },
        });
        if (!fp) {
          return;
        }

        const collectedKeystroke = fp?.keystroke;
        if (collectedKeystroke && collectedKeystroke.sampleCount > 0) {
          saveKeystrokeSeedToStorage(collectedKeystroke);
        }

        const shouldReportKeystroke = shouldReportBehaviorKeystroke({
          behaviorAlreadyReported: keystrokeAlreadyReported,
          sampleCount: Number(fp?.keystroke?.sampleCount || 0),
          threshold: KEYSTROKE_SAMPLE_THRESHOLD,
        });
        const shouldReportMouse = shouldReportBehaviorKeystroke({
          behaviorAlreadyReported: mouseAlreadyReported,
          sampleCount: Number(fp?.mouse?.sampleCount || 0),
          threshold: MOUSE_SAMPLE_THRESHOLD,
        });
        const shouldReportBehavior = shouldReportKeystroke || shouldReportMouse;

        if (
          shouldSkipFingerprintReportAttempt({
            baseAlreadyReported,
            behaviorAlreadyReported,
            skipBaseReport,
            shouldReportBehavior,
          })
        ) {
          return;
        }

        const reportDelayMs = getFingerprintReportDelayMs(fp);
        if (reportDelayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, reportDelayMs));
        }

        await submitFingerprintReports(fp, {
          skipBaseReport,
          currentUid,
          shouldReportKeystroke,
          shouldReportMouse,
          postReport: (url, payload, config) => API.post(url, payload, config),
          setStorageItem,
          localStorageRef: localStorage,
          sessionStorageRef: sessionStorage,
          baseReportStorageTsKey: BASE_REPORT_STORAGE_TS_KEY,
          baseReportStorageUidKey: BASE_REPORT_STORAGE_UID_KEY,
          reportedKey,
          keystrokeReportedKey,
          mouseReportedKey,
        });
      } catch (e) {
        console.debug('FP report skipped:', e?.message);
      }
    },
  );
}

export function useFingerprint(userId) {
  const reported = useRef(false);
  const timerRef = useRef(null);
  const prevUserIdRef = useRef(userId);
  const currentUidRef = useRef('0');
  const behaviorRetryControllerRef = useRef(null);

  // ── 主路径：userId 变化为有效值时触发 ──
  useEffect(() => {
    if (hasFingerprintUserChanged(prevUserIdRef.current, userId)) {
      reported.current = false;
      resetCurrentFingerprintRuntimeState(prevUserIdRef.current);
      inFlightReportStore.clear(userId);
      removeStorageItem(
        sessionStorage,
        getFingerprintSessionReportedKey(prevUserIdRef.current),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintSessionReportedKey(userId),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintBehaviorReportedKey(prevUserIdRef.current, 'keystroke'),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintBehaviorReportedKey(prevUserIdRef.current, 'mouse'),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintBehaviorReportedKey(userId, 'keystroke'),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintBehaviorReportedKey(userId, 'mouse'),
      );
      const currentSeed = readKeystrokeSeedFromStorage();
      if (!shouldPreserveFreshLoginKeystrokeSeed(currentSeed)) {
        removeStorageItem(sessionStorage, getFingerprintKeystrokeSeedKey());
      }
    }
    prevUserIdRef.current = userId;

    if (!userId || reported.current) return;
    reported.current = true;
    // 延迟 3 秒采集，不阻塞页面渲染
    timerRef.current = setTimeout(() => {
      void doReport();
    }, 3000);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [userId]);

  // ── 备用路径：监听 napi:user-login 事件 ──
  // 覆盖"同一 userId 重新登录"等 effect 不会重新执行的场景
  useEffect(() => {
    let loginTimer = null;
    const onLogin = () => {
      reported.current = false;
      const activeUid = currentUidRef.current || getCurrentUid();
      resetCurrentFingerprintRuntimeState(activeUid);
      // 清除当前用户会话标记，允许本次登录重新上报
      removeStorageItem(
        sessionStorage,
        getFingerprintSessionReportedKey(getCurrentUid()),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintBehaviorReportedKey(getCurrentUid(), 'keystroke'),
      );
      removeStorageItem(
        sessionStorage,
        getFingerprintBehaviorReportedKey(getCurrentUid(), 'mouse'),
      );
      const currentSeed = readKeystrokeSeedFromStorage();
      if (!shouldPreserveFreshLoginKeystrokeSeed(currentSeed)) {
        removeStorageItem(sessionStorage, getFingerprintKeystrokeSeedKey());
      }
      if (loginTimer) clearTimeout(loginTimer);
      loginTimer = setTimeout(() => {
        void doReport();
      }, 1000);
    };
    window.addEventListener('napi:user-login', onLogin);
    return () => {
      window.removeEventListener('napi:user-login', onLogin);
      if (loginTimer) clearTimeout(loginTimer);
    };
  }, []);

  useEffect(() => {
    currentUidRef.current = getCurrentUid();
  }, [userId]);

  useEffect(() => {
    behaviorRetryControllerRef.current?.dispose();
    behaviorRetryControllerRef.current = createBehaviorRetryReportController({
      threshold: KEYSTROKE_SAMPLE_THRESHOLD,
      debounceMs: BEHAVIOR_RETRY_DEBOUNCE_MS,
      getSampleCount: () => {
        const uid = currentUidRef.current || getCurrentUid();
        if (!uid || uid === '0') {
          return 0;
        }
        const keystrokeReported = Boolean(
          getStorageItem(
            sessionStorage,
            getFingerprintBehaviorReportedKey(uid, 'keystroke'),
          ),
        );
        const mouseReported = Boolean(
          getStorageItem(
            sessionStorage,
            getFingerprintBehaviorReportedKey(uid, 'mouse'),
          ),
        );
        const keystrokeSampleCount = Number(
          fingerprintCollector?.keystrokeCollector?.getFingerprint?.()
            ?.sampleCount || 0,
        );
        const mouseSampleCount = Number(
          fingerprintCollector?.mouseCollector?.getFingerprint?.()
            ?.sampleCount || 0,
        );
        return shouldRetryBehaviorReport({
          keystrokeAlreadyReported: keystrokeReported,
          mouseAlreadyReported: mouseReported,
          keystrokeSampleCount,
          mouseSampleCount,
          keystrokeThreshold: KEYSTROKE_SAMPLE_THRESHOLD,
          mouseThreshold: MOUSE_SAMPLE_THRESHOLD,
        })
          ? KEYSTROKE_SAMPLE_THRESHOLD + 1
          : 0;
      },
      isBehaviorReported: () => {
        const uid = currentUidRef.current || getCurrentUid();
        if (!uid || uid === '0') {
          return true;
        }
        return (
          Boolean(
            getStorageItem(
              sessionStorage,
              getFingerprintBehaviorReportedKey(uid, 'keystroke'),
            ),
          ) &&
          Boolean(
            getStorageItem(
              sessionStorage,
              getFingerprintBehaviorReportedKey(uid, 'mouse'),
            ),
          )
        );
      },
      triggerReport: () => doReport(),
    });

    return () => {
      behaviorRetryControllerRef.current?.dispose();
      behaviorRetryControllerRef.current = null;
    };
  }, []);

  // SPA 后续动态出现的输入框：在 focusin 时按需挂载 keystroke capture
  useEffect(() => {
    attachMouseBehaviorTarget(window);

    const onFocusIn = (event) => {
      attachKeystrokeTarget(event?.target);
    };
    const onBehaviorActivity = () => {
      behaviorRetryControllerRef.current?.handleKeystrokeEvent();
    };
    window.addEventListener('focusin', onFocusIn, true);
    window.addEventListener('input', onBehaviorActivity, true);
    window.addEventListener('keyup', onBehaviorActivity, true);
    window.addEventListener('mousemove', onBehaviorActivity, true);
    window.addEventListener('click', onBehaviorActivity, true);
    window.addEventListener('wheel', onBehaviorActivity, true);
    return () => {
      window.removeEventListener('focusin', onFocusIn, true);
      window.removeEventListener('input', onBehaviorActivity, true);
      window.removeEventListener('keyup', onBehaviorActivity, true);
      window.removeEventListener('mousemove', onBehaviorActivity, true);
      window.removeEventListener('click', onBehaviorActivity, true);
      window.removeEventListener('wheel', onBehaviorActivity, true);
    };
  }, []);
}
