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

export function hasFingerprintUserChanged(prevUserId, nextUserId) {
  return Number(nextUserId) > 0 && Number(prevUserId) !== Number(nextUserId);
}

export function getFingerprintReportDelayMs(fingerprint) {
  if (fingerprint?.dns_probe_id) {
    return 1500;
  }
  return 0;
}

export function shouldSkipBaseFingerprintReport({
  lastReport,
  lastUid,
  currentUid,
  now,
  intervalMs,
}) {
  if (!lastReport || String(lastUid || '') !== String(currentUid || '')) {
    return false;
  }

  const reportTs = Number.parseInt(lastReport, 10);
  if (!Number.isFinite(reportTs) || reportTs <= 0) {
    return false;
  }

  return now - reportTs < intervalMs;
}

export function shouldReportBehaviorKeystroke({
  behaviorAlreadyReported,
  sampleCount,
  threshold,
}) {
  if (behaviorAlreadyReported) {
    return false;
  }
  const normalizedSampleCount = Number(sampleCount || 0);
  return (
    Number.isFinite(normalizedSampleCount) && normalizedSampleCount > threshold
  );
}

export function shouldRetryBehaviorReport({
  keystrokeAlreadyReported,
  mouseAlreadyReported,
  keystrokeSampleCount,
  mouseSampleCount,
  keystrokeThreshold,
  mouseThreshold,
}) {
  return (
    shouldReportBehaviorKeystroke({
      behaviorAlreadyReported: keystrokeAlreadyReported,
      sampleCount: keystrokeSampleCount,
      threshold: keystrokeThreshold,
    }) ||
    shouldReportBehaviorKeystroke({
      behaviorAlreadyReported: mouseAlreadyReported,
      sampleCount: mouseSampleCount,
      threshold: mouseThreshold,
    })
  );
}

export function shouldSkipFingerprintReportAttempt({
  baseAlreadyReported,
  behaviorAlreadyReported,
  skipBaseReport,
  shouldReportBehavior,
}) {
  if (baseAlreadyReported && behaviorAlreadyReported) {
    return true;
  }
  if (baseAlreadyReported && !shouldReportBehavior) {
    return true;
  }
  if (!skipBaseReport) {
    return false;
  }
  return !shouldReportBehavior;
}

export function isKeystrokeCaptureTarget(target) {
  if (!target || typeof target !== 'object') {
    return false;
  }
  const tagName = String(target.tagName || '').toLowerCase();
  if (tagName !== 'input' && tagName !== 'textarea') {
    return false;
  }
  const type = String(target.type || '').toLowerCase();
  const fieldName = String(target.name || target.id || '').toLowerCase();
  const autocomplete = String(
    target.autocomplete || target.autoComplete || '',
  ).toLowerCase();
  if (type === 'hidden' || type === 'password') {
    return false;
  }
  if (fieldName === 'password' || fieldName === 'password2') {
    return false;
  }
  if (autocomplete === 'current-password' || autocomplete === 'new-password') {
    return false;
  }
  return !target.disabled && !target.readOnly;
}

export function resetFingerprintCollectorState(collector) {
  collector?.resetSessionState?.();
  collector?.resetBehaviorState?.();
}

export function resetFingerprintRuntimeState({
  collector,
  inFlightStore,
  userId,
  restartMouseCapture,
} = {}) {
  resetFingerprintCollectorState(collector);
  inFlightStore?.clear?.(userId);
  if (typeof restartMouseCapture === 'function') {
    restartMouseCapture();
  }
}

export function markFreshLoginKeystrokeSeed(seed) {
  if (!seed || typeof seed !== 'object') {
    return null;
  }

  const sampleCount = Number(seed.sampleCount || 0);
  if (!Number.isFinite(sampleCount) || sampleCount <= 0) {
    return null;
  }

  return {
    ...seed,
    __fresh_login_seed: true,
  };
}

export function shouldPreserveFreshLoginKeystrokeSeed(seed) {
  return Boolean(
    seed &&
    typeof seed === 'object' &&
    seed.__fresh_login_seed === true &&
    Number(seed.sampleCount || 0) > 0,
  );
}

export function createBehaviorRetryReportController({
  threshold,
  debounceMs,
  getSampleCount,
  isBehaviorReported,
  triggerReport,
}) {
  const normalizedThreshold = Number(threshold || 0);
  const normalizedDebounceMs = Math.max(0, Number(debounceMs || 0));
  const resolveSampleCount =
    typeof getSampleCount === 'function' ? getSampleCount : () => 0;
  const resolveBehaviorReported =
    typeof isBehaviorReported === 'function' ? isBehaviorReported : () => true;
  const runTriggerReport =
    typeof triggerReport === 'function'
      ? triggerReport
      : () => Promise.resolve();

  let timer = null;
  let inFlight = false;
  let disposed = false;

  const checkAndTrigger = async () => {
    if (disposed || inFlight || resolveBehaviorReported()) {
      return;
    }

    const sampleCount = Number(resolveSampleCount() || 0);
    if (!Number.isFinite(sampleCount) || sampleCount <= normalizedThreshold) {
      return;
    }

    inFlight = true;
    try {
      await Promise.resolve(runTriggerReport());
    } finally {
      inFlight = false;
    }
  };

  return {
    handleKeystrokeEvent() {
      if (disposed) {
        return;
      }
      if (timer) {
        clearTimeout(timer);
      }
      timer = setTimeout(() => {
        timer = null;
        void checkAndTrigger();
      }, normalizedDebounceMs);
    },
    flush() {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      return checkAndTrigger();
    },
    dispose() {
      disposed = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    },
  };
}

function normalizeFingerprintUserId(userId) {
  return String(userId || '0');
}

export function getFingerprintSessionReportedKey(userId) {
  const normalizedUserId = normalizeFingerprintUserId(userId);
  return `_napi_fp_reported:${normalizedUserId}`;
}

export function getFingerprintBehaviorReportedKey(userId, behaviorType = '') {
  const normalizedUserId = normalizeFingerprintUserId(userId);
  const normalizedBehaviorType = String(behaviorType || '').trim();
  if (!normalizedBehaviorType) {
    return `_napi_fp_behavior_reported:${normalizedUserId}`;
  }
  return `_napi_fp_behavior_reported:${normalizedUserId}:${normalizedBehaviorType}`;
}

export function getFingerprintKeystrokeSeedKey() {
  return '_napi_fp_keystroke_seed';
}

export function buildFingerprintBaseReportPayload(fingerprint) {
  if (!fingerprint || typeof fingerprint !== 'object') {
    return fingerprint;
  }

  const { keystroke, mouse, ...basePayload } = fingerprint;
  return basePayload;
}

export function buildFingerprintBehaviorReportPayload(
  fingerprint,
  { shouldReportKeystroke = false, shouldReportMouse = false } = {},
) {
  if (!fingerprint || typeof fingerprint !== 'object') {
    return null;
  }

  const payload = {
    ...(fingerprint.session_id ? { session_id: fingerprint.session_id } : {}),
    ...(fingerprint.session_start_at
      ? { session_start_at: fingerprint.session_start_at }
      : {}),
    ...(fingerprint.session_end_at
      ? { session_end_at: fingerprint.session_end_at }
      : {}),
    ...(shouldReportKeystroke && fingerprint.keystroke
      ? { keystroke: fingerprint.keystroke }
      : {}),
    ...(shouldReportMouse && fingerprint.mouse
      ? { mouse: fingerprint.mouse }
      : {}),
  };

  return payload.keystroke || payload.mouse ? payload : null;
}

export function buildFingerprintReportPostConfig(userId) {
  const normalizedUserId = String(userId || '').trim();
  if (!normalizedUserId || normalizedUserId === '0') {
    return {};
  }

  return {
    headers: {
      'New-API-User': normalizedUserId,
    },
  };
}

export async function submitFingerprintReports(
  fingerprint,
  {
    skipBaseReport = false,
    currentUid = '',
    shouldReportKeystroke = false,
    shouldReportMouse = false,
    postReport,
    setStorageItem,
    localStorageRef,
    sessionStorageRef,
    baseReportStorageTsKey,
    baseReportStorageUidKey,
    reportedKey,
    keystrokeReportedKey,
    mouseReportedKey,
    now = () => Date.now(),
  } = {},
) {
  if (!fingerprint || typeof fingerprint !== 'object') {
    return {
      postedBase: false,
      postedBehavior: false,
      preparedFingerprint: fingerprint,
      behaviorPayload: null,
    };
  }

  const runPostReport =
    typeof postReport === 'function' ? postReport : async () => undefined;
  const writeStorageItem =
    typeof setStorageItem === 'function' ? setStorageItem : () => undefined;
  const nowMs = Number(now()) || Date.now();
  const preparedFingerprint = {
    ...fingerprint,
    session_end_at: Math.floor(nowMs / 1000),
  };

  let postedBase = false;
  let postedBehavior = false;

  if (!skipBaseReport) {
    await runPostReport(
      '/api/fingerprint/report',
      buildFingerprintBaseReportPayload(preparedFingerprint),
      buildFingerprintReportPostConfig(currentUid),
    );
    postedBase = true;
    writeStorageItem(localStorageRef, baseReportStorageTsKey, String(nowMs));
    writeStorageItem(localStorageRef, baseReportStorageUidKey, currentUid);
    writeStorageItem(sessionStorageRef, reportedKey, '1');
  }

  const behaviorPayload = buildFingerprintBehaviorReportPayload(
    preparedFingerprint,
    {
      shouldReportKeystroke,
      shouldReportMouse,
    },
  );
  if (behaviorPayload) {
    await runPostReport(
      '/api/fingerprint/behavior',
      behaviorPayload,
      buildFingerprintReportPostConfig(currentUid),
    );
    postedBehavior = true;
    if (behaviorPayload.keystroke) {
      writeStorageItem(sessionStorageRef, keystrokeReportedKey, '1');
    }
    if (behaviorPayload.mouse) {
      writeStorageItem(sessionStorageRef, mouseReportedKey, '1');
    }
  }

  return {
    postedBase,
    postedBehavior,
    preparedFingerprint,
    behaviorPayload,
  };
}
