import { useEffect, useRef } from 'react';
import fingerprintCollector from '../utils/fingerprint';
import { API } from '../helpers';

const REPORT_INTERVAL = 24 * 60 * 60 * 1000; // 24小时

async function doReport() {
  // ── 会话级去重：防止 effect + event 双重触发 ──
  if (sessionStorage.getItem('_napi_fp_reported')) {
    return;
  }

  // ── 跨会话去重：同一用户 24 小时内不重复上报 ──
  // 无痕模式下 localStorage 为空，此条件不会命中 → 始终允许上报
  const lastReport = localStorage.getItem('_napi_fp_ts');
  const lastUid = localStorage.getItem('_napi_fp_uid');
  let currentUid = '0';
  try {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    currentUid = String(user.id || '0');
  } catch {
    // ignore
  }
  // 同一用户 24h 内跳过；不同用户立即上报
  if (
    lastReport &&
    lastUid === currentUid &&
    Date.now() - parseInt(lastReport) < REPORT_INTERVAL
  ) {
    return;
  }

  try {
    const fp = await fingerprintCollector.collect();
    if (!fp) return;
    await API.post('/api/fingerprint/report', fp);
    localStorage.setItem('_napi_fp_ts', Date.now().toString());
    localStorage.setItem('_napi_fp_uid', currentUid);
    sessionStorage.setItem('_napi_fp_reported', '1');
  } catch (e) {
    console.debug('FP report skipped:', e?.message);
  }
}

export function useFingerprint(userId) {
  const reported = useRef(false);
  const timerRef = useRef(null);

  // ── 主路径：userId 从 0 变为有效值时触发 ──
  useEffect(() => {
    if (!userId || reported.current) return;
    reported.current = true;
    // 延迟 3 秒采集，不阻塞页面渲染
    timerRef.current = setTimeout(doReport, 3000);
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
      // 清除会话标记，允许本次登录重新上报
      sessionStorage.removeItem('_napi_fp_reported');
      if (loginTimer) clearTimeout(loginTimer);
      loginTimer = setTimeout(doReport, 1000);
    };
    window.addEventListener('napi:user-login', onLogin);
    return () => {
      window.removeEventListener('napi:user-login', onLogin);
      if (loginTimer) clearTimeout(loginTimer);
    };
  }, []);
export function useFingerprint(userId) {
  const reported = useRef(false);

  useEffect(() => {
    if (!userId || reported.current) return;

    // 检查上次上报时间
    const lastReport = localStorage.getItem('_napi_fp_ts');
    if (lastReport && Date.now() - parseInt(lastReport) < REPORT_INTERVAL) {
      return;
    }

    const report = async () => {
      try {
        const fp = await fingerprintCollector.collect();
        if (!fp) return;

        await API.post('/api/fingerprint/report', fp);
        localStorage.setItem('_napi_fp_ts', Date.now().toString());
        reported.current = true;
      } catch (e) {
        // 静默失败，不影响用户体验
        console.debug('FP report skipped:', e?.message);
      }
    };

    // 延迟3秒采集，不阻塞页面渲染
    const timer = setTimeout(report, 3000);
    return () => clearTimeout(timer);
  }, [userId]);
}