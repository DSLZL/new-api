/**
 * 指纹系统权限检查工具
 */

let _fpAccess = null;
let _checking = false;
let _checkPromise = null;

export async function checkFingerprintAccess() {
  if (_fpAccess !== null) return _fpAccess;
  if (_checking && _checkPromise) return _checkPromise;

  _checking = true;
  _checkPromise = (async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        _fpAccess = false;
        return false;
      }

      const resp = await fetch('/api/fingerprint/access', {
        headers: {
          Authorization: `Bearer ${token}`,
          'New-Api-User': localStorage.getItem('user_id') || '',
        },
      });
      const data = await resp.json();
      _fpAccess = data.success && data.has_access && data.enabled;
    } catch {
      _fpAccess = false;
    }
    _checking = false;
    return _fpAccess;
  })();

  return _checkPromise;
}

export function clearFPAccessCache() {
  _fpAccess = null;
  _checking = false;
  _checkPromise = null;
}

export function getCachedFPAccess() {
  return _fpAccess;
}