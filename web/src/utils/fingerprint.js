/**
 * 浏览器指纹采集 SDK
 * 采集多维度设备/环境特征用于多账号关联识别
 */

import { KeystrokeDynamics } from './keystroke';
import { MouseBehaviorTracker } from './mouse_tracker';

const PERSISTENT_ID_KEY = '_fp_sid';
const PERSISTENT_CACHE_NAME = '_fp_track';
const PERSISTENT_CACHE_URL = '/_fp_track_id';
const IDB_DB_NAME = '_fpDB';
const IDB_STORE_NAME = 'store';
const IDB_KEY_NAME = 'sid';
const SESSION_ID_KEY = '_napi_fp_session_id';
const SESSION_START_AT_KEY = '_napi_fp_session_start_at';

class PersistentTracker {
  constructor() {
    this.key = PERSISTENT_ID_KEY;
  }

  async getFromAnywhere() {
    const hits = [];

    const local = this.readLocalStorage();
    if (local) hits.push({ source: 'localStorage', id: local });

    const idb = await this.readIndexedDB();
    if (idb) hits.push({ source: 'indexedDB', id: idb });

    const cookie = this.readCookie();
    if (cookie) hits.push({ source: 'cookie', id: cookie });

    const cache = await this.readCacheAPI();
    if (cache) hits.push({ source: 'cache', id: cache });

    const session = this.readSessionStorage();
    if (session) hits.push({ source: 'sessionStorage', id: session });

    const first = hits[0];
    if (first?.id) {
      await this.selfHeal(first.id);
    }

    return {
      id: first?.id || '',
      idSource: first?.source || '',
      candidates: hits,
    };
  }

  async setEverywhere(id) {
    if (!id) return;
    this.writeLocalStorage(id);
    this.writeSessionStorage(id);
    this.writeCookie(id);
    await this.writeIndexedDB(id);
    await this.writeCacheAPI(id);
  }

  async selfHeal(validId) {
    if (!validId) return;
    await this.setEverywhere(validId);
  }

  readLocalStorage() {
    try {
      return localStorage.getItem(this.key) || '';
    } catch {
      return '';
    }
  }

  writeLocalStorage(id) {
    try {
      localStorage.setItem(this.key, id);
    } catch {
      // ignore
    }
  }

  readSessionStorage() {
    try {
      return sessionStorage.getItem(this.key) || '';
    } catch {
      return '';
    }
  }

  writeSessionStorage(id) {
    try {
      sessionStorage.setItem(this.key, id);
    } catch {
      // ignore
    }
  }

  readCookie() {
    try {
      const match = document.cookie.match(
        new RegExp('(^| )' + this.key + '=([^;]+)'),
      );
      return match ? match[2] : '';
    } catch {
      return '';
    }
  }

  writeCookie(id) {
    try {
      document.cookie = `${this.key}=${id};max-age=31536000;path=/;Secure;SameSite=Lax`;
    } catch {
      // ignore
    }
  }

  getIndexedDBHandle() {
    return new Promise((resolve) => {
      try {
        if (!window.indexedDB) {
          resolve(null);
          return;
        }
        const request = window.indexedDB.open(IDB_DB_NAME, 1);
        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(IDB_STORE_NAME)) {
            db.createObjectStore(IDB_STORE_NAME);
          }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
  }

  async readIndexedDB() {
    const db = await this.getIndexedDBHandle();
    if (!db) return '';

    return new Promise((resolve) => {
      try {
        const tx = db.transaction(IDB_STORE_NAME, 'readonly');
        const store = tx.objectStore(IDB_STORE_NAME);
        const req = store.get(IDB_KEY_NAME);
        req.onsuccess = () => resolve(req.result || '');
        req.onerror = () => resolve('');
        tx.oncomplete = () => db.close();
        tx.onerror = () => db.close();
      } catch {
        try {
          db.close();
        } catch {
          // ignore
        }
        resolve('');
      }
    });
  }

  async writeIndexedDB(id) {
    const db = await this.getIndexedDBHandle();
    if (!db) return;

    await new Promise((resolve) => {
      try {
        const tx = db.transaction(IDB_STORE_NAME, 'readwrite');
        tx.objectStore(IDB_STORE_NAME).put(id, IDB_KEY_NAME);
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
      } catch {
        resolve();
      }
    });

    try {
      db.close();
    } catch {
      // ignore
    }
  }

  async readCacheAPI() {
    try {
      if (!window.caches) return '';
      const cache = await caches.open(PERSISTENT_CACHE_NAME);
      const response = await cache.match(PERSISTENT_CACHE_URL);
      if (!response) return '';
      return (await response.text()) || '';
    } catch {
      return '';
    }
  }

  async writeCacheAPI(id) {
    try {
      if (!window.caches) return;
      const cache = await caches.open(PERSISTENT_CACHE_NAME);
      await cache.put(PERSISTENT_CACHE_URL, new Response(id));
    } catch {
      // ignore
    }
  }
}

class FingerprintCollector {
  constructor() {
    this.persistentTracker = new PersistentTracker();
    this.keystrokeCollector = new KeystrokeDynamics();
    this.mouseCollector = new MouseBehaviorTracker();
  }

  generateSafeUUID() {
    if (
      typeof crypto !== 'undefined' &&
      typeof crypto.randomUUID === 'function'
    ) {
      return crypto.randomUUID();
    }
    return this.generateUUID();
  }

  getStorageItem(storage, key) {
    try {
      return storage.getItem(key) || '';
    } catch {
      return '';
    }
  }

  setStorageItem(storage, key, value) {
    try {
      storage.setItem(key, value);
    } catch {
      // ignore
    }
  }

  removeStorageItem(storage, key) {
    try {
      storage.removeItem(key);
    } catch {
      // ignore
    }
  }

  getOrCreateSessionState() {
    const existingId = this.getStorageItem(sessionStorage, SESSION_ID_KEY);
    const existingStartAt = Number.parseInt(
      this.getStorageItem(sessionStorage, SESSION_START_AT_KEY),
      10,
    );

    if (existingId && Number.isFinite(existingStartAt) && existingStartAt > 0) {
      return {
        sessionId: existingId,
        sessionStartAt: existingStartAt,
      };
    }

    const sessionId = this.generateSafeUUID();
    const sessionStartAt = Math.floor(Date.now() / 1000);
    this.setStorageItem(sessionStorage, SESSION_ID_KEY, sessionId);
    this.setStorageItem(
      sessionStorage,
      SESSION_START_AT_KEY,
      String(sessionStartAt),
    );

    return {
      sessionId,
      sessionStartAt,
    };
  }

  resetSessionState() {
    this.removeStorageItem(sessionStorage, SESSION_ID_KEY);
    this.removeStorageItem(sessionStorage, SESSION_START_AT_KEY);
  }

  resetBehaviorState() {
    if (this.keystrokeCollector) {
      this.keystrokeCollector.detachAll();
      this.keystrokeCollector.reset();
    }
    if (this.mouseCollector) {
      this.mouseCollector.stop();
      this.mouseCollector.reset();
    }
  }

  normalizeKeystrokePayload(keystroke) {
    if (!keystroke || typeof keystroke !== 'object') {
      return null;
    }

    const sampleCount = Number(keystroke.sampleCount || 0);
    if (!Number.isFinite(sampleCount) || sampleCount <= 0) {
      return null;
    }

    return {
      avgHoldTime: Number(keystroke.avgHoldTime || 0),
      stdHoldTime: Number(keystroke.stdHoldTime || 0),
      avgFlightTime: Number(keystroke.avgFlightTime || 0),
      stdFlightTime: Number(keystroke.stdFlightTime || 0),
      typingSpeed: Number(keystroke.typingSpeed || 0),
      commonDigraphs: Array.isArray(keystroke.commonDigraphs)
        ? keystroke.commonDigraphs.slice(0, 10)
        : [],
      sampleCount,
    };
  }

  mergeKeystrokeSeed(keystrokeSeed) {
    if (!keystrokeSeed || typeof keystrokeSeed !== 'object') {
      return;
    }

    if (typeof keystrokeSeed.__captureTarget === 'object') {
      this.keystrokeCollector.startCapture(keystrokeSeed.__captureTarget);
      return;
    }

    if (Array.isArray(keystrokeSeed.__captureTargets)) {
      keystrokeSeed.__captureTargets.forEach((target) => {
        if (target && typeof target === 'object') {
          this.keystrokeCollector.startCapture(target);
        }
      });
      return;
    }

    const payload = this.normalizeKeystrokePayload(keystrokeSeed);
    if (!payload) {
      return;
    }

    this.keystrokeCollector.reset();
    this.keystrokeCollector.holdDurations = new Array(payload.sampleCount).fill(
      Number(payload.avgHoldTime || 0),
    );
    this.keystrokeCollector.flightDurations = new Array(
      Math.max(payload.sampleCount - 1, 0),
    ).fill(Number(payload.avgFlightTime || 0));
    this.keystrokeCollector.keydownCount = payload.sampleCount;
    this.keystrokeCollector.firstEventTime = 0;
    this.keystrokeCollector.lastEventTime = payload.sampleCount;

    const digraphBuckets = new Map();
    payload.commonDigraphs.forEach((item) => {
      if (!item || !item.digraph) {
        return;
      }
      const count = Number(item.sampleCount || 1);
      if (!Number.isFinite(count) || count <= 0) {
        return;
      }
      const avgFlightTime = Number(item.avgFlightTime || 0);
      digraphBuckets.set(
        String(item.digraph),
        new Array(count).fill(avgFlightTime),
      );
    });
    this.keystrokeCollector.digraphBuckets = digraphBuckets;
  }

  getDNSProbeDomainSuffix() {
    const sanitized = (
      import.meta.env.VITE_FINGERPRINT_DNS_PROBE_DOMAIN_SUFFIX || ''
    )
      .trim()
      .replace(/^https?:\/\//, '')
      .replace(/^\/+/, '')
      .replace(/\/+$/, '');
    if (!/^[a-z0-9.-]+$/i.test(sanitized) || !sanitized.includes('.')) {
      return '';
    }
    return sanitized;
  }

  triggerDNSProbe() {
    const domainSuffix = this.getDNSProbeDomainSuffix();
    if (!domainSuffix) {
      return '';
    }

    const probeId = this.generateSafeUUID();
    const url = `https://${probeId}.${domainSuffix}/pixel.gif`;

    try {
      void fetch(url, {
        method: 'GET',
        mode: 'no-cors',
        cache: 'no-store',
        credentials: 'omit',
        keepalive: true,
      }).catch(() => undefined);
      return probeId;
    } catch {
      return '';
    }
  }

  async triggerETagTracking() {
    try {
      const response = await fetch('/api/static/fp.js', {
        cache: 'default',
        credentials: 'same-origin',
      });
      const etag = response.headers.get('ETag') || '';
      return etag.replace(/^W\//, '').replace(/"/g, '');
    } catch {
      return '';
    }
  }

  async getWebRTCIPs() {
    if (typeof window === 'undefined' || !window.RTCPeerConnection) {
      return { localIPs: [], publicIPs: [] };
    }

    return new Promise((resolve) => {
      const localSet = new Set();
      const publicSet = new Set();
      let settled = false;

      const finalize = (rtc) => {
        if (settled) return;
        settled = true;
        try {
          rtc.close();
        } catch {
          // ignore
        }
        resolve({
          localIPs: Array.from(localSet),
          publicIPs: Array.from(publicSet),
        });
      };

      const classify = (ip) => {
        if (!ip || ip === '0.0.0.0' || ip.endsWith('.local')) {
          return;
        }
        if (this.isPrivateIPv4(ip)) {
          localSet.add(ip);
          return;
        }
        publicSet.add(ip);
      };

      try {
        const rtc = new RTCPeerConnection({
          iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
        });

        rtc.createDataChannel('fp');
        rtc.onicecandidate = (event) => {
          if (!event.candidate || !event.candidate.candidate) {
            finalize(rtc);
            return;
          }
          const candidate = event.candidate.candidate;
          const ipv4Matches = candidate.match(/(?:\d{1,3}\.){3}\d{1,3}/g) || [];
          ipv4Matches.forEach(classify);
        };

        rtc
          .createOffer()
          .then((offer) => rtc.setLocalDescription(offer))
          .catch(() => finalize(rtc));

        setTimeout(() => finalize(rtc), 3000);
      } catch {
        resolve({ localIPs: [], publicIPs: [] });
      }
    });
  }

  isPrivateIPv4(ip) {
    if (!ip || !ip.includes('.')) return false;
    const parts = ip.split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) {
      return false;
    }

    if (parts[0] === 10) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31;
  }

  async primePersistenceAfterLogin() {
    const { id } = await this.persistentTracker.getFromAnywhere();
    if (id) {
      await this.persistentTracker.selfHeal(id);
      return id;
    }

    const fallback = this.getOrCreateDeviceId();
    await this.persistentTracker.setEverywhere(fallback);
    return fallback;
  }

  normalizeMousePayload(mouse) {
    if (!mouse || typeof mouse !== 'object') {
      return null;
    }

    const sampleCount = Number(mouse.sampleCount || 0);
    if (!Number.isFinite(sampleCount) || sampleCount <= 0) {
      return null;
    }

    const clickDistribution = mouse.clickDistribution;
    const normalizedClickDistribution =
      clickDistribution && typeof clickDistribution === 'object'
        ? {
            topLeft: Number(clickDistribution.topLeft || 0),
            topRight: Number(clickDistribution.topRight || 0),
            bottomLeft: Number(clickDistribution.bottomLeft || 0),
            bottomRight: Number(clickDistribution.bottomRight || 0),
          }
        : {
            topLeft: 0,
            topRight: 0,
            bottomLeft: 0,
            bottomRight: 0,
          };

    return {
      avgSpeed: Number(mouse.avgSpeed || 0),
      maxSpeed: Number(mouse.maxSpeed || 0),
      speedStd: Number(mouse.speedStd || 0),
      avgAcceleration: Number(mouse.avgAcceleration || 0),
      accStd: Number(mouse.accStd || 0),
      directionChangeRate: Number(mouse.directionChangeRate || 0),
      avgScrollDelta: Number(mouse.avgScrollDelta || 0),
      scrollDeltaMode: Number(mouse.scrollDeltaMode || 0),
      clickDistribution: normalizedClickDistribution,
      sampleCount,
    };
  }

  async collect(options = {}) {
    try {
      const {
        userId = 0,
        keystroke = null,
        keystrokeSeed = null,
        mouse = null,
      } = options;
      this.mergeKeystrokeSeed(keystrokeSeed);
      const [
        canvas,
        webgl,
        webglDeep,
        audio,
        fonts,
        clientRects,
        mediaDevices,
        speechVoices,
        webrtc,
        etagID,
        persistentState,
      ] = await Promise.allSettled([
        this.getCanvasFingerprint(),
        this.getWebGLFingerprint(),
        this.getDeepWebGLFingerprint(),
        this.getAudioFingerprint(),
        this.getFontsFingerprint(),
        this.getClientRectsFingerprint(),
        this.getMediaDevicesFingerprint(),
        this.getSpeechVoicesFingerprint(),
        this.getWebRTCIPs(),
        this.triggerETagTracking(),
        this.persistentTracker.getFromAnywhere(),
      ]);

      const hardware = this.getHardwareInfo();
      const environment = this.getEnvironmentInfo();
      const localDeviceId = this.getOrCreateDeviceId();
      const sessionState = this.getOrCreateSessionState();
      const dnsProbeID = userId ? this.triggerDNSProbe() : '';
      const mergedKeystroke = this.normalizeKeystrokePayload(keystroke);
      const dynamicKeystroke = this.normalizeKeystrokePayload(
        this.keystrokeCollector.getFingerprint(),
      );
      const keystrokePayload =
        dynamicKeystroke &&
        (!mergedKeystroke ||
          dynamicKeystroke.sampleCount >= mergedKeystroke.sampleCount)
          ? dynamicKeystroke
          : mergedKeystroke;
      const mergedMouse = this.normalizeMousePayload(mouse);
      const dynamicMouse = this.normalizeMousePayload(
        this.mouseCollector.getFingerprint(),
      );
      const mousePayload =
        dynamicMouse &&
        (!mergedMouse || dynamicMouse.sampleCount >= mergedMouse.sampleCount)
          ? dynamicMouse
          : mergedMouse;

      const persistentId =
        persistentState.status === 'fulfilled' && persistentState.value.id
          ? persistentState.value.id
          : localDeviceId;
      const persistentSource =
        persistentState.status === 'fulfilled'
          ? persistentState.value.idSource || 'generated'
          : 'generated';
      const mediaDevicesData =
        mediaDevices.status === 'fulfilled'
          ? mediaDevices.value
          : {
              deviceCount: '',
              deviceIdHash: '',
              groupIdHash: '',
              totalDevices: 0,
            };
      const speechVoicesData =
        speechVoices.status === 'fulfilled'
          ? speechVoices.value
          : {
              voiceHash: '',
              voiceCount: 0,
              localVoiceCount: 0,
            };

      await this.persistentTracker.setEverywhere(persistentId);

      const fingerprint = {
        canvas_hash: canvas.status === 'fulfilled' ? canvas.value.hash : '',
        webgl_hash: webgl.status === 'fulfilled' ? webgl.value.hash : '',
        webgl_deep_hash:
          webglDeep.status === 'fulfilled' ? webglDeep.value.hash : '',
        client_rects_hash:
          clientRects.status === 'fulfilled' ? clientRects.value.hash : '',
        webgl_vendor: webgl.status === 'fulfilled' ? webgl.value.vendor : '',
        webgl_renderer:
          webglDeep.status === 'fulfilled' && webglDeep.value.renderer
            ? webglDeep.value.renderer
            : webgl.status === 'fulfilled'
              ? webgl.value.renderer
              : '',
        media_devices_hash: mediaDevicesData.deviceIdHash,
        media_device_count: mediaDevicesData.deviceCount,
        media_device_group_hash: mediaDevicesData.groupIdHash,
        media_device_total: mediaDevicesData.totalDevices,
        speech_voices_hash: speechVoicesData.voiceHash,
        speech_voice_count: speechVoicesData.voiceCount,
        speech_local_voice_count: speechVoicesData.localVoiceCount,
        audio_hash: audio.status === 'fulfilled' ? audio.value.hash : '',
        fonts_hash: fonts.status === 'fulfilled' ? fonts.value.hash : '',
        fonts_list: fonts.status === 'fulfilled' ? fonts.value.list : '',
        screen_width: hardware.screenWidth,
        screen_height: hardware.screenHeight,
        color_depth: hardware.colorDepth,
        pixel_ratio: hardware.pixelRatio,
        cpu_cores: hardware.cpuCores,
        device_memory: hardware.deviceMemory,
        max_touch: hardware.maxTouch,
        timezone: environment.timezone,
        tz_offset: environment.tzOffset,
        languages: environment.languages,
        platform: environment.platform,
        do_not_track: environment.dnt,
        cookie_enabled: environment.cookieEnabled,
        local_device_id: localDeviceId,
        persistent_id: persistentId,
        id_source: persistentSource,
        etag_id: etagID.status === 'fulfilled' ? etagID.value : '',
        webrtc_local_ips:
          webrtc.status === 'fulfilled' ? webrtc.value.localIPs : [],
        webrtc_public_ips:
          webrtc.status === 'fulfilled' ? webrtc.value.publicIPs : [],
        dns_resolver_ip: '',
        dns_probe_id: dnsProbeID,
        session_id: sessionState.sessionId,
        session_start_at: sessionState.sessionStartAt,
        session_end_at: sessionState.sessionStartAt,
      };

      if (keystrokePayload) {
        fingerprint.keystroke = keystrokePayload;
      }
      if (mousePayload) {
        fingerprint.mouse = mousePayload;
      }

      fingerprint.composite_hash = await this.computeCompositeHash(fingerprint);
      return fingerprint;
    } catch (e) {
      console.debug('Fingerprint collection error:', e);
      return null;
    }
  }

  // Canvas 指纹
  async getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    canvas.width = 280;
    canvas.height = 60;
    const ctx = canvas.getContext('2d');
    if (!ctx) return { hash: '' };

    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(100, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.font = '11pt "Times New Roman"';
    ctx.fillText('Cwm fjordbank gly', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.font = '18pt Arial';
    ctx.fillText('Cwm fjordbank gly', 4, 45);

    ctx.globalCompositeOperation = 'multiply';
    ctx.fillStyle = 'rgb(255,0,255)';
    ctx.beginPath();
    ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();

    const dataUrl = canvas.toDataURL();
    const hash = await this.sha256(dataUrl);
    return { hash };
  }

  // WebGL 指纹
  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl =
        canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { hash: '', vendor: '', renderer: '' };

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
        : '';
      const renderer = debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
        : '';

      const params = {
        vendor,
        renderer,
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS)),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        extensions: gl.getSupportedExtensions()?.sort() || [],
      };

      const hash = this.simpleHash(JSON.stringify(params));
      return { hash, vendor, renderer };
    } catch {
      return { hash: '', vendor: '', renderer: '' };
    }
  }

  getWebGLPrecisionSignature(gl) {
    const shaderTypes = [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER];
    const precisionTypes = [
      gl.LOW_FLOAT,
      gl.MEDIUM_FLOAT,
      gl.HIGH_FLOAT,
      gl.LOW_INT,
      gl.MEDIUM_INT,
      gl.HIGH_INT,
    ];
    const signature = [];

    shaderTypes.forEach((shaderType) => {
      precisionTypes.forEach((precisionType) => {
        const format = gl.getShaderPrecisionFormat(shaderType, precisionType);
        if (!format) {
          signature.push('0:0:0');
          return;
        }
        signature.push(
          `${format.rangeMin}:${format.rangeMax}:${format.precision}`,
        );
      });
    });

    return signature;
  }

  getDeepWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl =
        canvas.getContext('webgl2') ||
        canvas.getContext('webgl') ||
        canvas.getContext('experimental-webgl');
      if (!gl) {
        return {
          hash: '',
          renderer: '',
          vendor: '',
          extensionCount: 0,
          maxTextureSize: 0,
        };
      }

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
        : '';
      const renderer = debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
        : '';

      const supportedExtensions = (gl.getSupportedExtensions() || [])
        .slice()
        .sort();
      const params = {
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        vendor,
        renderer,
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxCubeMapTextureSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxViewportDims: Array.from(
          gl.getParameter(gl.MAX_VIEWPORT_DIMS) || [],
        ),
        maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
        maxCombinedTextureImageUnits: gl.getParameter(
          gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS,
        ),
        maxTextureImageUnits: gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS),
        maxVertexTextureImageUnits: gl.getParameter(
          gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS,
        ),
        maxFragmentUniformVectors: gl.getParameter(
          gl.MAX_FRAGMENT_UNIFORM_VECTORS,
        ),
        antialias: !!gl.getContextAttributes()?.antialias,
        precisionSignature: this.getWebGLPrecisionSignature(gl),
        extensions: supportedExtensions,
      };

      const hash = this.simpleHash(JSON.stringify(params));
      return {
        hash,
        renderer,
        vendor,
        extensionCount: supportedExtensions.length,
        maxTextureSize: Number(params.maxTextureSize) || 0,
      };
    } catch {
      return {
        hash: '',
        renderer: '',
        vendor: '',
        extensionCount: 0,
        maxTextureSize: 0,
      };
    }
  }

  async getClientRectsFingerprint() {
    try {
      if (!document.body) {
        return { hash: '' };
      }

      const fontFamilies = ['monospace', 'sans-serif', 'serif', 'cursive'];
      const testStrings = [
        'mmmmmmmmmmlli',
        'The quick brown fox jumps',
        'WMwi1lI0O',
        'あいうえお',
      ];

      const container = document.createElement('div');
      container.style.position = 'absolute';
      container.style.left = '-9999px';
      container.style.top = '0';
      container.style.visibility = 'hidden';
      container.style.pointerEvents = 'none';

      const measurements = [];
      document.body.appendChild(container);

      try {
        for (const fontFamily of fontFamilies) {
          for (const text of testStrings) {
            const span = document.createElement('span');
            span.style.fontFamily = fontFamily;
            span.style.fontSize = '16px';
            span.style.lineHeight = 'normal';
            span.style.position = 'absolute';
            span.style.left = '-9999px';
            span.textContent = text;
            container.appendChild(span);

            const rect = span.getBoundingClientRect();
            measurements.push({
              fontFamily,
              text,
              width: rect.width,
              height: rect.height,
            });
          }
        }
      } finally {
        container.remove();
      }

      const payload = JSON.stringify(measurements);
      const hash = await this.sha256(payload);
      return { hash };
    } catch {
      return { hash: '' };
    }
  }

  async getMediaDevicesFingerprint() {
    try {
      const mediaDevices = navigator.mediaDevices;
      if (!mediaDevices?.enumerateDevices) {
        return {
          deviceCount: '',
          deviceIdHash: '',
          groupIdHash: '',
          totalDevices: 0,
        };
      }

      const devices = await mediaDevices.enumerateDevices();
      if (!Array.isArray(devices) || devices.length === 0) {
        return {
          deviceCount: '0-0-0',
          deviceIdHash: '',
          groupIdHash: '',
          totalDevices: 0,
        };
      }

      const counts = {
        audioinput: 0,
        audiooutput: 0,
        videoinput: 0,
      };
      const deviceIds = [];
      const groupIds = new Set();

      devices.forEach((device) => {
        if (!device?.kind) return;
        if (Object.prototype.hasOwnProperty.call(counts, device.kind)) {
          counts[device.kind] += 1;
        }
        if (device.deviceId) {
          deviceIds.push(device.deviceId);
        }
        if (device.groupId) {
          groupIds.add(device.groupId);
        }
      });

      return {
        deviceCount: `${counts.audioinput}-${counts.audiooutput}-${counts.videoinput}`,
        deviceIdHash: deviceIds.length
          ? await this.sha256(deviceIds.slice().sort().join('|'))
          : '',
        groupIdHash: groupIds.size
          ? await this.sha256(Array.from(groupIds).sort().join('|'))
          : '',
        totalDevices: devices.length,
      };
    } catch {
      return {
        deviceCount: '',
        deviceIdHash: '',
        groupIdHash: '',
        totalDevices: 0,
      };
    }
  }

  async getSpeechVoicesFingerprint() {
    try {
      if (typeof window === 'undefined' || !window.speechSynthesis) {
        return { voiceHash: '', voiceCount: 0, localVoiceCount: 0 };
      }

      const synth = window.speechSynthesis;
      const normalizeVoices = async (voices) => {
        const normalized = (voices || [])
          .map((voice) => ({
            name: voice?.name || '',
            lang: voice?.lang || '',
            localService: !!voice?.localService,
          }))
          .filter((voice) => voice.name || voice.lang);

        const localVoiceCount = normalized.filter(
          (voice) => voice.localService,
        ).length;
        const serialized = normalized
          .map(
            (voice) =>
              `${voice.name}|${voice.lang}|${voice.localService ? 1 : 0}`,
          )
          .sort();

        return {
          voiceHash: serialized.length
            ? await this.sha256(serialized.join('||'))
            : '',
          voiceCount: normalized.length,
          localVoiceCount,
        };
      };

      const immediate = synth.getVoices();
      if (immediate?.length) {
        return await normalizeVoices(immediate);
      }

      return await new Promise((resolve) => {
        let settled = false;
        const finalize = async (voices) => {
          if (settled) return;
          settled = true;
          synth.removeEventListener?.('voiceschanged', handleVoicesChanged);
          resolve(await normalizeVoices(voices));
        };
        const handleVoicesChanged = () => {
          finalize(synth.getVoices());
        };

        synth.addEventListener?.('voiceschanged', handleVoicesChanged);
        setTimeout(() => {
          finalize(synth.getVoices());
        }, 2000);
      });
    } catch {
      return { voiceHash: '', voiceCount: 0, localVoiceCount: 0 };
    }
  }

  // AudioContext 指纹
  async getAudioFingerprint() {
    try {
      const AudioCtx =
        window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AudioCtx) return { hash: '' };

      const ctx = new AudioCtx(1, 44100, 44100);
      const oscillator = ctx.createOscillator();
      oscillator.type = 'triangle';
      oscillator.frequency.setValueAtTime(10000, ctx.currentTime);

      const compressor = ctx.createDynamicsCompressor();
      compressor.threshold.setValueAtTime(-50, ctx.currentTime);
      compressor.knee.setValueAtTime(40, ctx.currentTime);
      compressor.ratio.setValueAtTime(12, ctx.currentTime);
      compressor.attack.setValueAtTime(0, ctx.currentTime);
      compressor.release.setValueAtTime(0.25, ctx.currentTime);

      oscillator.connect(compressor);
      compressor.connect(ctx.destination);
      oscillator.start(0);

      const buffer = await ctx.startRendering();
      const data = buffer.getChannelData(0);
      const slice = data.slice(4500, 5000);
      const hash = await this.sha256(slice.toString());
      return { hash };
    } catch {
      return { hash: '' };
    }
  }

  // 字体检测
  getFontsFingerprint() {
    try {
      const testFonts = [
        'Arial',
        'Arial Black',
        'Comic Sans MS',
        'Courier New',
        'Georgia',
        'Impact',
        'Lucida Console',
        'Microsoft YaHei',
        'SimHei',
        'SimSun',
        'PingFang SC',
        'Hiragino Sans GB',
        'Helvetica Neue',
        'Menlo',
        'Consolas',
        'Palatino',
        'Trebuchet MS',
        'Verdana',
        'Tahoma',
        'Segoe UI',
        'Ubuntu',
        'Cantarell',
        'Fira Sans',
        'Source Han Sans',
      ];

      const baseFonts = ['monospace', 'sans-serif', 'serif'];
      const testString = 'mmmmmmmmmmlli';
      const testSize = '72px';

      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (!ctx) return { hash: '', list: '' };

      const getTextWidth = (font) => {
        ctx.font = `${testSize} ${font}`;
        return ctx.measureText(testString).width;
      };

      const baseWidths = baseFonts.map((f) => getTextWidth(f));
      const detected = testFonts.filter((font) => {
        return baseFonts.some((base, i) => {
          return getTextWidth(`"${font}", ${base}`) !== baseWidths[i];
        });
      });

      const list = detected.join(',');
      return {
        hash: this.simpleHash(list),
        list: list,
      };
    } catch {
      return { hash: '', list: '' };
    }
  }

  // 硬件信息
  getHardwareInfo() {
    return {
      screenWidth: screen.width || 0,
      screenHeight: screen.height || 0,
      colorDepth: screen.colorDepth || 0,
      pixelRatio: window.devicePixelRatio || 1,
      cpuCores: navigator.hardwareConcurrency || 0,
      deviceMemory: navigator.deviceMemory || 0,
      maxTouch: navigator.maxTouchPoints || 0,
    };
  }

  // 环境信息
  getEnvironmentInfo() {
    return {
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
      tzOffset: new Date().getTimezoneOffset(),
      languages: JSON.stringify(
        navigator.languages || [navigator.language || ''],
      ),
      platform: navigator.platform || '',
      dnt: navigator.doNotTrack || '',
      cookieEnabled: navigator.cookieEnabled !== false,
    };
  }

  // 持久化设备ID (多重存储)
  getOrCreateDeviceId() {
    const key = '_napi_did';
    let id = null;

    try {
      id = localStorage.getItem(key);
    } catch {}
    if (!id) {
      try {
        id = sessionStorage.getItem(key);
      } catch {}
    }
    if (!id) {
      id = this.getCookie(key);
    }

    if (!id) {
      id = this.generateSafeUUID();
    }

    // 写入多个存储位置
    try {
      localStorage.setItem(key, id);
    } catch {}
    try {
      sessionStorage.setItem(key, id);
    } catch {}
    try {
      document.cookie = `${key}=${id};max-age=31536000;path=/;SameSite=Lax`;
    } catch {}

    return id;
  }

  // Composite hash
  async computeCompositeHash(fp) {
    const key = [
      fp.canvas_hash,
      fp.webgl_hash,
      fp.audio_hash,
      fp.fonts_hash,
      fp.screen_width + 'x' + fp.screen_height,
      fp.cpu_cores,
      fp.timezone,
      fp.platform,
    ].join('|');
    return await this.sha256(key);
  }

  // SHA-256
  async sha256(data) {
    try {
      const encoder = new TextEncoder();
      const buffer = await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(String(data)),
      );
      return Array.from(new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    } catch {
      return this.simpleHash(String(data));
    }
  }

  // 简单 hash (降级方案)
  simpleHash(data) {
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(16, '0');
  }

  getCookie(name) {
    const match = document.cookie.match(
      new RegExp('(^| )' + name + '=([^;]+)'),
    );
    return match ? match[2] : null;
  }

  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }
}

const fingerprintCollector = new FingerprintCollector();
export default fingerprintCollector;
