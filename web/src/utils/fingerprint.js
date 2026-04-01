/**
 * 浏览器指纹采集 SDK
 * 采集多维度设备/环境特征用于多账号关联识别
 */

class FingerprintCollector {
  async collect() {
    try {
      const [canvas, webgl, audio, fonts] = await Promise.allSettled([
        this.getCanvasFingerprint(),
        this.getWebGLFingerprint(),
        this.getAudioFingerprint(),
        this.getFontsFingerprint(),
      ]);

      const hardware = this.getHardwareInfo();
      const environment = this.getEnvironmentInfo();
      const deviceId = this.getOrCreateDeviceId();

      const fingerprint = {
        canvas_hash: canvas.status === 'fulfilled' ? canvas.value.hash : '',
        webgl_hash: webgl.status === 'fulfilled' ? webgl.value.hash : '',
        webgl_vendor: webgl.status === 'fulfilled' ? webgl.value.vendor : '',
        webgl_renderer:
          webgl.status === 'fulfilled' ? webgl.value.renderer : '',
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
        local_device_id: deviceId,
      };

      fingerprint.composite_hash =
        await this.computeCompositeHash(fingerprint);
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
        canvas.getContext('webgl') ||
        canvas.getContext('experimental-webgl');
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
        shadingLanguageVersion: gl.getParameter(
          gl.SHADING_LANGUAGE_VERSION,
        ),
        extensions: gl.getSupportedExtensions()?.sort() || [],
      };

      const hash = this.simpleHash(JSON.stringify(params));
      return { hash, vendor, renderer };
    } catch {
      return { hash: '', vendor: '', renderer: '' };
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
      id = crypto.randomUUID
        ? crypto.randomUUID()
        : this.generateUUID();
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
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(
      /[xy]/g,
      (c) => {
        const r = (Math.random() * 16) | 0;
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
      },
    );
  }
}

const fingerprintCollector = new FingerprintCollector();
export default fingerprintCollector;