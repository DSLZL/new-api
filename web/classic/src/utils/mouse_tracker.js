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

const MOUSE_SAMPLE_INTERVAL_MS = 50;
const SCROLL_BUCKET_LIMIT = 64;

function toSafeNumber(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return 0;
  }
  return num;
}

function getStats(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return { avg: 0, max: 0, std: 0 };
  }
  const sum = values.reduce((acc, current) => acc + current, 0);
  const avg = sum / values.length;
  const variance =
    values.reduce(
      (acc, current) => acc + (current - avg) * (current - avg),
      0,
    ) / values.length;
  return {
    avg,
    max: Math.max(...values),
    std: Math.sqrt(Math.max(variance, 0)),
  };
}

function normalizeScrollDeltaMode(modeMap) {
  let bestMode = 0;
  let bestCount = 0;
  for (const [mode, count] of modeMap.entries()) {
    if (count > bestCount || (count === bestCount && mode < bestMode)) {
      bestMode = mode;
      bestCount = count;
    }
  }
  return bestMode;
}

function emptyClickDistribution() {
  return {
    topLeft: 0,
    topRight: 0,
    bottomLeft: 0,
    bottomRight: 0,
  };
}

export class MouseBehaviorTracker {
  constructor() {
    this.activeTarget = null;
    this.handlers = null;
    this.reset();
  }

  reset() {
    this.samples = [];
    this.speeds = [];
    this.accelerations = [];
    this.directionChangeCount = 0;
    this.totalAngles = 0;
    this.scrollDeltas = [];
    this.scrollModeCounts = new Map();
    this.clickCounts = {
      topLeft: 0,
      topRight: 0,
      bottomLeft: 0,
      bottomRight: 0,
    };
    this.lastSampleAt = -1;
    this.lastPoint = null;
    this.lastVectorAngle = null;
  }

  stop() {
    if (!this.activeTarget || !this.handlers) {
      return;
    }
    this.activeTarget.removeEventListener('mousemove', this.handlers.mousemove);
    this.activeTarget.removeEventListener('click', this.handlers.click);
    this.activeTarget.removeEventListener('wheel', this.handlers.wheel);
    this.activeTarget = null;
    this.handlers = null;
  }

  start(target = window) {
    if (!target || typeof target.addEventListener !== 'function') {
      return;
    }
    if (this.activeTarget === target && this.handlers) {
      return;
    }
    this.stop();

    const onMouseMove = (event) => {
      if (!event || event.defaultPrevented) {
        return;
      }
      const timeStamp = toSafeNumber(event.timeStamp);
      if (
        this.lastSampleAt >= 0 &&
        timeStamp - this.lastSampleAt < MOUSE_SAMPLE_INTERVAL_MS
      ) {
        return;
      }

      const point = {
        x: toSafeNumber(event.clientX),
        y: toSafeNumber(event.clientY),
        t: timeStamp,
      };
      this.lastSampleAt = timeStamp;
      this.samples.push(point);

      if (!this.lastPoint) {
        this.lastPoint = point;
        return;
      }

      const dt = point.t - this.lastPoint.t;
      if (dt <= 0) {
        this.lastPoint = point;
        return;
      }

      const dx = point.x - this.lastPoint.x;
      const dy = point.y - this.lastPoint.y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      const speed = (distance / dt) * 1000;
      if (Number.isFinite(speed) && speed >= 0) {
        const previousSpeed = this.speeds[this.speeds.length - 1];
        this.speeds.push(speed);
        if (Number.isFinite(previousSpeed)) {
          const acceleration = Math.abs(speed - previousSpeed) / (dt / 1000);
          if (Number.isFinite(acceleration)) {
            this.accelerations.push(acceleration);
          }
        }
      }

      if (distance > 0) {
        const angle = Math.atan2(dy, dx);
        if (Number.isFinite(this.lastVectorAngle)) {
          this.totalAngles += 1;
          const delta = Math.abs(angle - this.lastVectorAngle);
          const normalized = Math.min(delta, Math.abs(2 * Math.PI - delta));
          if (normalized > Math.PI / 4) {
            this.directionChangeCount += 1;
          }
        }
        this.lastVectorAngle = angle;
      }

      this.lastPoint = point;
    };

    const onClick = (event) => {
      if (!event || event.defaultPrevented) {
        return;
      }
      const width = toSafeNumber(event.view?.innerWidth) || 1;
      const height = toSafeNumber(event.view?.innerHeight) || 1;
      const x = toSafeNumber(event.clientX);
      const y = toSafeNumber(event.clientY);
      const horizontal = x < width / 2 ? 'Left' : 'Right';
      const vertical = y < height / 2 ? 'top' : 'bottom';
      const key = `${vertical}${horizontal}`;
      if (Object.hasOwn(this.clickCounts, key)) {
        this.clickCounts[key] += 1;
      }
    };

    const onWheel = (event) => {
      if (!event || event.defaultPrevented) {
        return;
      }
      const delta = Math.abs(toSafeNumber(event.deltaY));
      if (delta > 0) {
        if (this.scrollDeltas.length < SCROLL_BUCKET_LIMIT) {
          this.scrollDeltas.push(delta);
        }
        const mode = Math.max(0, Math.floor(toSafeNumber(event.deltaMode)));
        this.scrollModeCounts.set(
          mode,
          (this.scrollModeCounts.get(mode) || 0) + 1,
        );
      }
    };

    target.addEventListener('mousemove', onMouseMove);
    target.addEventListener('click', onClick);
    target.addEventListener('wheel', onWheel);
    this.activeTarget = target;
    this.handlers = {
      mousemove: onMouseMove,
      click: onClick,
      wheel: onWheel,
    };
  }

  getFingerprint() {
    const speedStats = getStats(this.speeds);
    const accStats = getStats(this.accelerations);
    const totalClicks = Object.values(this.clickCounts).reduce(
      (acc, current) => acc + current,
      0,
    );
    const clickDistribution = emptyClickDistribution();
    if (totalClicks > 0) {
      Object.keys(clickDistribution).forEach((key) => {
        clickDistribution[key] = this.clickCounts[key] / totalClicks;
      });
    }

    const scrollStats = getStats(this.scrollDeltas);

    return {
      avgSpeed: speedStats.avg,
      maxSpeed: speedStats.max,
      speedStd: speedStats.std,
      avgAcceleration: accStats.avg,
      accStd: accStats.std,
      directionChangeRate:
        this.totalAngles > 0 ? this.directionChangeCount / this.totalAngles : 0,
      avgScrollDelta: scrollStats.avg,
      scrollDeltaMode: normalizeScrollDeltaMode(this.scrollModeCounts),
      clickDistribution,
      sampleCount: this.samples.length,
    };
  }
}
