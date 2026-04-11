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

const MAX_DIGRAPH_BUCKETS = 256;
const TOP_DIGRAPH_LIMIT = 10;

function toSafeNumber(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return 0;
  }
  return num;
}

function getTimingStats(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return { avg: 0, std: 0 };
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
    std: Math.sqrt(Math.max(variance, 0)),
  };
}

function classifyKey(event) {
  const key = String(event?.key || '').trim();
  const code = String(event?.code || '').trim();

  if (key.length === 1) {
    if (/[0-9]/.test(key)) {
      return 'digit';
    }
    if (/[a-z]/i.test(key)) {
      return 'alpha';
    }
  }

  if (code.startsWith('Digit')) {
    return 'digit';
  }
  if (code.startsWith('Key')) {
    return 'alpha';
  }

  if (key === ' ' || code === 'Space') {
    return 'space';
  }

  if (key === 'Enter') {
    return 'enter';
  }

  if (key === 'Backspace') {
    return 'backspace';
  }

  if (key === 'Tab') {
    return 'tab';
  }

  if (key.startsWith('Arrow')) {
    return 'arrow';
  }

  if (key.length > 1) {
    return 'control';
  }

  return 'other';
}

export class KeystrokeDynamics {
  constructor() {
    this.activeElements = new Map();
    this.reset();
  }

  reset() {
    this.holdDurations = [];
    this.flightDurations = [];
    this.keydownTimes = new Map();
    this.lastKeydownTime = 0;
    this.lastKeyClass = '';
    this.firstEventTime = 0;
    this.lastEventTime = 0;
    this.keydownCount = 0;
    this.digraphBuckets = new Map();
  }

  detachAll() {
    for (const [element, handlers] of this.activeElements.entries()) {
      element.removeEventListener('keydown', handlers.keydown);
      element.removeEventListener('keyup', handlers.keyup);
    }
    this.activeElements.clear();
  }

  startCapture(inputElement) {
    if (!inputElement || typeof inputElement.addEventListener !== 'function') {
      return;
    }
    const tagName = String(inputElement.tagName || '').toLowerCase();
    const inputType = String(inputElement.type || '').toLowerCase();
    if (
      tagName === 'input' &&
      (inputType === 'hidden' || inputType === 'password')
    ) {
      return;
    }
    if (this.activeElements.has(inputElement)) {
      return;
    }

    const onKeydown = (event) => {
      if (!event || event.isComposing || event.defaultPrevented) {
        return;
      }

      const now = toSafeNumber(event.timeStamp);
      if (now < 0) {
        return;
      }

      if (this.firstEventTime === 0 && this.keydownCount === 0) {
        this.firstEventTime = now;
      }
      this.lastEventTime = now;

      const uniqueCode = String(event.code || event.key || '');
      if (!this.keydownTimes.has(uniqueCode)) {
        this.keydownTimes.set(uniqueCode, now);
      }

      const keyClass = classifyKey(event);
      if (this.keydownCount > 0 && this.lastKeydownTime >= 0) {
        const flight = now - this.lastKeydownTime;
        if (flight >= 0 && flight <= 5000) {
          this.flightDurations.push(flight);

          if (this.lastKeyClass && keyClass) {
            const digraph = `${this.lastKeyClass}->${keyClass}`;
            const existing = this.digraphBuckets.get(digraph) || [];
            if (existing.length < MAX_DIGRAPH_BUCKETS) {
              this.digraphBuckets.set(digraph, existing.concat(flight));
            }
          }
        }
      }

      this.lastKeydownTime = now;
      this.lastKeyClass = keyClass;
      this.keydownCount += 1;
    };

    const onKeyup = (event) => {
      if (!event || event.isComposing || event.defaultPrevented) {
        return;
      }

      const now = toSafeNumber(event.timeStamp);
      if (now < 0) {
        return;
      }
      this.lastEventTime = now;

      const uniqueCode = String(event.code || event.key || '');
      const downTime = this.keydownTimes.get(uniqueCode);
      if (downTime === undefined) {
        return;
      }
      this.keydownTimes.delete(uniqueCode);

      const hold = now - downTime;
      if (hold >= 0 && hold <= 5000) {
        this.holdDurations.push(hold);
      }
    };

    inputElement.addEventListener('keydown', onKeydown);
    inputElement.addEventListener('keyup', onKeyup);
    this.activeElements.set(inputElement, {
      keydown: onKeydown,
      keyup: onKeyup,
    });
  }

  getFingerprint() {
    const holdStats = getTimingStats(this.holdDurations);
    const flightStats = getTimingStats(this.flightDurations);

    const durationMs = Math.max(this.lastEventTime - this.firstEventTime, 1);
    const durationSeconds = durationMs / 1000;
    const typingSpeed =
      durationSeconds > 0 ? this.keydownCount / durationSeconds : 0;

    const commonDigraphs = Array.from(this.digraphBuckets.entries())
      .map(([digraph, values]) => {
        const stats = getTimingStats(values);
        return {
          digraph,
          avgFlightTime: stats.avg,
          stdFlightTime: stats.std,
          sampleCount: values.length,
        };
      })
      .sort((a, b) => {
        if (b.sampleCount === a.sampleCount) {
          return a.digraph.localeCompare(b.digraph);
        }
        return b.sampleCount - a.sampleCount;
      })
      .slice(0, TOP_DIGRAPH_LIMIT);

    return {
      avgHoldTime: holdStats.avg,
      stdHoldTime: holdStats.std,
      avgFlightTime: flightStats.avg,
      stdFlightTime: flightStats.std,
      commonDigraphs,
      typingSpeed,
      sampleCount: this.holdDurations.length,
    };
  }
}
