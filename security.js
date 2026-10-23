(function (root) {
  'use strict';

  const REQUIRED_KEYS = ['unit', 'corridor', 'chamber_c', 'ambient_c', 'battery_pct', 'delay_m', 'ts'];
  const ALLOWED_KEYS = new Set(REQUIRED_KEYS);
  const INJECTION_PATTERN = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)|system\s+prompt|disable\s+(the\s+)?(alarm|guard|firewall)|drop\s+table|<\s*script\b|javascript\s*:/i;

  function detectInjection(value) {
    if (typeof value !== 'string') return false;
    return INJECTION_PATTERN.test(value);
  }

  function validateTelemetry(packet) {
    const errors = [];
    if (!packet || typeof packet !== 'object' || Array.isArray(packet)) {
      return { ok: false, errors: ['Packet must be a JSON object.'] };
    }
    for (const key of Object.keys(packet)) {
      if (!ALLOWED_KEYS.has(key)) errors.push(`Unexpected field: ${key}`);
    }
    for (const key of REQUIRED_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(packet, key) || packet[key] === undefined || packet[key] === null) {
        errors.push(`Missing required field: ${key}`);
      }
    }
    for (const key of ['unit', 'corridor']) {
      if (typeof packet[key] !== 'string' || packet[key].trim().length < 1 || packet[key].length > 80) {
        errors.push(`${key} must be a non-empty string up to 80 characters.`);
      } else if (detectInjection(packet[key])) {
        errors.push(`${key} contains suspicious instruction text.`);
      }
    }
    const numericBounds = {
      chamber_c: [-80, 80],
      ambient_c: [-80, 80],
      battery_pct: [0, 100],
      delay_m: [0, 1440]
    };
    for (const [key, [min, max]] of Object.entries(numericBounds)) {
      const value = packet[key];
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        errors.push(`${key} must be a finite number.`);
      } else if (value < min || value > max) {
        errors.push(`${key} must be between ${min} and ${max}.`);
      }
    }
    if (typeof packet.ts !== 'string' || !Number.isFinite(Date.parse(packet.ts))) {
      errors.push('ts must be a valid timestamp string.');
    }
    for (const [key, value] of Object.entries(packet)) {
      if (typeof value === 'string' && detectInjection(value)) {
        errors.push(`${key} contains suspicious instruction text.`);
      }
    }
    return { ok: errors.length === 0, errors: [...new Set(errors)] };
  }

  function calculateRisk({ temp, ambient, battery, delay, safeMaxTemp }) {
    const values = [temp, ambient, battery, delay, safeMaxTemp];
    if (!values.every(Number.isFinite)) throw new TypeError('Risk inputs must be finite numbers.');
    if (battery < 0 || battery > 100 || delay < 0 || delay > 1440 || safeMaxTemp < -80 || safeMaxTemp > 80) {
      throw new RangeError('Risk inputs are outside supported bounds.');
    }
    const thermalGradient = Math.max(0.5, (ambient - temp) * 0.045);
    const tempExcess = Math.max(0, temp - safeMaxTemp);
    return Math.max(12, Math.min(240, Math.round(95 - (tempExcess * 11) - (thermalGradient * 14) - (delay * 0.35) + Math.max(0, battery - 50) * 0.05)));
  }

  const api = Object.freeze({ detectInjection, validateTelemetry, calculateRisk });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.KavachSecurity = api;
})(typeof window !== 'undefined' ? window : globalThis);
