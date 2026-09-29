/**
 * Punycode & Unicode Confusables Utility
 * High-performance Punycode decoding (`xn--`), Unicode normalization (NFC/NFD),
 * and O(N) single-pass homograph character mapping using inverted lookup tables.
 * @module PunycodeUtils
 */

export class PunycodeUtils {
  /**
   * Confusable Unicode character mapping table (Cyrillic, Greek, Latin lookalikes).
   * @type {Record<string, string[]>}
   */
  static CONFUSABLES = Object.freeze({
    'a': ['а', 'ɑ', 'α', 'á', 'à', 'â', 'ä', 'ã', 'å'],
    'c': ['с', 'ϲ', 'ç', 'ć', 'č'],
    'e': ['е', 'ė', 'ē', 'é', 'è', 'ê', 'ë', 'ę'],
    'h': ['һ', 'ħ'],
    'i': ['і', 'ı', 'í', 'ì', 'î', 'ï'],
    'j': ['ј'],
    'o': ['о', 'ο', 'ó', 'ò', 'ô', 'ö', 'õ', 'ø'],
    'p': ['р', 'ρ'],
    's': ['ѕ', 'ś', 'š'],
    'x': ['х', 'χ'],
    'y': ['у', 'ү', 'ý', 'ÿ'],
    'b': ['ь']
  });

  /**
   * Character substitution dictionary (common visual spoofing).
   * @type {Record<string, string>}
   */
  static CHAR_SUBSTITUTIONS = Object.freeze({
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '9': 'g',
    '@': 'a',
    '$': 's'
  });

  /**
   * Precomputed inverted Map for O(1) character-to-Latin lookup.
   * @type {Map<string, string>}
   */
  static _INVERTED_CONFUSABLES = (() => {
    const map = new Map();
    for (const [latinChar, lookalikes] of Object.entries(PunycodeUtils.CONFUSABLES)) {
      for (const lookalike of lookalikes) {
        map.set(lookalike, latinChar);
      }
    }
    return map;
  })();

  /**
   * Precomputed RegExp for single-pass replacement of all confusables.
   * @type {RegExp}
   */
  static _CONFUSABLES_REGEX = (() => {
    const allLookalikes = [];
    for (const lookalikes of Object.values(PunycodeUtils.CONFUSABLES)) {
      allLookalikes.push(...lookalikes);
    }
    // Escape regex special chars if any
    const pattern = `[${allLookalikes.map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')}]`;
    return new RegExp(pattern, 'g');
  })();

  /**
   * Precomputed RegExp for single-pass replacement of visual substitutions.
   * @type {RegExp}
   */
  static _SUBSTITUTIONS_REGEX = /[01345789@$]/g;

  /**
   * Normalize string to standard NFC Unicode representation.
   * @param {string} str 
   * @returns {string}
   */
  static normalizeUnicode(str) {
    if (!str || typeof str !== 'string') return '';
    return str.normalize('NFC');
  }

  /**
   * Check if a domain contains Punycode encoding (`xn--`).
   * @param {string} domain 
   * @returns {boolean}
   */
  static isPunycode(domain) {
    if (!domain || typeof domain !== 'string') return false;
    return domain.toLowerCase().includes('xn--');
  }

  /**
   * Decode Punycode label into standard Unicode representation (browser native URL API).
   * @param {string} hostname 
   * @returns {string} Decoded Unicode domain string.
   */
  static decodePunycode(hostname) {
    if (!hostname) return '';
    try {
      // Modern URL constructor automatically decodes punycode hostnames
      const dummyUrl = new URL(`http://${hostname}`);
      return dummyUrl.hostname;
    } catch {
      return hostname;
    }
  }

  /**
   * Detect homograph spoofing characters in string in a single O(N) pass.
   * @param {string} str 
   * @returns {{ hasHomograph: boolean, detectedChars: Array<{ original: string, mappedTo: string }> }}
   */
  static detectHomographs(str) {
    const result = { hasHomograph: false, detectedChars: [] };
    if (!str || typeof str !== 'string') return result;

    const normalized = PunycodeUtils.normalizeUnicode(str);
    const lookup = PunycodeUtils._INVERTED_CONFUSABLES;
    const seen = new Set();

    // Single-pass O(N) character traversal
    for (let i = 0; i < normalized.length; i++) {
      const char = normalized[i];
      const mappedTo = lookup.get(char);
      if (mappedTo !== undefined && !seen.has(char)) {
        seen.add(char);
        result.hasHomograph = true;
        result.detectedChars.push({ original: char, mappedTo });
      }
    }

    return result;
  }

  /**
   * Normalize homographs by replacing confusable characters with their Latin equivalents in single pass.
   * @param {string} str 
   * @returns {string}
   */
  static normalizeHomographs(str) {
    if (!str || typeof str !== 'string') return '';
    const lookup = PunycodeUtils._INVERTED_CONFUSABLES;
    return str.replace(PunycodeUtils._CONFUSABLES_REGEX, (match) => lookup.get(match) || match);
  }

  /**
   * Replace visual substitutions (e.g. 0->o, 1->l, @->a) and homographs with standard Latin characters.
   * Runs in two single-pass linear replacements instead of 70 nested replaceAll passes.
   * @param {string} str 
   * @returns {string}
   */
  static replaceSubstitutions(str) {
    if (!str || typeof str !== 'string') return '';
    const homographClean = PunycodeUtils.normalizeHomographs(str.toLowerCase());
    const subs = PunycodeUtils.CHAR_SUBSTITUTIONS;
    return homographClean.replace(PunycodeUtils._SUBSTITUTIONS_REGEX, (match) => subs[match] || match);
  }
}
