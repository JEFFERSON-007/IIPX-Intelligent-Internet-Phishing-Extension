/**
 * Punycode & Unicode Confusables Utility
 * Handles Punycode decoding (`xn--`), Unicode normalization (NFC/NFD), and homograph character mapping.
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
   * Detect homograph spoofing characters in string.
   * @param {string} str 
   * @returns {{ hasHomograph: boolean, detectedChars: Array<{ original: string, mappedTo: string }> }}
   */
  static detectHomographs(str) {
    const result = { hasHomograph: false, detectedChars: [] };
    if (!str || typeof str !== 'string') return result;

    const normalized = PunycodeUtils.normalizeUnicode(str);

    for (const [latinChar, lookalikes] of Object.entries(PunycodeUtils.CONFUSABLES)) {
      for (const lookalike of lookalikes) {
        if (normalized.includes(lookalike)) {
          result.hasHomograph = true;
          result.detectedChars.push({ original: lookalike, mappedTo: latinChar });
        }
      }
    }

    return result;
  }

  /**
   * Normalize homographs by replacing confusable characters with their Latin equivalents.
   * @param {string} str 
   * @returns {string}
   */
  static normalizeHomographs(str) {
    if (!str || typeof str !== 'string') return '';
    let output = str;
    for (const [latinChar, lookalikes] of Object.entries(PunycodeUtils.CONFUSABLES)) {
      for (const lookalike of lookalikes) {
        if (output.includes(lookalike)) {
          output = output.replaceAll(lookalike, latinChar);
        }
      }
    }
    return output;
  }

  /**
   * Replace visual substitutions (e.g. 0->o, 1->l, @->a) and homographs with standard Latin characters.
   * @param {string} str 
   * @returns {string}
   */
  static replaceSubstitutions(str) {
    if (!str || typeof str !== 'string') return '';
    let output = PunycodeUtils.normalizeHomographs(str.toLowerCase());
    for (const [sub, target] of Object.entries(PunycodeUtils.CHAR_SUBSTITUTIONS)) {
      output = output.replaceAll(sub, target);
    }
    return output;
  }
}
