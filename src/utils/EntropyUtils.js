/**
 * Entropy & String Metrics Utility
 * Advanced mathematics engine for Shannon Entropy, Levenshtein Distance, and Keyboard Proximity.
 * Highly optimized with typed arrays, bounded DP matrices, and zero-allocation fast paths.
 * @module EntropyUtils
 */

export class EntropyUtils {
  // Reusable ASCII frequency buffer to eliminate garbage collection overhead in hot loops
  static _asciiFreqBuffer = new Uint16Array(256);

  /**
   * Calculate Shannon Entropy of a string (bits per character).
   * High entropy (>4.2) often indicates randomly generated / DGA / obfuscated domains.
   * Optimized with static typed buffer for ASCII inputs.
   * @param {string} str - Input string.
   * @returns {number} Entropy value between 0.0 and 8.0.
   */
  static calculateShannonEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) {
      return 0;
    }

    const len = str.length;
    let hasNonAscii = false;

    // Check if input is standard ASCII (valid for 99.9% of domain names)
    for (let i = 0; i < len; i++) {
      if (str.charCodeAt(i) > 255) {
        hasNonAscii = true;
        break;
      }
    }

    if (!hasNonAscii) {
      const buffer = EntropyUtils._asciiFreqBuffer;
      buffer.fill(0);

      for (let i = 0; i < len; i++) {
        buffer[str.charCodeAt(i)]++;
      }

      let entropy = 0;
      for (let i = 0; i < 256; i++) {
        const count = buffer[i];
        if (count > 0) {
          const p = count / len;
          entropy -= p * Math.log2(p);
        }
      }

      return parseFloat(entropy.toFixed(4));
    }

    // Fallback for full Unicode strings
    const frequencies = new Map();
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(4));
  }

  /**
   * Calculate Levenshtein Distance between two strings.
   * Optimized to O(min(M, N)) space with optional threshold-bounded early exit.
   * @param {string} strA - First string.
   * @param {string} strB - Second string.
   * @param {number} [maxDistance=Infinity] - Optional cutoff threshold. If distance exceeds this, returns maxDistance + 1 early.
   * @returns {number} Minimum edit operations.
   */
  static calculateLevenshteinDistance(strA, strB, maxDistance = Infinity) {
    if (strA === strB) return 0;
    if (!strA || !strA.length) return strB ? strB.length : 0;
    if (!strB || !strB.length) return strA.length;

    let a = strA;
    let b = strB;
    let lenA = a.length;
    let lenB = b.length;

    // Length difference fast-pruning
    const lengthDiff = Math.abs(lenA - lenB);
    if (lengthDiff > maxDistance) {
      return maxDistance + 1;
    }

    // Ensure 'b' is the shorter string to minimize O(min(M, N)) memory buffer
    if (lenA < lenB) {
      const tempStr = a; a = b; b = tempStr;
      const tempLen = lenA; lenA = lenB; lenB = tempLen;
    }

    // Two 1D rows instead of full (M+1)*(N+1) 2D matrix
    let prevRow = new Int32Array(lenB + 1);
    let currRow = new Int32Array(lenB + 1);

    for (let j = 0; j <= lenB; j++) {
      prevRow[j] = j;
    }

    for (let i = 1; i <= lenA; i++) {
      currRow[0] = i;
      const charA = a.charCodeAt(i - 1);
      let minInRow = currRow[0];

      for (let j = 1; j <= lenB; j++) {
        const cost = charA === b.charCodeAt(j - 1) ? 0 : 1;
        const deletion = prevRow[j] + 1;
        const insertion = currRow[j - 1] + 1;
        const substitution = prevRow[j - 1] + cost;

        let res = deletion < insertion ? deletion : insertion;
        if (substitution < res) res = substitution;

        currRow[j] = res;
        if (res < minInRow) minInRow = res;
      }

      // Early break if the entire row exceeds maxDistance threshold
      if (minInRow > maxDistance) {
        return maxDistance + 1;
      }

      // Swap rows
      const temp = prevRow;
      prevRow = currRow;
      currRow = temp;
    }

    return prevRow[lenB];
  }

  /**
   * Pre-computed set of QWERTY adjacent pairs for O(1) membership checks.
   * @type {Set<string>}
   */
  static _adjacentPairSet = (() => {
    const rawNeighbors = {
      'q': ['w', 'a'], 'w': ['q', 'e', 's', 'a'], 'e': ['w', 'r', 'd', 's'],
      'r': ['e', 't', 'f', 'd'], 't': ['r', 'y', 'g', 'f'], 'y': ['t', 'u', 'h', 'g'],
      'u': ['y', 'i', 'j', 'h'], 'i': ['u', 'o', 'k', 'j'], 'o': ['i', 'p', 'l', 'k'],
      'p': ['o', 'l'], 'a': ['q', 'w', 's', 'z'], 's': ['a', 'w', 'e', 'd', 'z', 'x'],
      'd': ['s', 'e', 'r', 'f', 'x', 'c'], 'f': ['d', 'r', 't', 'g', 'c', 'v'],
      'g': ['f', 't', 'y', 'h', 'v', 'b'], 'h': ['g', 'y', 'u', 'j', 'b', 'n'],
      'j': ['h', 'u', 'i', 'k', 'n', 'm'], 'k': ['j', 'i', 'o', 'l', 'm'],
      'l': ['k', 'o', 'p'], 'z': ['a', 's', 'x'], 'x': ['z', 's', 'd', 'c'],
      'c': ['x', 'd', 'f', 'v'], 'v': ['c', 'f', 'g', 'b'], 'b': ['v', 'g', 'h', 'n'],
      'n': ['b', 'h', 'j', 'm'], 'm': ['n', 'j', 'k']
    };

    const set = new Set();
    for (const [key, neighbors] of Object.entries(rawNeighbors)) {
      for (const n of neighbors) {
        set.add(`${key}:${n}`);
      }
    }
    return set;
  })();

  /**
   * Check if two characters are adjacent on a QWERTY keyboard in O(1) time.
   * @param {string} charA 
   * @param {string} charB 
   * @returns {boolean}
   */
  static isKeyboardAdjacent(charA, charB) {
    if (!charA || !charB) return false;
    const a = charA.toLowerCase();
    const b = charB.toLowerCase();
    if (a === b) return true;
    return EntropyUtils._adjacentPairSet.has(`${a}:${b}`);
  }
}
