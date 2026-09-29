/**
 * Suffix Domain Trie Data Structure
 * Highly optimized Radix/Trie tree for fast O(L) domain and subdomain lookups,
 * where L is the number of domain labels (typically 2-4), completely independent
 * of the number of registered blocklist domains (N).
 * @module DomainTrie
 */

class TrieNode {
  constructor() {
    /** @type {Map<string, TrieNode>} */
    this.children = new Map();
    /** @type {boolean} Indicates if this node forms a complete registered blocked domain */
    this.isTerminal = false;
    /** @type {string|null} The canonical matched domain */
    this.domain = null;
  }
}

export class DomainTrie {
  constructor() {
    /** @type {TrieNode} */
    this.root = new TrieNode();
    /** @type {number} Total registered domains */
    this.size = 0;
  }

  /**
   * Insert a domain into the suffix trie.
   * Labels are stored reversed: e.g. "evil.example.com" -> ["com", "example", "evil"]
   * @param {string} domain 
   */
  insert(domain) {
    if (!domain || typeof domain !== 'string') return;
    const clean = domain.trim().toLowerCase();
    if (!clean) return;

    const labels = clean.split('.').reverse();
    let current = this.root;

    for (const label of labels) {
      if (!current.children.has(label)) {
        current.children.set(label, new TrieNode());
      }
      current = current.children.get(label);
    }

    if (!current.isTerminal) {
      current.isTerminal = true;
      current.domain = clean;
      this.size++;
    }
  }

  /**
   * Search for a hostname in the suffix trie.
   * Matches both exact domains and any subdomains:
   * e.g., if "evil.com" is in the trie:
   * - "evil.com" -> MATCH
   * - "sub.evil.com" -> MATCH
   * - "login.portal.evil.com" -> MATCH
   * - "not-evil.com" -> NO MATCH
   * @param {string} hostname 
   * @returns {{ matched: boolean, ruleDomain: string|null }}
   */
  match(hostname) {
    if (!hostname || typeof hostname !== 'string') {
      return { matched: false, ruleDomain: null };
    }

    const labels = hostname.trim().toLowerCase().split('.').reverse();
    let current = this.root;

    for (const label of labels) {
      if (!current.children.has(label)) {
        break;
      }
      current = current.children.get(label);

      // If we encounter a terminal node, any sub-levels belong to this blocked domain
      if (current.isTerminal) {
        return { matched: true, ruleDomain: current.domain };
      }
    }

    return { matched: false, ruleDomain: null };
  }

  /**
   * Batch insert an iterable of domains.
   * @param {Iterable<string>} domains 
   */
  insertAll(domains) {
    if (!domains) return;
    for (const domain of domains) {
      this.insert(domain);
    }
  }

  /**
   * Clear the entire trie.
   */
  clear() {
    this.root = new TrieNode();
    this.size = 0;
  }
}
