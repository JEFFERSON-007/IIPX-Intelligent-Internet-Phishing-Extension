/**
 * Multi-Layer LRU Cache Module
 * High-performance bounded caching with Time-To-Live (TTL) expiration,
 * implemented with an O(1) Doubly-Linked List + Hash Map LRU architecture.
 * @module MultiLayerCache
 */

class LRUNode {
  /**
   * @param {string} key 
   * @param {*} value 
   * @param {number} timestamp 
   */
  constructor(key, value, timestamp) {
    this.key = key;
    this.value = value;
    this.timestamp = timestamp;
    /** @type {LRUNode|null} */
    this.prev = null;
    /** @type {LRUNode|null} */
    this.next = null;
  }
}

export class MultiLayerCache {
  /**
   * Create a MultiLayerCache instance.
   * @param {number} [maxEntries=1000] - Maximum entry count.
   * @param {number} [ttlMs=1800000] - Time To Live in milliseconds (default 30 mins).
   */
  constructor(maxEntries = 1000, ttlMs = 30 * 60 * 1000) {
    /** @type {number} */
    this.maxEntries = maxEntries;
    /** @type {number} */
    this.ttlMs = ttlMs;

    /** @type {Map<string, LRUNode>} */
    this.map = new Map();

    // Sentinels for O(1) doubly-linked list operations
    this.head = new LRUNode('', null, 0);
    this.tail = new LRUNode('', null, 0);
    this.head.next = this.tail;
    this.tail.prev = this.head;

    /** @type {number} */
    this.hits = 0;
    /** @type {number} */
    this.misses = 0;
  }

  /**
   * Detach a node from its current position in the linked list.
   * @private
   * @param {LRUNode} node 
   */
  _detach(node) {
    node.prev.next = node.next;
    node.next.prev = node.prev;
  }

  /**
   * Insert a node directly after the head sentinel (most recently used).
   * @private
   * @param {LRUNode} node 
   */
  _attachHead(node) {
    node.next = this.head.next;
    node.prev = this.head;
    this.head.next.prev = node;
    this.head.next = node;
  }

  /**
   * Move an existing node to the head (most recently used).
   * @private
   * @param {LRUNode} node 
   */
  _moveToHead(node) {
    this._detach(node);
    this._attachHead(node);
  }

  /**
   * Retrieve item from cache if present and non-expired in O(1) time.
   * @param {string} key 
   * @returns {*|null} Cached item value or null if expired/absent.
   */
  get(key) {
    const node = this.map.get(key);
    if (!node) {
      this.misses++;
      return null;
    }

    const now = Date.now();
    if (now - node.timestamp > this.ttlMs) {
      this._detach(node);
      this.map.delete(key);
      this.misses++;
      return null;
    }

    this._moveToHead(node);
    this.hits++;
    return node.value;
  }

  /**
   * Insert or update item in LRU cache in O(1) time.
   * @param {string} key 
   * @param {*} value 
   */
  set(key, value) {
    const now = Date.now();
    let node = this.map.get(key);

    if (node) {
      node.value = value;
      node.timestamp = now;
      this._moveToHead(node);
      return;
    }

    if (this.map.size >= this.maxEntries) {
      // Evict least recently used (node right before tail sentinel)
      const lruNode = this.tail.prev;
      if (lruNode && lruNode !== this.head) {
        this._detach(lruNode);
        this.map.delete(lruNode.key);
      }
    }

    node = new LRUNode(key, value, now);
    this.map.set(key, node);
    this._attachHead(node);
  }

  /**
   * Check if active key exists without mutating hit statistics.
   * @param {string} key 
   * @returns {boolean}
   */
  has(key) {
    const node = this.map.get(key);
    if (!node) return false;

    if (Date.now() - node.timestamp > this.ttlMs) {
      this._detach(node);
      this.map.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Delete entry in O(1) time.
   * @param {string} key 
   * @returns {boolean}
   */
  delete(key) {
    const node = this.map.get(key);
    if (!node) return false;

    this._detach(node);
    return this.map.delete(key);
  }

  /**
   * Clear all entries and reset stats.
   */
  clear() {
    this.map.clear();
    this.head.next = this.tail;
    this.tail.prev = this.head;
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Evict all expired entries.
   */
  purgeExpired() {
    const now = Date.now();
    let current = this.tail.prev;

    while (current && current !== this.head) {
      const prevNode = current.prev;
      if (now - current.timestamp > this.ttlMs) {
        this._detach(current);
        this.map.delete(current.key);
      }
      current = prevNode;
    }
  }

  /**
   * Return cache health and hit-ratio metrics.
   * @returns {{ size: number, maxEntries: number, hits: number, misses: number, hitRatio: number }}
   */
  getStats() {
    const total = this.hits + this.misses;
    return {
      size: this.map.size,
      maxEntries: this.maxEntries,
      hits: this.hits,
      misses: this.misses,
      hitRatio: total > 0 ? parseFloat((this.hits / total).toFixed(4)) : 0.0
    };
  }
}

/**
 * Singleton instance providing specific siloes for caching.
 */
export const GlobalCache = {
  URLCache: new MultiLayerCache(500, 30 * 60 * 1000),     // 30 min TTL
  DomainCache: new MultiLayerCache(2000, 60 * 60 * 1000), // 1 hour TTL
  ResultCache: new MultiLayerCache(100, 5 * 60 * 1000),   // 5 min TTL
  
  clearAll() {
    this.URLCache.clear();
    this.DomainCache.clear();
    this.ResultCache.clear();
  },
  
  purgeExpiredAll() {
    this.URLCache.purgeExpired();
    this.DomainCache.purgeExpired();
    this.ResultCache.purgeExpired();
  }
};
