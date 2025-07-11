/*
 * Copyright (c) 2015, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.util;

import org.checkerframework.checker.nullness.qual.Nullable;

import java.sql.SQLException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Caches values in simple least-recently-accessed order.
 */
@SuppressWarnings("ExtendsObject")
public class LruCache<Key extends Object, Value extends CanEstimateSize>
    implements Gettable<Key, Value> {
  /**
   * Action that is invoked when the entry is removed from the cache.
   *
   * @param <Value> type of the cache entry
   */
  public interface EvictAction<Value> {
    void evict(Value value) throws SQLException;
  }

  /**
   * When the entry is not present in cache, this create action is used to create one.
   *
   * @param <Value> type of the cache entry
   */
  public interface CreateAction<Key, Value> {
    Value create(Key key) throws SQLException;
  }

  private final @Nullable EvictAction<Value> onEvict;
  private final @Nullable CreateAction<Key, Value> createAction;
  private final int maxSizeEntries;
  private final long maxSizeBytes;
  private long currentSize;
  private final Map<Key, Value> cache;

  private class LimitedMap extends LinkedHashMap<Key, Value> {
    LimitedMap(int initialCapacity, float loadFactor, boolean accessOrder) {
      super(initialCapacity, loadFactor, accessOrder);
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<Key, Value> eldest) {
      // Avoid creating iterators if size constraints not violated
      if (size() <= maxSizeEntries && currentSize <= maxSizeBytes) {
        return false;
      }

      Iterator<Map.Entry<Key, Value>> it = entrySet().iterator();
      while (it.hasNext()) {
        if (size() <= maxSizeEntries && currentSize <= maxSizeBytes) {
          return false;
        }

        Map.Entry<Key, Value> entry = it.next();
        evictValue(entry.getValue());
        long valueSize = entry.getValue().getSize();
        if (valueSize > 0) {
          // just in case
          currentSize -= valueSize;
        }
        it.remove();
      }
      return false;
    }
  }

  private void evictValue(Value value) {
    try {
      if (onEvict != null) {
        onEvict.evict(value);
      }
    } catch (SQLException e) {
      /* ignore */
    }
  }

  public LruCache(int maxSizeEntries, long maxSizeBytes, boolean accessOrder) {
    this(maxSizeEntries, maxSizeBytes, accessOrder, null, null);
  }

  public LruCache(int maxSizeEntries, long maxSizeBytes, boolean accessOrder,
      @Nullable CreateAction<Key, Value> createAction,
      @Nullable EvictAction<Value> onEvict) {
    this.maxSizeEntries = maxSizeEntries;
    this.maxSizeBytes = maxSizeBytes;
    this.createAction = createAction;
    this.onEvict = onEvict;
    this.cache = new LimitedMap(16, 0.75f, accessOrder);
  }

  /**
   * Returns an entry from the cache.
   *
   * @param key cache key
   * @return entry from cache or null if cache does not contain given key.
   */
  @Override
  public @Nullable Value get(Key key) {
    Map<Key, Value> cache = this.cache;
    synchronized (cache) {
      return cache.get(key);
    }
  }

  /**
   * Borrows an entry from the cache.
   *
   * @param key cache key
   * @return entry from cache or newly created entry if cache does not contain given key.
   * @throws SQLException if entry creation fails
   */
  public Value borrow(Key key) throws SQLException {
    Map<Key, Value> cache = this.cache;
    synchronized (cache) {
      Value value = cache.remove(key);
      if (value == null) {
        if (createAction == null) {
          throw new UnsupportedOperationException("createAction == null, so can't create object");
        }
        return createAction.create(key);
      }
      currentSize -= value.getSize();
      return value;
    }
  }

  /**
   * Returns given value to the cache.
   *
   * @param key key
   * @param value value
   */
  public void put(Key key, Value value) {
    Map<Key, Value> cache = this.cache;
    synchronized (cache) {
      long valueSize = value.getSize();
      if (maxSizeBytes == 0 || maxSizeEntries == 0 || valueSize * 2 > maxSizeBytes) {
        // Just destroy the value if cache is disabled or if entry would consume more than a half of
        // the cache
        evictValue(value);
        return;
      }
      currentSize += valueSize;
      @Nullable Value prev = cache.put(key, value);
      if (prev == null) {
        return;
      }
      // This should be a rare case
      currentSize -= prev.getSize();
      if (prev != value) {
        evictValue(prev);
      }
    }
  }

  /**
   * Puts all the values from the given map into the cache.
   *
   * @param m The map containing entries to put into the cache
   */
  public void putAll(Map<Key, Value> m) {
    Map<Key, Value> cache = this.cache;
    synchronized (cache) {
      for (Map.Entry<Key, Value> entry : m.entrySet()) {
        this.put(entry.getKey(), entry.getValue());
      }
    }
  }
}
