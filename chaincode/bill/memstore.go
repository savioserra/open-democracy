package bill

import (
	"strings"
	"sync"
)

// MemStore is an in-memory implementation of Store. It is safe for concurrent
// use and is intended for tests and the in-process gateway. The gateway wraps
// it with disk persistence; tests can use it directly.
type MemStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{data: map[string][]byte{}}
}

// Get returns the value for key, or nil if missing.
func (m *MemStore) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// Put stores value at key. The slice is copied to insulate callers from
// later mutations.
func (m *MemStore) Put(key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

// Exists reports whether the key has a non-empty value.
func (m *MemStore) Exists(key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	return ok && len(v) > 0, nil
}

// ScanByPrefix returns every key/value pair whose key starts with prefix.
func (m *MemStore) ScanByPrefix(prefix string) ([]KV, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]KV, 0)
	for k, v := range m.data {
		if strings.HasPrefix(k, prefix) {
			cp := make([]byte, len(v))
			copy(cp, v)
			out = append(out, KV{Key: k, Value: cp})
		}
	}
	return out, nil
}

// Snapshot returns a copy of every key/value pair held by the store.
// It is used by the gateway's persistence layer.
func (m *MemStore) Snapshot() map[string][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]byte, len(m.data))
	for k, v := range m.data {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// Load replaces the store contents with the given snapshot. Used by the
// gateway's persistence layer at startup.
func (m *MemStore) Load(snap map[string][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string][]byte, len(snap))
	for k, v := range snap {
		cp := make([]byte, len(v))
		copy(cp, v)
		m.data[k] = cp
	}
}
