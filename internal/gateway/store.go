package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"open-democracy/chaincode/bill"
)

// PersistedStore wraps a bill.MemStore with synchronous JSON-file persistence.
// Every Put writes the full snapshot to disk so the dashboard survives restarts
// without an external database. The on-disk format is a stable JSON object
// with base64-encoded values, which keeps the file readable and avoids
// quoting issues with arbitrary bytes.
//
// This is intentionally simple: the bill ledger has a small footprint, all
// state mutations go through Service which marshals one bill at a time, and
// snapshot writes are atomic via rename. For higher throughput an embedded
// KV like bbolt would be a drop-in replacement of this file.
type PersistedStore struct {
	*bill.MemStore
	path     string
	writeMu  sync.Mutex // serializes flushes
	snapshot int        // monotonic counter for debugging only
}

// OpenStore loads (or creates) a PersistedStore at path.
func OpenStore(path string) (*PersistedStore, error) {
	mem := bill.NewMemStore()
	ps := &PersistedStore{MemStore: mem, path: path}
	if err := ps.load(); err != nil {
		return nil, err
	}
	return ps, nil
}

// Put writes through to memory then flushes the full snapshot to disk.
func (p *PersistedStore) Put(key string, value []byte) error {
	if err := p.MemStore.Put(key, value); err != nil {
		return err
	}
	return p.flush()
}

// Path returns the file backing this store.
func (p *PersistedStore) Path() string { return p.path }

func (p *PersistedStore) load() error {
	f, err := os.Open(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open store: %w", err)
	}
	defer f.Close()
	var encoded map[string]string
	if err := json.NewDecoder(f).Decode(&encoded); err != nil {
		return fmt.Errorf("decode store: %w", err)
	}
	out := make(map[string][]byte, len(encoded))
	for k, v := range encoded {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return fmt.Errorf("decode value at %s: %w", k, err)
		}
		out[k] = raw
	}
	p.MemStore.Load(out)
	return nil
}

func (p *PersistedStore) flush() error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	snap := p.MemStore.Snapshot()
	encoded := make(map[string]string, len(snap))
	for k, v := range snap {
		encoded[k] = base64.StdEncoding.EncodeToString(v)
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		return fmt.Errorf("ensure store dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.path), ".store-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp store: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(encoded); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("encode store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), p.path); err != nil {
		return fmt.Errorf("rename store: %w", err)
	}
	p.snapshot++
	return nil
}
