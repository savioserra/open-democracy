package gateway

import (
	"errors"
	"sync"

	"open-democracy/chaincode/bill"
)

// Participant is a known identity that the gateway can act as. It mirrors,
// in spirit, an X.509 certificate carrying scope claims, but uses pure data
// because the gateway runs the ledger in-process and does not need TLS auth
// for a local demo. The Display field is shown on the dashboard.
type Participant struct {
	ID      string   `json:"id"`
	Display string   `json:"display"`
	Claims  []string `json:"claims"`
}

// Invoker materializes the participant as a *bill.Invoker so it can be
// passed to the Service.
func (p Participant) Invoker() *bill.Invoker {
	return bill.NewInvoker(p.ID, p.Claims)
}

// Registry is the in-memory directory of all known participants. It is
// populated at startup from seed data and can be extended at runtime via
// AddParticipant. The dashboard renders this list and the API uses it to
// resolve the X-User header to a *bill.Invoker.
type Registry struct {
	mu      sync.RWMutex
	byID    map[string]Participant
	ordered []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]Participant{}}
}

// Add inserts a participant. If the id already exists, it is replaced.
func (r *Registry) Add(p Participant) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[p.ID]; !exists {
		r.ordered = append(r.ordered, p.ID)
	}
	r.byID[p.ID] = p
}

// Get returns a participant by id.
func (r *Registry) Get(id string) (Participant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[id]
	if !ok {
		return Participant{}, errors.New("unknown participant: " + id)
	}
	return p, nil
}

// List returns all participants in insertion order.
func (r *Registry) List() []Participant {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Participant, 0, len(r.ordered))
	for _, id := range r.ordered {
		out = append(out, r.byID[id])
	}
	return out
}
