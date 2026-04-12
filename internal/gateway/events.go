package gateway

import (
	"encoding/json"
	"sync"
	"time"
)

// Event is one domain event emitted by the bill Service. Payload is left as
// raw JSON so the dashboard can render arbitrary fields without needing a
// schema for every event type.
type Event struct {
	Seq     uint64          `json:"seq"`
	Time    time.Time       `json:"time"`
	Name    string          `json:"name"`
	Payload json.RawMessage `json:"payload"`
}

// Broadcaster fans events out to a ring buffer (for late subscribers and the
// /events page) and to any number of live channel subscribers (for SSE).
//
// It is intentionally bounded so a slow SSE consumer cannot wedge the
// in-process ledger; if a subscriber's channel is full the event is dropped
// for that subscriber but still recorded in history.
type Broadcaster struct {
	mu          sync.Mutex
	seq         uint64
	history     []Event
	historyCap  int
	subscribers map[chan Event]struct{}
}

// NewBroadcaster creates a Broadcaster keeping the last `historyCap` events
// in memory.
func NewBroadcaster(historyCap int) *Broadcaster {
	if historyCap <= 0 {
		historyCap = 200
	}
	return &Broadcaster{
		historyCap:  historyCap,
		subscribers: map[chan Event]struct{}{},
	}
}

// Emit implements bill.EventSink. It records the event and fans it out to
// every live subscriber that has room in their channel.
func (b *Broadcaster) Emit(name string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	ev := Event{Seq: b.seq, Time: time.Now().UTC(), Name: name, Payload: append(json.RawMessage(nil), payload...)}
	b.history = append(b.history, ev)
	if len(b.history) > b.historyCap {
		b.history = b.history[len(b.history)-b.historyCap:]
	}
	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			// drop for slow subscribers
		}
	}
	return nil
}

// Subscribe returns a channel that will receive future events. The caller
// must call Unsubscribe when done. Buffer is small but enough for browser
// consumers.
func (b *Broadcaster) Subscribe() chan Event {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a previously registered channel and closes it.
func (b *Broadcaster) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// History returns a copy of the recent event ring buffer in chronological
// order (oldest first). Used by the dashboard's events page on first load.
func (b *Broadcaster) History() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.history))
	copy(out, b.history)
	return out
}
