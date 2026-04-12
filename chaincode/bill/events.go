package bill

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// EventSink receives domain events emitted by the Service. In Fabric the sink
// forwards to ctx.GetStub().SetEvent; in the gateway process it can be a
// channel-based broadcaster powering the dashboard's live event feed.
type EventSink interface {
	Emit(name string, payload []byte) error
}

// stubEventSink adapts the Fabric chaincode stub's SetEvent to EventSink.
type stubEventSink struct {
	ctx contractapi.TransactionContextInterface
}

func newStubEventSink(ctx contractapi.TransactionContextInterface) EventSink {
	return &stubEventSink{ctx: ctx}
}

func (s *stubEventSink) Emit(name string, payload []byte) error {
	return s.ctx.GetStub().SetEvent(name, payload)
}

// nopEventSink discards events. Useful in tests where events are not asserted.
type nopEventSink struct{}

// NopEventSink returns a sink that ignores every emitted event.
func NopEventSink() EventSink { return nopEventSink{} }

func (nopEventSink) Emit(string, []byte) error { return nil }
