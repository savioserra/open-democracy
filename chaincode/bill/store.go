package bill

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Store is the minimal key/value abstraction the BillContract needs.
//
// It exists so the same business logic can run inside Hyperledger Fabric
// (backed by the chaincode stub) and inside an out-of-band gateway process
// (backed by an in-memory or file-backed map). Keys are opaque strings; values
// are opaque byte slices. Implementations must treat keys as case-sensitive.
type Store interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Exists(key string) (bool, error)
	// ScanByPrefix returns all key/value pairs whose key starts with prefix.
	// Order is unspecified.
	ScanByPrefix(prefix string) ([]KV, error)
}

// KV is a single key/value pair returned by ScanByPrefix.
type KV struct {
	Key   string
	Value []byte
}

// stubStore adapts the Fabric chaincode stub to the Store interface so the
// shared Service can read and write through ctx.GetStub().
type stubStore struct {
	ctx contractapi.TransactionContextInterface
}

func newStubStore(ctx contractapi.TransactionContextInterface) Store { return &stubStore{ctx: ctx} }

func (s *stubStore) Get(key string) ([]byte, error) {
	return s.ctx.GetStub().GetState(key)
}

func (s *stubStore) Put(key string, value []byte) error {
	return s.ctx.GetStub().PutState(key, value)
}

func (s *stubStore) Exists(key string) (bool, error) {
	data, err := s.ctx.GetStub().GetState(key)
	if err != nil {
		return false, err
	}
	return len(data) > 0, nil
}

func (s *stubStore) ScanByPrefix(prefix string) ([]KV, error) {
	it, err := s.ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []KV
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		out = append(out, KV{Key: kv.GetKey(), Value: kv.GetValue()})
	}
	return out, nil
}
