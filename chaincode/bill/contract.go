package bill

import (
	"encoding/json"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// BillContract is the Hyperledger Fabric chaincode entrypoint. Every method
// is a thin wrapper that:
//
//  1. Builds an *Invoker from the X.509 certificate attributes via cid.
//  2. Reads the transaction timestamp from the stub.
//  3. Constructs a Service backed by stub-based Store and EventSink adapters.
//  4. Delegates to the Service so the same business logic runs in Fabric and
//     in the in-process gateway used by the dashboard.
type BillContract struct {
	contractapi.Contract
}

// service builds a Service wired to the given Fabric transaction context.
func (c *BillContract) service(ctx contractapi.TransactionContextInterface) *Service {
	return NewService(newStubStore(ctx), newStubEventSink(ctx))
}

// CreateBill creates a new bill in draft status and registers the first version.
func (c *BillContract) CreateBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).CreateBill(caller, now, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask)
}

// EditBill adds a new version to a draft bill.
func (c *BillContract) EditBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).EditBill(caller, now, billID, ipfsHash, description)
}

// AssignRoleForBill grants per-bill roles to a user.
func (c *BillContract) AssignRoleForBill(ctx contractapi.TransactionContextInterface, billID, userID, role string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).AssignRoleForBill(caller, billID, userID, role)
}

// VoteOnVersion records a vote against a draft version.
func (c *BillContract) VoteOnVersion(ctx contractapi.TransactionContextInterface, billID, versionIndex, choice string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).VoteOnVersion(caller, now, billID, versionIndex, choice)
}

// SubmitBill opens the formal voting window.
func (c *BillContract) SubmitBill(ctx contractapi.TransactionContextInterface, billID, startTimeSeconds, durationSeconds string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).SubmitBill(caller, billID, startTimeSeconds, durationSeconds)
}

// CastVote records a vote during the open voting window.
func (c *BillContract) CastVote(ctx contractapi.TransactionContextInterface, billID, choice string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).CastVote(caller, now, billID, choice)
}

// EndVote finalizes the vote.
func (c *BillContract) EndVote(ctx contractapi.TransactionContextInterface, billID string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).EndVote(caller, now, billID)
}

// SetBillScope updates the scope of a bill.
func (c *BillContract) SetBillScope(ctx contractapi.TransactionContextInterface, billID, scope string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).SetBillScope(caller, billID, scope)
}

// SetBillCriteria updates the execution / rejection masks of a draft bill.
func (c *BillContract) SetBillCriteria(ctx contractapi.TransactionContextInterface, billID, executeMask, rejectMask string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).SetBillCriteria(caller, billID, executeMask, rejectMask)
}

// GetBill returns the bill as a JSON string.
func (c *BillContract) GetBill(ctx contractapi.TransactionContextInterface, billID string) (string, error) {
	b, err := c.service(ctx).GetBill(billID)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func txTimestampSeconds(ctx contractapi.TransactionContextInterface) (int64, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	return protobufTimestampToSeconds(ts), nil
}

func protobufTimestampToSeconds(ts *timestamp.Timestamp) int64 {
	if ts == nil {
		return 0
	}
	return ts.Seconds
}
