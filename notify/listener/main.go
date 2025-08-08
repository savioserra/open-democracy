package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
    "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
    "github.com/hyperledger/fabric-sdk-go/pkg/core/config"
    "github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// Simple notification listener skeleton that connects to a Fabric network using the SDK
// and logs chaincode events. Replace the notify... functions with integration to your
// messaging infrastructure (e-mail, push notifications, etc.).
func main() {
    cfgPath := getenv("FABRIC_SDK_CONFIG", "")
    if cfgPath == "" {
        log.Println("FABRIC_SDK_CONFIG not set. Provide path to connection profile (YAML). Exiting listener skeleton.")
        return
    }
    channelID := getenv("FABRIC_CHANNEL", "mychannel")
    org := getenv("FABRIC_ORG", "Org1")
    user := getenv("FABRIC_USER", "User1")
    ccName := getenv("FABRIC_CC", "bill")
    pattern := getenv("FABRIC_EVENT_FILTER", ".*")

    sdk, err := fabsdk.New(config.FromFile(cfgPath))
    if err != nil {
        log.Fatalf("failed to create SDK: %v", err)
    }
    defer sdk.Close()

    chCtx := sdk.ChannelContext(channelID, fabsdk.WithUser(user), fabsdk.WithOrg(org))
    chClient, err := channel.New(chCtx)
    if err != nil {
        log.Fatalf("failed to create channel client: %v", err)
    }

    reg, notifier, err := chClient.RegisterChaincodeEvent(ccName, pattern)
    if err != nil {
        log.Fatalf("failed to register chaincode event: %v", err)
    }
    defer chClient.Unregister(reg)

    // graceful shutdown
    ctx, cancel := signalNotifyContext()
    defer cancel()

    log.Printf("Listening for events on cc=%s pattern=%s channel=%s org=%s user=%s", ccName, pattern, channelID, org, user)
    for {
        select {
        case <-ctx.Done():
            log.Println("listener stopping...")
            return
        case ev := <-notifier:
            if ev == nil {
                time.Sleep(200 * time.Millisecond)
                continue
            }
            handleEvent(ev)
        }
    }
}

func handleEvent(ev *fab.CCEvent) {
    log.Printf("Event received: cc=%s name=%s tx=%s", ev.ChaincodeID, ev.EventName, ev.TxID)
    switch ev.EventName {
    case "BillCreated":
        var payload map[string]string
        _ = json.Unmarshal(ev.Payload, &payload)
        if billID, ok := payload["billId"]; ok {
            notifyUsersOfNewBill(billID)
        }
    case "VoteStarted":
        // In a real system, fetch the bill and notify eligible voters
        log.Printf("Vote started payload=%s", string(ev.Payload))
    case "BillVersionAdded":
        log.Printf("New version added payload=%s", string(ev.Payload))
    case "VersionVoteAdded":
        log.Printf("Version vote added payload=%s", string(ev.Payload))
    case "VersionAgreed":
        log.Printf("Version agreed payload=%s", string(ev.Payload))
    case "VoteEnded":
        log.Printf("Vote ended payload=%s", string(ev.Payload))
    default:
        // catch-all
    }
}

func notifyUsersOfNewBill(billID string) {
    // TODO: integrate with your preference DB and e-mail/push system
    fmt.Printf("[notify] New bill created: %s\n", billID)
}

func getenv(k, def string) string {
    if v := os.Getenv(k); v != "" {
        return v
    }
    return def
}

func signalNotifyContext() (context.Context, context.CancelFunc) {
    ctx, cancel := context.WithCancel(context.Background())
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-c
        cancel()
    }()
    return ctx, cancel
}
