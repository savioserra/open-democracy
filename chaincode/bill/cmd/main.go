package main

import (
    "log"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
    cc "open-democracy/chaincode/bill"
)

func main() {
    chaincode, err := contractapi.NewChaincode(&cc.BillContract{})
    if err != nil {
        log.Panicf("error creating Bill chaincode: %v", err)
    }

    if err := chaincode.Start(); err != nil {
        log.Panicf("error starting Bill chaincode: %v", err)
    }
}
