package tui

import (
	"fmt"
	"strconv"
	"strings"
)

const defaultGatewayPort = "8080"

func normalizeGatewayPort(port string) (string, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return defaultGatewayPort, nil
	}

	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return "", fmt.Errorf("must be a number between 1 and 65535")
	}

	return strconv.Itoa(value), nil
}
