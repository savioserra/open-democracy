// odctl is the federation CLI for open-democracy. It provides a terminal
// UI to configure, bootstrap, and manage an open-democracy node.
//
// Run it from the project root:
//
//	./bin/odctl
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"open-democracy/internal/tui"
)

func main() {
	p := tea.NewProgram(tui.New(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
