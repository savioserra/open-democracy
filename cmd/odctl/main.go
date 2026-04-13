// odctl is the federation CLI for open-democracy. It offers a hybrid
// interface: no arguments launch the terminal UI, and explicit subcommands
// provide scriptable operations for demo and federation node workflows.
package main

import "os"

func main() {
	os.Exit(newCLI(os.Stdout, os.Stderr).run(os.Args[1:]))
}
