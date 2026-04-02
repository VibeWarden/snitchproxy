package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "snitchproxy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// TODO: parse flags, load config, wire up engine, start server
	fmt.Printf("snitchproxy %s\n", version)
	return nil
}
