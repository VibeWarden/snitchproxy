// Package snitchproxy provides the public API for embedding snitchproxy
// in other Go applications.
//
// This is the only public package in the module. Use it to programmatically
// start a snitchproxy instance, configure assertions, and retrieve results.
//
// Example:
//
//	sp, err := snitchproxy.New(
//	    snitchproxy.WithConfigFile("snitchproxy.yaml"),
//	    snitchproxy.WithMode(snitchproxy.ModeProxy),
//	    snitchproxy.WithListenAddr(":8080"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sp.Close()
//
//	if err := sp.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// ... run your tests ...
//
//	violations := sp.Violations()
package snitchproxy

// Mode represents the operating mode of snitchproxy.
type Mode string

const (
	ModeProxy Mode = "proxy"
	ModeDecoy Mode = "decoy"
)
