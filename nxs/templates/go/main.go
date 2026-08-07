package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Fprintln(os.Stderr, "nxs-go-template — custom NXS skeleton")
			os.Exit(0)
		}
		if a == "--version" {
			fmt.Println("nxs-go-template 0.1.0 (id=custom/go-template)")
			os.Exit(0)
		}
	}

	hasCrash, hasMeta, hasTarget := false, false, false
	for i, a := range args {
		switch a {
		case "--crash":
			hasCrash = true
		case "--meta":
			hasMeta = true
		case "--target":
			hasTarget = true
		}
		_ = i
	}
	if !hasCrash && !hasMeta {
		fmt.Fprintln(os.Stderr, "error: at least one of --crash or --meta required")
		os.Exit(1)
	}
	if !hasTarget && !hasMeta {
		fmt.Fprintln(os.Stderr, "error: --target required when --meta is absent")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[nxs-go-template] skeleton — replace with real logic")
	os.Exit(0)
}
