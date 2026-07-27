//go:build !windows

// The GUI front-end is Windows-only (uses the native walk toolkit). This stub
// keeps `go build ./...` working on macOS/Linux.
package main

import "fmt"

func main() {
	fmt.Println("autoconv-gui is Windows-only; build with GOOS=windows.")
}
