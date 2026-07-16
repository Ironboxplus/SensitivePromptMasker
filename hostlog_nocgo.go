//go:build !cgo

package main

import "fmt"

func sendCPASensitiveHostLog([]byte) ([]byte, error) {
	return nil, fmt.Errorf("host logging requires cgo")
}
