//go:build !darwin && !linux

package platform

import (
	"fmt"
	"runtime"
)

func New() (Platform, error) {
	return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
}
