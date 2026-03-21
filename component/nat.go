//go:build nat || full || mini
// +build nat full mini

package build

import (
	_ "github.com/kenzok8/trojan-go/proxy/nat"
)
