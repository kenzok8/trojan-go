//go:build client || full || mini
// +build client full mini

package build

import (
	_ "github.com/kenzok8/trojan-go/proxy/client"
)
