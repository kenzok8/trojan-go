//go:build server || full || mini
// +build server full mini

package build

import (
	_ "github.com/kenzok8/trojan-go/proxy/server"
)
