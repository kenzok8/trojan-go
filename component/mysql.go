//go:build mysql || full || mini
// +build mysql full mini

package build

import (
	_ "github.com/kenzok8/trojan-go/statistic/mysql"
)
