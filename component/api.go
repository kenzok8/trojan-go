//go:build api || full
// +build api full

package build

import (
	_ "github.com/kenzok8/trojan-go/api/control"
	_ "github.com/kenzok8/trojan-go/api/service"
)
