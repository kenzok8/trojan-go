package server

import (
	"github.com/kenzok8/trojan-go/config"
	"github.com/kenzok8/trojan-go/proxy/client"
)

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(client.Config)
	})
}
