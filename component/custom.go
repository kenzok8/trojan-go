//go:build custom || full
// +build custom full

package build

import (
	_ "github.com/kenzok8/trojan-go/proxy/custom"
	_ "github.com/kenzok8/trojan-go/tunnel/adapter"
	_ "github.com/kenzok8/trojan-go/tunnel/dokodemo"
	_ "github.com/kenzok8/trojan-go/tunnel/freedom"
	_ "github.com/kenzok8/trojan-go/tunnel/http"
	_ "github.com/kenzok8/trojan-go/tunnel/mux"
	_ "github.com/kenzok8/trojan-go/tunnel/router"
	_ "github.com/kenzok8/trojan-go/tunnel/shadowsocks"
	_ "github.com/kenzok8/trojan-go/tunnel/simplesocks"
	_ "github.com/kenzok8/trojan-go/tunnel/socks"
	_ "github.com/kenzok8/trojan-go/tunnel/tls"
	_ "github.com/kenzok8/trojan-go/tunnel/tproxy"
	_ "github.com/kenzok8/trojan-go/tunnel/transport"
	_ "github.com/kenzok8/trojan-go/tunnel/trojan"
	_ "github.com/kenzok8/trojan-go/tunnel/websocket"
)
