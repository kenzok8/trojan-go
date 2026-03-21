package version

import (
	"flag"
	"fmt"
	"runtime"

	"github.com/kenzok8/trojan-go/common"
	"github.com/kenzok8/trojan-go/constant"
	"github.com/kenzok8/trojan-go/option"
)

type versionOption struct {
	flag *bool
}

func (*versionOption) Name() string {
	return "version"
}

func (*versionOption) Priority() int {
	return 10
}

func (c *versionOption) Handle() error {
	if *c.flag {
		fmt.Println("Trojan-Go", constant.Version)
		fmt.Println("Go Version:", runtime.Version())
		fmt.Println("OS/Arch:", runtime.GOOS+"/"+runtime.GOARCH)
		fmt.Println("Git Commit:", constant.Commit)
		fmt.Println("")
		fmt.Println("Maintained by kenzok8")
		fmt.Println("Licensed under GNU General Public License version 3")
		fmt.Println("GitHub Repository:\thttps://github.com/kenzok8/trojan-go")
		fmt.Println("Trojan-Go Documents:\thttps://github.com/kenzok8/trojan-go/tree/master/docs")
		return nil
	}
	return common.NewError("not set")
}

func init() {
	option.RegisterHandler(&versionOption{
		flag: flag.Bool("version", false, "Display version and help info"),
	})
}
