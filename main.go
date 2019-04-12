package main

/*Passive DNS/IP information DB for
Bro generated KAFKA streams*/

import (
	"fmt"

	"github.com/gviz/revDNS/internal/revconfig"
)

func main() {
	fmt.Println("revDNS ")
	conf := revconfig.InitConfig()
	if conf == nil {
		return
	}

	r := NewRevDns(conf)
	r.Start()
}
