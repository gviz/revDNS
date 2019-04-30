package main

/*Passive DNS/IP information DB for
Bro generated KAFKA streams*/

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gviz/revDNS/internal/bl"
	"github.com/gviz/revDNS/internal/revconfig"
)

func main() {
	fmt.Println("revDNS ")
	ctx := context.Background()
	conf := revconfig.InitConfig()
	if conf == nil {
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer func() {
		signal.Stop(sig)
		cancel()
	}()

	go func(ctx context.Context, sig chan os.Signal) {
		for {
			select {
			case <-sig:
				signal.Stop(sig)
				cancel()
			case <-ctx.Done():
				log.Println("Main ctx exit")
				//Wait for cleanup
				time.Sleep(time.Second * 2)
				os.Exit(0)
			}
		}
	}(ctx, sig)

	b := bl.BlacklistDB{}
	b.Init()

	r := NewRevDns(conf, ctx)
	r.Start()
}
