package main

import (
	"fmt"
	"testing"

	"github.com/gviz/revDNS/internal/wl"
)

func TestAlexaHandler(T *testing.T) {
	w := wl.WhitelistDB{}
	w.Init("adfasfas")
	fmt.Println(w.Lookup("www.google.com"))
	fmt.Println(w.Lookup("le.cm"))
	fmt.Println(w.Lookup("www.gle.com"))
	//w.List()

}
