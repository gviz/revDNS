package wl

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	ciscoUmbrella = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
)

//WhitelistDB stores domains imported from whitelist
type WhitelistDB struct {
	Name  string
	WlURL string
	db    map[string]int
}

//Lookup returns the rank in WL if entry is present
func (w *WhitelistDB) Lookup(domain string) int {
	rank, ok := w.db[domain]
	if ok {
		return rank
	}
	return 0
}

//List returns whitelist entries
func (w *WhitelistDB) List() {
	for key := range w.db {
		fmt.Println(key)
	}
}

//Init Initializes whitelist db. Default to CISCO Umbrella top sites.
func (w *WhitelistDB) Init(file string) {
	var buff []byte
	w.db = make(map[string]int)
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		//Default Whitelist
		w.WlURL = ciscoUmbrella
		log.Println("Downloading wl ...")
		resp, err := http.Get(w.WlURL)
		if err != nil {
			log.Println("Error downloading umbrella list")
			return
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		zp, err := zip.NewReader(bytes.NewReader(body), resp.ContentLength)
		for _, f := range zp.File {
			z, err := f.Open()
			if err != nil {
				log.Println("Error accessing zip contents:")
				return
			}
			buff, _ = ioutil.ReadAll(z)
		}
	} else {
		buff, _ = ioutil.ReadFile(file)
	}
	dr := strings.NewReader(string(buff))
	csv := csv.NewReader(dr)

	domains, err := csv.ReadAll()
	if err != nil {
		log.Panicln("Error parsing domains")
		return
	}
	for indx := range domains {
		dom := domains[indx][1]
		rank := domains[indx][0]
		w.db[dom], err = strconv.Atoi(rank)
	}
}
