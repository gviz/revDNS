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
	ransomwarebl   = "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"
	malwaredomains = "http://malware-domains.com/files/domains.zip"
)

//BlacklistDB stores domains imported from Blacklist
type BlacklistDB struct {
	Name  string
	WlURL string
	db    map[string]int
}

//Lookup returns the rank in WL if entry is present
func (w *BlacklistDB) Lookup(domain string) int {
	rank, ok := w.db[domain]
	if ok {
		return rank
	}
	return 0
}

//List returns Blacklist entries
func (w *BlacklistDB) List() {
	for key := range w.db {
		fmt.Println(key)
	}
}

//Init Initializes Blacklist db. Default to CISCO Umbrella top sites.
func (w *BlacklistDB) Init(file string) {
	var buff []byte
	w.db = make(map[string]int)
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		//Default Blacklist
		w.WlURL = malwaredomains
		log.Println("Downloading wl ...")
		resp, err := http.Get(w.WlURL)
		if err != nil {
			log.Println("Error downloading  malware black list")
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
