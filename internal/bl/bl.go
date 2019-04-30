package wl

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type blSource struct {
	url     string
	handler int
}

//Add new sources here
var blackList = []blSource{
	{
		url:     ransomwarebl,
		handler: BL_RANSOMWARE,
	},
	{
		url:     malwaredomains,
		handler: BL_MALWARE,
	},
	{
		url:     spywaredomains,
		handler: BL_SPYWARE,
	},
}

const (
	ransomwarebl   = "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"
	malwaredomains = "http://dns-bh.sagadc.org/domains.zip"
	spywaredomains = "http://dns-bh.sagadc.org/spywaredomains.zones.zip"
)

const (
	BL_RANSOMWARE = 0 + iota
	BL_MALWARE
	BL_SPYWARE
)

//BlacklistDB stores domains imported from Blacklist
type BlacklistDB struct {
	Name  string
	WlURL string
	db    map[string]*blEntry
}

type blEntry struct {
	ransomWare  bool
	spyWare     bool
	malwareType string
}

func (bl *BlacklistDB) processRansomware(data []byte) {
	s := strings.NewReader(string(data))
	b := bufio.NewScanner(s)
	for b.Scan() {
		l := b.Text()
		if l[0] == '#' {
			continue
		}
		log.Printf("Ransomware Entry: %s \n", l)
		if _, ok := bl.db[l]; ok {
			bl.db[l].ransomWare = true

		} else {
			bl.db[l] = &blEntry{
				ransomWare: true,
			}
		}
	}
}

//Lookup returns the rank in WL if entry is present
func (bl *BlacklistDB) Lookup(domain string) *blEntry {
	entry, ok := bl.db[domain]
	if ok {
		return entry
	}
	return nil
}

//List returns Blacklist entries
func (bl *BlacklistDB) List() {
	for key := range bl.db {
		fmt.Println(key)
	}
}
func (bl *BlacklistDB) processSpywareList(data []byte, len int64) {
	var buff []byte
	zp, err := zip.NewReader(bytes.NewReader(data), len)
	if err != nil {
		log.Println(err)
		return
	}
	for _, f := range zp.File {
		z, err := f.Open()
		if err != nil {
			log.Println("Error accessing zip contents:")
			return
		}
		buff, _ = ioutil.ReadAll(z)
	}
	s := strings.NewReader(string(buff))
	b := bufio.NewScanner(s)
	for b.Scan() {
		l := b.Text()
		if l[0] == '#' {
			continue
		}
		values := strings.Split(l, " ")
		log.Printf("Spyware Entry: %s \n", values[0])
		if _, ok := bl.db[values[0]]; ok {
			bl.db[l].spyWare = true
		} else {
			bl.db[l] = &blEntry{
				spyWare: true,
			}
		}

	}
}

func (bl *BlacklistDB) processMalwareList(data []byte, len int64) {
	var buff []byte
	zp, err := zip.NewReader(bytes.NewReader(data), len)
	if err != nil {
		log.Println(err)
		return
	}
	for _, f := range zp.File {
		z, err := f.Open()
		if err != nil {
			log.Println("Error accessing zip contents:")
			return
		}
		buff, _ = ioutil.ReadAll(z)
	}
	s := strings.NewReader(string(buff))
	b := bufio.NewScanner(s)
	for b.Scan() {
		l := b.Text()
		if l[0] == '#' {
			continue
		}
		values := strings.Split(l, " ")
		log.Printf("Malware Entry: %s - %s\n", values[0], values[1])
		if _, ok := bl.db[values[0]]; ok {
			bl.db[l].malwareType = values[1]
		} else {
			bl.db[l] = &blEntry{
				malwareType: values[1],
			}
		}

	}
}
func (bl *BlacklistDB) downloadList(url string) ([]byte, int64) {
	log.Printf("Downloading bl: %s ...", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Println("Error downloading  malware black list")
		return []byte{}, 0
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return []byte{}, 0
	}
	return body, resp.ContentLength
}

//Init Initializes Blacklist db. Default to CISCO Umbrella top sites.
func (bl *BlacklistDB) Init() {
	bl.db = make(map[string]*blEntry)

	for _, lst := range blackList {
		data, len := bl.downloadList(lst.url)
		switch lst.handler {
		case BL_MALWARE:
			bl.processMalwareList(data, len)
		case BL_RANSOMWARE:
			bl.processRansomware(data)
		case BL_SPYWARE:
			bl.processSpywareList(data, len)
		}
	}
}
