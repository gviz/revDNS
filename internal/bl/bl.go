package bl

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
)

type blSource struct {
	url      string
	fileType string
	domIndx  int
	valIndx  int
	skipChar byte
	handler  int
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
	{
		url:     talosIPBl,
		handler: BL_IP,
	},
}

const (
	ransomwarebl   = "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"
	malwaredomains = "http://dns-bh.sagadc.org/domains.zip"
	spywaredomains = "http://dns-bh.sagadc.org/spywaredomains.zones.zip"
	talosIPBl      = "https://www.talosintelligence.com/documents/ip-blacklist"
)

const (
	BL_RANSOMWARE = 0 + iota
	BL_MALWARE
	BL_SPYWARE
	BL_IP
)

//BlacklistDB stores domains imported from Blacklist
type BlacklistDB struct {
	Name   string
	blURL  string
	domDB  map[string]*blEntry
	ipDB   map[string]*blEntry
	domLck sync.RWMutex
	ipLck  sync.RWMutex
}

type blEntry struct {
	sources     map[string]struct{}
	ransomWare  bool
	spyWare     bool
	malwareType string
}

//Convert map to array
func (be blEntry) MarshalJSON() ([]byte, error) {
	sources := make([]string, 0)
	for key := range be.sources {
		sources = append(sources, key)
	}

	return json.Marshal(
		struct {
			sources     []string
			ransomWare  bool
			spyWare     bool
			malwareType string
		}{
			sources:     sources,
			ransomWare:  be.ransomWare,
			spyWare:     be.spyWare,
			malwareType: be.malwareType,
		},
	)
}

func (bl *BlacklistDB) setSource(b *blEntry, name string) {
	b.sources[name] = struct{}{}
}

//Add new ip entry - resolved ips for blacklisted domains
func (bl *BlacklistDB) AddIP(ip string, desc string) {
	bl.ipLck.Lock()
	defer bl.ipLck.Unlock()
	bl.ipDB[ip] = &blEntry{}
	bl.setSource(bl.ipDB[ip], desc)
}

func (bl *BlacklistDB) processRansomware(data []byte) {
	s := strings.NewReader(string(data))
	b := bufio.NewScanner(s)
	bl.domLck.Lock()
	defer bl.domLck.Unlock()
	for b.Scan() {
		l := b.Text()
		if (len(l) == 0) || (l[0] == '#') {
			continue
		}
		log.Printf("Ransomware Entry: %s \n", l)
		if _, ok := bl.domDB[l]; ok {
			bl.domDB[l].ransomWare = true

		} else {
			bl.domDB[l] = &blEntry{
				ransomWare: true,
			}
		}
		bl.setSource(bl.domDB[l], ransomwarebl)
	}
}

//Lookup returns the rank in WL if entry is present
func (bl *BlacklistDB) Lookup(domain string) *blEntry {
	bl.domLck.RLock()
	entry, ok := bl.domDB[domain]
	bl.domLck.RUnlock()
	if ok {
		return entry
	}
	bl.ipLck.RLock()
	entry, ok = bl.domDB[domain]
	bl.ipLck.RUnlock()
	if ok {
		return entry
	}
	return nil
}

//List returns Blacklist entries
func (bl *BlacklistDB) List() {
	for key := range bl.domDB {
		fmt.Println(key)
	}
}

func (bl *BlacklistDB) processIPList(data []byte, ln int64, source string) {
	s := strings.NewReader(string(data))
	b := bufio.NewScanner(s)
	bl.ipLck.Lock()
	defer bl.ipLck.Unlock()
	for b.Scan() {
		l := b.Text()
		if (len(l) == 0) || (l[0] == '#') {
			continue
		}
		log.Printf("IP BL Entry: %s \n", l)
		if _, ok := bl.ipDB[l]; ok {
			continue
		} else {
			bl.ipDB[l] = &blEntry{}
		}
		bl.setSource(bl.domDB[l], source)
	}
}

func (bl *BlacklistDB) processSpywareList(data []byte, ln int64) {
	var buff []byte
	zp, err := zip.NewReader(bytes.NewReader(data), ln)
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
	bl.domLck.Lock()
	defer bl.domLck.Unlock()
	for b.Scan() {
		l := b.Text()
		l = strings.TrimSpace(l)
		if (len(l) == 0) || (l[0] == '/') {
			continue
		}
		values := strings.Fields(l)
		dom := strings.Trim(values[1], "\"")
		log.Printf("Spyware Entry: %s \n", dom)
		if _, ok := bl.domDB[dom]; ok {
			bl.domDB[dom].spyWare = true
		} else {
			bl.domDB[dom] = &blEntry{
				spyWare: true,
			}
		}
		bl.setSource(bl.domDB[dom], spywaredomains)
	}
}

func (bl *BlacklistDB) processMalwareList(data []byte, ln int64) {
	var buff []byte
	zp, err := zip.NewReader(bytes.NewReader(data), ln)
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
	bl.domLck.Lock()
	defer bl.domLck.Unlock()
	for b.Scan() {
		l := b.Text()
		l = strings.TrimSpace(l)
		log.Println(l)
		if (len(l) == 0) || (l[0] == '#') {
			continue
		}

		values := strings.Fields(l)
		log.Printf("Malware Entry: %s - %s\n", values[0], values[1])
		if _, ok := bl.domDB[values[0]]; ok {
			bl.domDB[values[0]].malwareType = values[1]
		} else {
			bl.domDB[values[0]] = &blEntry{
				malwareType: values[1],
			}
		}
		bl.setSource(bl.domDB[values[0]], malwaredomains)
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

//Init Initializes Blacklist db.
func (bl *BlacklistDB) Init() {
	bl.domDB = make(map[string]*blEntry)
	bl.ipDB = make(map[string]*blEntry)

	for _, lst := range blackList {
		data, len := bl.downloadList(lst.url)
		switch lst.handler {
		case BL_MALWARE:
			bl.processMalwareList(data, len)
		case BL_RANSOMWARE:
			bl.processRansomware(data)
		case BL_SPYWARE:
			bl.processSpywareList(data, len)
		case BL_IP:
			bl.processIPList(data, len, lst.url)
		}
	}
}
