package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	wis "github.com/domainr/whois"
	"github.com/gorilla/mux"
	"github.com/gviz/revDNS/internal/revconfig"
	"github.com/gviz/revDNS/internal/revdb"
	"github.com/gviz/revDNS/internal/wl"
	whoisParser "github.com/likexian/whois-parser-go"
)

type writeReq struct {
	key  string
	info revdb.DnsVal
	c    chan struct{}
}

const (
	EVENT_TYPE_BL = 1 + iota
	EVENT_TYPE_NEW
	EVENT_TYPE_DOM_AGE
	EVENT_TYPE_ATTACKER
)

const (
	EVENT_BL_DOM = 1 + iota
	EVENT_BL_IP
	EVENT_YOUNG_HOST
	EVENT_ATTACKER
	EVENT_NEW_HOST
)

type Event struct {
	Name    string `json:"name"`
	Type    string `json:"event_type"`
	Host    string `json:"host"`
	Msg     string `json:"message"`
	encoded []byte
	err     error
}

func (a *Event) Encode() ([]byte, error) {
	a.encoded, a.err = json.Marshal(a)
	if a.err != nil {
		log.Println(a.err)
	} else {
		log.Println(string(a.encoded))
	}
	return a.encoded, a.err
}

func (a *Event) Length() int {
	return len(a.encoded)
}

type revDns struct {
	httpReq chan lkupReq
	writer  chan writeReq
	db      revdb.DBIface
	conf    *revconfig.RevConfig
	wl      *wl.WhitelistDB
	alert   chan Event
	stream  *stream
	ctx     context.Context
}

func NewRevDns(conf *revconfig.RevConfig, ctx context.Context) *revDns {
	w := wl.WhitelistDB{
		Name: "Umbrella",
	}
	w.Init("Default")

	writer := make(chan writeReq, 50000)
	stream := &stream{
		brokers:    []string{conf.Kafka.Host},
		readTopic:  conf.Kafka.ReadTopic,
		alertTopic: conf.Kafka.EventChannel,
		writer:     writer,
		ctx:        ctx,
	}

	stream.Init(conf)
	return &revDns{
		httpReq: make(chan lkupReq, 50000),
		writer:  make(chan writeReq, 50000),
		conf:    conf,
		wl:      &w,
		alert:   make(chan Event, 50000),
		stream:  stream,
		ctx:     ctx,
	}
}

func (r *revDns) updateIPEntry(ip string, new revdb.DnsVal) {
	var old revdb.IPDBEntry
	doUpdate := false
	/*TBD: check for existing entry and update */
	ipVal, err := r.db.ReadDB(ip, revdb.IpBucket)
	if err == nil && len(ipVal) != 0 {
		err := json.Unmarshal(ipVal, &old)
		if err != nil {
			log.Println("Error updating IP Entry", err)
			return
		}
		//log.Println("Updating new entry for ", ip, new)
	} else {
		//log.Println("Adding new entry for ", ip, new)
		old = revdb.IPDBEntry{
			Ip: revdb.IpInfo{
				Protos: make(map[revdb.Proto]struct{}),
			},
			Domains: make(map[string]struct{}),
		}
	}

	if new.Attacker && !old.Ip.Attacker {
		doUpdate = true
		old.Ip.Attacker = new.Attacker
	}

	if new.Black && !old.Ip.Black {
		doUpdate = true
		old.Ip.Black = new.Black
	}

	for proto := range new.Protos {
		if _, ok := old.Ip.Protos[proto]; !ok {
			doUpdate = true
			old.Ip.Protos[proto] = struct{}{}
		}
	}

	for dm := range new.Domains {
		if _, ok := old.Domains[dm]; !ok {
			doUpdate = true
			old.Domains[dm] = struct{}{}
		}
	}
	if doUpdate {
		r.db.WriteDB(ip, old)
	}
}

func (r *revDns) updateWhoisInfo(name string, odm *revdb.DnsInfo) {
	var dm string
	log.Println("Updating whois...")

	topDm := strings.Split(name, ".")
	if len(topDm) > 2 {
		dm = strings.Join(topDm[len(topDm)-2:], ".")
		log.Println("Extracted topdm ", name, ":", dm)
	} else {
		dm = name
	}

	whoisInfo, er := wis.Fetch(dm)
	if er == nil {
		w, er := whoisParser.Parse(string(whoisInfo.Body))
		if er != nil {
			log.Println(er)
		}
		odm.Whois = &w
		log.Println("Whois: ", odm.Whois)
	} else {
		log.Println(er)
	}
}

func (r *revDns) updateDNSEntry(new revdb.DnsVal) {
	var odm revdb.DnsInfo
	doUpdate := false
	for dm := range new.Domains {
		val := new.Domains[dm]
		info, err := r.db.ReadDB(dm, revdb.DnsBucket)
		if err == nil && len(info) != 0 {

			odm = revdb.DnsInfo{
				Source:   make(map[string]struct{}),
				Referers: make(map[string]struct{}),
			}

			//log.Println(string(info))
			err := json.Unmarshal(info, &odm)
			if err != nil {
				log.Println("Error updating DNS entry")
				log.Println(err)
				break
			}

			/*
				if odm.Whois != val.Whois {
					log.Println("Whois Information Change - ",
						dm)
					odm.Whois = val.Whois
				}
			*/
			for ref := range val.Referers {
				if _, ok := odm.Referers[ref]; !ok {
					doUpdate = true
					odm.Referers[ref] = struct{}{}
				}
			}

			for src := range val.Source {
				if _, ok := odm.Source[src]; !ok {
					doUpdate = true
					odm.Source[src] = struct{}{}
				}
			}
			if doUpdate {
				r.db.WriteDB(dm, odm)
			}
		} else {
			val := val
			val.WlId = r.wl.Lookup(dm)
			if val.WlId == 0 {
				r.updateWhoisInfo(dm, &val)
				r.checkForNewDomain(dm,
					val.Whois.Registrar.CreatedDate)
			}
			r.db.WriteDB(dm, val)
		}
	}

}

func (r *revDns) checkForNewDomain(host string, ctime string) {
	//	tm, err := time.Parse()
	//	timeFormat := "2002-03-29T21:33:52Z"
	tm, err := time.Parse(time.RFC3339, ctime)
	if err != nil {
		log.Println(err)
		return
	}

	if time.Since(tm).Hours() < 30*24 {
		log.Println("New Domain: Less than 30 days.....")
		r.alert <- Event{
			Name: "New Domain",
			Host: host,
			Type: "INFO",
			Msg:  "Less than 30 days.....",
		}
	}
}

func (r *revDns) LookupIP(ip string, verbose int) (string, error) {
	var js []byte
	ipVal := revdb.IPDBEntry{}
	log.Println("Looking up :", ip)
	ipInfo, err := r.db.ReadDB(ip, revdb.IpBucket)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	log.Printf("Readdb returns:", string(ipInfo))

	if len(ipInfo) == 0 {
		log.Println("No read response")
	}

	if verbose > 0 {
		err := json.Unmarshal(ipInfo, &ipVal)
		if err != nil {
			log.Println("Error unmarshalling Ip Info ", err)
			return "", err
		}

		dnsVal := revdb.DnsVal{
			IpInfo:  ipVal.Ip,
			Domains: make(map[string]revdb.DnsInfo),
		}
		for dm := range ipVal.Domains {
			var dnsInfo revdb.DnsInfo
			info, err := r.db.ReadDB(dm, revdb.DnsBucket)
			if err != nil {
				break
			}
			err = json.Unmarshal(info, &dnsInfo)
			if err == nil {
				dnsVal.Domains[dm] = dnsInfo
			}
		}
		var er error
		js, er = json.Marshal(dnsVal)
		if er != nil {
			log.Println(er)
			return "", er
		}
	} else {
		js = ipInfo
	}
	log.Println("Lookedup info:", string(js))
	return string(js), nil
}

func (r *revDns) LookupDomain(domain string) (string, error) {

	dnsInfo, err := r.db.ReadDB(domain, revdb.DnsBucket)
	if err != nil {
		log.Println(err)
		return "", err
	}

	log.Println("Returning ", string(dnsInfo), " for ", domain)
	return string(dnsInfo), nil
}

func (r *revDns) httpHandler() {
	router := mux.NewRouter()
	router.Handle("/revdns/api/v1/ip/{ip}", &lkup{c: r.httpReq}).Methods("GET")
	router.Handle("/revdns/api/v1/hname/{hname}", &lkup{c: r.httpReq}).Methods("GET")
	server := fmt.Sprintf(":%s", strconv.Itoa(r.conf.Api.Port))
	log.Fatal(http.ListenAndServe(server, router))
}

func (r *revDns) Start() {
	rCtx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	go func() {
		select {
		case <-rCtx.Done():
			log.Println("Cancelling revDns Ctx")
		}
	}()

	log.Println("Starting DB handler ...")
	go r.dbHandler()

	log.Println("Starting http handler")
	go r.httpHandler()
	r.stream.Run()
}

//Handle DB lookups and updates
func (r *revDns) dbHandler() {
	db := revdb.NewDefaultBoltDB()
	if db == nil {
		log.Fatal("Error opening DB")
	}
	r.db = db
	defer db.Close()
	for {
		select {
		case webreq := <-r.httpReq:
			go func(httpReq lkupReq) {
				var rsp string
				var err error
				switch httpReq.rType {
				case "IP":
					rsp, err = r.LookupIP(httpReq.lkupVal, httpReq.verbose)
					if err != nil {
						break
					}
				case "DNS":
					rsp, err = r.LookupDomain(httpReq.lkupVal)
					if err != nil {
						break
					}
				}
				log.Println("Responding ...", rsp)
				fmt.Fprintln(httpReq.w, rsp)
				httpReq.c <- struct{}{}
			}(webreq)

		case wr := <-r.writer:
			go func(w writeReq) {
				r.updateIPEntry(wr.key, wr.info)
				r.updateDNSEntry(wr.info)
				wr.c <- struct{}{}
			}(wr)
		case alert := <-r.alert:
			r.stream.WriteAlert(alert)
		}
	}
}
