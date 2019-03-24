package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gviz/revDNS/internal/revconfig"
	"github.com/gviz/revDNS/internal/revdb"
)

type writeReq struct {
	key  string
	info revdb.DnsVal
	c    chan struct{}
}

type revDns struct {
	httpReq chan lkupReq
	writer  chan writeReq
	db      revdb.DBIface
	conf    *revconfig.RevConfig
}

func NewRevDns(conf *revconfig.RevConfig) *revDns {
	return &revDns{
		httpReq: make(chan lkupReq, 50000),
		writer:  make(chan writeReq, 50000),
		conf:    conf,
	}
}

func (r *revDns) updateIPEntry(ip string, new revdb.DnsVal) {
	var old revdb.IPDBEntry
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

	if new.Attacker {
		old.Ip.Attacker = new.Attacker
	}

	if new.Black {
		old.Ip.Black = new.Black
	}

	for proto := range new.Protos {
		if _, ok := old.Ip.Protos[proto]; !ok {
			old.Ip.Protos[proto] = struct{}{}
		}
	}

	for dm := range new.Domains {
		if _, ok := old.Domains[dm]; !ok {
			old.Domains[dm] = struct{}{}
		}
	}
	r.db.WriteDB(ip, old)
}

func (r *revDns) updateDNSEntry(new revdb.DnsVal) {
	var odm revdb.DnsInfo
	for dm := range new.Domains {
		val := new.Domains[dm]
		info, err := r.db.ReadDB(dm, revdb.DnsBucket)
		if err == nil && len(info) != 0 {
			odm = revdb.DnsInfo{
				Source:   make(map[string]struct{}),
				Referers: make(map[string]struct{}),
			}
			log.Println(string(info))
			err := json.Unmarshal(info, &odm)
			if err != nil {
				log.Println("Error updating DNS entry")
				log.Println(err)
				break
			}

			if odm.Whois != val.Whois {
				log.Println("Whois Information Change - ",
					dm)
				odm.Whois = val.Whois
			}

			for ref := range val.Referers {
				if _, ok := odm.Referers[ref]; !ok {
					odm.Referers[ref] = struct{}{}
				}
			}

			for src := range val.Source {
				if _, ok := odm.Source[src]; !ok {
					odm.Source[src] = struct{}{}
				}
			}
			r.db.WriteDB(dm, odm)
		} else {
			r.db.WriteDB(dm, val)
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

	js, err := json.Marshal(dnsInfo)
	if err != nil {
		log.Println(err)
		return "", err
	}
	log.Println("Returning ", string(js), " for ", domain)
	return string(js), nil
}

func (r *revDns) httpHandler() {
	router := mux.NewRouter()
	router.Handle("/revdns/api/v1/ip/{ip}", &lkup{c: r.httpReq}).Methods("GET")
	router.Handle("/revdns/api/v1/hname/{hname}", &lkup{c: r.httpReq}).Methods("GET")
	server := fmt.Sprintf(":%s", strconv.Itoa(r.conf.Api.Port))
	log.Fatal(http.ListenAndServe(server, router))
}

func (r *revDns) Start() {
	log.Println("Starting DB handler ...")
	go r.dbHandler()

	log.Println("Starting http handler")
	go r.httpHandler()
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
		}
	}
}
