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
	ip      string
	domains []string
	c       chan struct{}
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

func (r *revDns) httpHandler() {
	router := mux.NewRouter()
	router.Handle("/revdns/api/v1/ip/{ip}", &lkup{c: r.httpReq}).Methods("GET")
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
				rsp, err := db.ReadDB(httpReq.ip)
				if err == nil {
					log.Println("Responding ...", rsp)
					json.NewEncoder(httpReq.w).Encode(rsp)
					httpReq.c <- struct{}{}
				}
			}(webreq)

		case wr := <-r.writer:
			go func(w writeReq) {
				//log.Println("Write request :", w)
				db.WriteDB(wr.ip, wr.domains)
				wr.c <- struct{}{}
			}(wr)
		}
	}
}
