package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type lkup struct {
	c chan lkupReq
}

type lkupReq struct {
	rType   string
	lkupVal string
	verbose int
	w       http.ResponseWriter
	c       chan struct{}
}

func (l *lkup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rType string
	var lkupVal string
	vars := mux.Vars(r)
	ret := make(chan struct{})
	if vars == nil {
		return
	}
	log.Println(r)
	lkupVal, ok := vars["ip"]
	if ok == false {
		lkupVal, ok = vars["hname"]
		if ok == false {
			return
		}
		rType = "DNS"
	} else {
		rType = "IP"
	}

	l.c <- lkupReq{
		rType:   rType,
		lkupVal: lkupVal,
		verbose: 0,
		w:       w,
		c:       ret,
	}
	<-ret
}
