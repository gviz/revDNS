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
	ip string
	w  http.ResponseWriter
	c  chan struct{}
}

func (l *lkup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ret := make(chan struct{})
	if vars == nil {
		return
	}
	log.Println(r)
	ip, ok := vars["ip"]
	if ok == false {
		return
	}

	l.c <- lkupReq{
		ip: ip,
		w:  w,
		c:  ret,
	}
	<-ret
}
