package revdb

import (
	"encoding/json"
	"fmt"

	"github.com/gviz/revDNS/internal/wl"
	whoisparser "github.com/likexian/whois-parser-go"
)

type Alert struct {
	name  string
	atype string
	msg   string
}

type DnsInfo struct {
	WlId     int                    `json:wlid`
	Whois    *whoisparser.WhoisInfo `json:"whois,omitempty"`
	Referers map[string]struct{}    `json:"referers,omitempty"` //Http Referers
	Source   map[string]struct{}    `json:"source,omitempty"`   //Source stream. Http, dns, ssl,...
}

type Proto struct {
	Id    int
	Dport int
}

type IpInfo struct {
	Black    bool               `json:black`
	Attacker bool               `json:attacker`
	Protos   map[Proto]struct{} `json:"Protos,omitempty"`
}

type DnsVal struct {
	IpInfo
	Domains map[string]DnsInfo
}

type IPDBEntry struct {
	Ip      IpInfo
	Domains map[string]struct{}
}

func (dns IPDBEntry) MarshalJSON() ([]byte, error) {

	pArray := make([]Proto, 0)

	for k := range dns.Ip.Protos {
		pArray = append(pArray, k)
	}
	//fmt.Println("Marshall called...")
	return json.Marshal(
		struct {
			ip struct {
				Black    bool
				Attacker bool
				Protos   []Proto
			}
			Domains map[string]struct{}
		}{
			ip: struct {
				Black    bool
				Attacker bool
				Protos   []Proto
			}{
				Black:    dns.Ip.Black,
				Attacker: dns.Ip.Attacker,
				Protos:   pArray,
			},
			Domains: dns.Domains,
		})
}

type dbConfig struct {
	wl *wl.WhitelistDB
}

//DBWriter Writer interface for revdb
type DBWriter interface {
	WriteDB(key string, info interface{}) error
}

//DBReader Reader interface for revdb
type DBReader interface {
	ReadDB(key string, bucket string) ([]byte, error)
}

//DBIface Interface for revdb operations
type DBIface interface {
	DBWriter
	DBReader
	initConfig(cfg dbConfig)
	Close()
	String() string
}

type Handler struct {
	Reader DBIface
	Writer DBIface
}

func (db *Handler) Close() {
	db.Reader.Close()
	db.Writer.Close()
}

func (db *Handler) String() string {
	ret := fmt.Sprintf("%s -> %s",
		db.Reader.String(), db.Writer.String())
	return ret
}

func NewDBHandler(in DBIface,
	out DBIface) *Handler {
	return &Handler{
		Reader: in,
		Writer: out,
	}
}

func NewDnsVal() *DnsVal {
	return &DnsVal{
		Domains: make(map[string]DnsInfo),
	}
}
