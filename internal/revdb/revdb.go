package revdb

import (
	"fmt"

	"github.com/gviz/revDNS/internal/wl"
)

type DnsInfo struct {
	WlId  int    `json:wlid`
	Whois string `json:whois`
}

type IpInfo struct {
	Black    bool `json:black`
	Attacker bool `json:attacker`
}
type DnsVal struct {
	IpInfo
	Domains map[string]DnsInfo
}

type dbConfig struct {
	wl *wl.WhitelistDB
}

//DBWriter Writer interface for revdb
type DBWriter interface {
	WriteDB(ip string, domains []string) (int, error)
}

//DBReader Reader interface for revdb
type DBReader interface {
	ReadDB(ip string) (DnsVal, error)
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
