package main

//Import Bro logs from Elastic search and update revdb/boltdb

import (
	"flag"
	"log"

	"github.com/gviz/revDNS/internal/revdb"
)

func main() {
	var builddb string
	flag.StringVar(&builddb, "Build DNS DB", "ss", "--builddb")
	outDB := revdb.NewDefaultBoltDB()
	defer outDB.Close()
	if builddb == "ss" {
		if outDB == nil {
			log.Println("Error opening output db")
			return
		}
		log.Println("Building DB....")
		log.Println("Collecting DNS entries ..")
		dnsCount := revdb.ImportBroDNSEntries(outDB)
		log.Println("Collecting SSL entries")
		sslCount := revdb.ImportBroSSLEntries(outDB)

		log.Printf("DNS: %d SSL: %d Total: %d\n",
			dnsCount, sslCount, dnsCount+sslCount)

	}

}
