package main

//Read and dump revdb/boltdb entries

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/boltdb/bolt"
)

type dnsVal struct {
	Domains map[string]struct{}
}

func NewDnsVal() *dnsVal {
	return &dnsVal{
		Domains: make(map[string]struct{}),
	}
}

func bulkRead() int {
	dbPath := "./revdb.db"
	log.Printf("Opening %s\n", dbPath)

	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	count := 0
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("dnsBucket"))

		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			count++
			fmt.Print(string(k), " ")
			val := NewDnsVal()
			if v != nil {
				err := json.Unmarshal(v, &val)
				if err != nil {
					log.Println("Error decoding json val:", err)
					return err
				}
				for key := range val.Domains {
					fmt.Print(key)
				}
				fmt.Println("")
			}
		}
		return nil
	})
	return count
}

func main() {
	c := bulkRead()
	log.Printf("Num Entries : %d\n", c)
}
