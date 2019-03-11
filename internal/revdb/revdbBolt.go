package revdb

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/gviz/revDNS/intenal/wl"
)

const (
	boltdbVersion = "1.0.0"
	bucketName    = "dnsBucket"
)

/*BoltDB Handler for boltdb backend*/
type BoltDB struct {
	name       string
	path       string
	version    string
	db         *bolt.DB
	bucket     *bolt.Bucket
	wl         *wl.WhitelistDB
	numEntries int
	sslEntries int
	dnsEntries int
}

type boltValue struct {
	domains map[string]struct{}
}

func (b *BoltDB) initConfig(cfg dbConfig) {
	b.wl = cfg.wl
}

func (b *BoltDB) String() string {
	return "boltInterface for revdb"
}

//IncSSLEntries tracks ssl entry additions
func (b *BoltDB) IncSSLEntries(numEntries int) {
	b.sslEntries += numEntries
}

//IncDNSEntries tracks dns entry addtions
func (b *BoltDB) IncDNSEntries(numEntries int) {
	b.dnsEntries += numEntries
}

//ReadDB reads ip information from boltdb
func (b *BoltDB) ReadDB(ip string) (DnsVal, error) {
	var domains DnsVal
	err := b.db.View(func(tx *bolt.Tx) error {
		val := NewDnsVal()
		v := tx.Bucket([]byte(bucketName)).Get([]byte(ip))
		if v != nil {
			err := json.Unmarshal(v, &val)
			if err != nil {
				log.Println("Error decoding json val:", err)
				return err
			}
			fmt.Println(val)
			domains = *val
		}
		return nil
	})

	return domains, err
}

//WriteDB writes ip/domain information to boltdb
func (b *BoltDB) WriteDB(ip string, domains []string) (int, error) {
	newEntry := true
	err := b.db.Update(func(tx *bolt.Tx) error {
		val := NewDnsVal()
		v := tx.Bucket([]byte(bucketName)).Get([]byte(ip))
		if v != nil {
			/*Update */
			err := json.Unmarshal(v, &val)
			if err != nil {
				log.Println("Error decoding json val:", err)
				return err
			}
			newEntry = false
		}

		for _, name := range domains {
			id := b.wl.Lookup(name)
			//log.Printf("Doman: %s , WL: %d\n",
			//name, id)

			val.Domains[name] = DnsInfo{
				WlId: id,
			}
		}

		data, err := json.Marshal(&val)
		if err != nil {
			log.Println("Error encoding json")
			return err
		}
		err = tx.Bucket([]byte(bucketName)).Put([]byte(ip), data)
		if newEntry {
			b.numEntries++
		}
		return err
	})
	return 0, err
}

//Close closes boltdb
func (b *BoltDB) Close() {
	b.db.Close()
}

// NewBoltDB Creates new boltdb
func NewBoltDB(path string, file string, name string) *BoltDB {
	var bkt *bolt.Bucket
	dbPath := path + "/" + file + ".db"
	log.Printf("Opening %s\n", dbPath)

	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("config"))
		if b == nil {
			v := tx.Bucket([]byte("config")).Get([]byte("version"))
			if v != nil {
				if strings.Compare(string(v), boltdbVersion) != 0 {
					log.Panicf("Incompatable version")
				}
			}
		} else {
			b.Put([]byte("version"), []byte(boltdbVersion))
		}
		b, err = tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("create bucket failed: %s", err)
		}
		bkt = b
		return nil
	})
	w := wl.WhitelistDB{
		Name: "Umbrella",
	}
	w.Init("asdfasdf")
	return &BoltDB{
		name:   name,
		path:   path,
		db:     db,
		bucket: bkt,
		wl:     &w,
	}
}

//NewDefaultBoltDB returns boltdb with default values
func NewDefaultBoltDB() *BoltDB {
	return NewBoltDB("./", "revdb", "dnsinfo")
}
