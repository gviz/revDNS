package revdb

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/gviz/revDNS/internal/wl"
)

const (
	boltdbVersion = "1.0.0"
	DnsBucket     = "dnsBucket"
	IpBucket      = "ipBucket"
)

/*BoltDB Handler for boltdb backend*/
type BoltDB struct {
	name       string
	path       string
	version    string
	db         *bolt.DB
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
func (b *BoltDB) ReadDB(key string, bucket string) ([]byte, error) {
	var val []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(IpBucket)).Get([]byte(key))
		if v != nil {
			val = v
		}
		return nil
	})

	return val, err
}

//WriteDB writes ip/domain information to boltdb
func (b *BoltDB) WriteDB(key string, info interface{}) error {
	var data []byte
	var err error
	var bucketName string

	switch info.(type) {
	case IPDBEntry:
		bucketName = IpBucket
		data, err = json.Marshal(info.(IPDBEntry))
	case DnsInfo:
		bucketName = DnsBucket
		data, err = json.Marshal(info.(DnsInfo))
	}

	if err != nil {
		log.Println("Error encoding json", err)
		//debug.PrintStack()
		return err
	}
	fmt.Println(string(data))

	err = b.db.Update(func(tx *bolt.Tx) error {
		err := tx.Bucket([]byte(bucketName)).Put([]byte(key), data)
		return err
	})
	if err != nil {
		log.Println("Error write:", err)
	}
	return err
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
		b, err = tx.CreateBucketIfNotExists([]byte(IpBucket))
		if err != nil {
			return fmt.Errorf("create bucket failed: %s", err)
		}
		bkt = b
		b, err = tx.CreateBucketIfNotExists([]byte(DnsBucket))
		if err != nil {
			return fmt.Errorf("create bucket failed: %s", err)
		}
		return nil
	})
	w := wl.WhitelistDB{
		Name: "Umbrella",
	}
	w.Init("Default")
	return &BoltDB{
		name: name,
		path: path,
		db:   db,
		wl:   &w,
	}
}

//NewDefaultBoltDB returns boltdb with default values
func NewDefaultBoltDB() *BoltDB {
	return NewBoltDB("./", "revdb", "dnsinfo")
}
