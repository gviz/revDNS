package revdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	elasticsearch "github.com/elastic/go-elasticsearch"
	"github.com/elastic/go-elasticsearch/esapi"
)

const dnsQuery = `{
	"query": { 
		   "match_phrase": {
	   "@meta.stream": "dns"
	 }
	}
	}`
const sslQuery = `{
	"query": { 
		   "match_phrase": {
	   "@meta.stream": "ssl"
	 }
	}
	}`
const esTemplate = `{
	"query": { 
		   "match_phrase": {
	   "ip": "%s"
	 }
	}
	}`

const broDNSIndex = "bro-network*"

type jsonObj map[string]interface{}

type dnsObj struct {
	name map[string]struct{}
}
type revdbs struct {
	db map[string]dnsObj
}

var revdb *revdbs

/*EsDB - Elastic search handler*/
type EsDB struct {
	name  string
	index string
	es    *elasticsearch.Client
}

type dnsEsObj struct {
	IP      string
	Domains []string
}

/*ReadDB gets information from ES*/
func (dns *EsDB) ReadDB(ip string) (int, error) {
	query := fmt.Sprintf(esTemplate, ip)
	res, err := dns.es.Search(dns.es.Search.WithContext(context.Background()),
		dns.es.Search.WithIndex(dns.index),
		dns.es.Search.WithBody(strings.NewReader(query)),
		dns.es.Search.WithFrom(0),
		dns.es.Search.WithSize(150),
	)
	defer res.Body.Close()
	return 0, err
}

/*WriteDB writes to ES*/
func (dns *EsDB) WriteDB(ip string, domains []string) (int, error) {
	log.Printf("Index: %s\n", dns.index)
	j, _ := json.Marshal(&dnsEsObj{IP: ip, Domains: domains})

	fmt.Println((string(j)))
	req := esapi.IndexRequest{
		Index:   dns.index,
		Body:    bytes.NewReader(j),
		Refresh: "true",
	}
	rs, err := req.Do(context.Background(), dns.es)

	if err != nil {
		log.Println("Error creating index")
		return 0, err
	}
	if rs.IsError() {
		log.Println("Error creating index entry")
	}

	defer rs.Body.Close()
	return 0, nil
}

//NewEsDBWriter returns handle to elastic search (reader and writer)
func NewEsDBWriter() *EsDB {
	es, err := elasticsearch.NewClient(elasticsearch.Config{})

	if err != nil {
		return nil
	}
	return &EsDB{
		name:  "Elastic",
		index: "revdb-1.0",
		es:    es,
	}
}

func getVal(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	val, ok := m[k]
	if ok && val != nil {
		return val.(string)
	} else {
		return ""
	}

}

//ImportBroDNSEntries imports domain information from DNS entries in elastic search
func ImportBroDNSEntries(writer DBIface) int {
	revdb = &revdbs{db: make(map[string]dnsObj)}
	es, err := elasticsearch.NewClient(elasticsearch.Config{})

	if err != nil {
		fmt.Println(err)
		return 0
	}

	fromIndx := 0
	defaultSz := 100
	count := 0
	for {
		r := make(map[string]interface{})
		res, err := es.Search(es.Search.WithContext(context.Background()),
			es.Search.WithIndex(broDNSIndex),
			es.Search.WithBody(strings.NewReader(dnsQuery)),
			es.Search.WithFrom(fromIndx),
			es.Search.WithSize(defaultSz),
		)

		if err != nil {
			log.Fatalf("ERROR: %s", err)
			break
		}

		if err := json.NewDecoder(res.Body).Decode(&r); err == nil {
			log.Println("Test")
			broHits := r["hits"]

			if broHits == nil {
				log.Println("No Hits")
				break
			}

			broRecords := broHits.(map[string]interface{})["hits"].([]interface{})
			for _, broRecord := range broRecords {
				if broRecord.(map[string]interface{})["_source"] == nil {
					log.Println("Invalid Bro Record")
					break
				}

				broDNS := broRecord.(map[string]interface{})["_source"].(map[string]interface{})["dns"]
				host := getVal(broDNS.(map[string]interface{}), "id_orig_h")
				query := getVal(broDNS.(map[string]interface{}), "query")
				ts := getVal(broDNS.(map[string]interface{}), "ts")
				logStr := fmt.Sprintf("%s %s %s ", ts, host, query)
				answers, ok := broDNS.(map[string]interface{})["answers"]
				if ok {
					fmt.Println(logStr, answers)
					for _, ip := range answers.([]interface{}) {
						if _, ok := revdb.db[ip.(string)]; !ok {
							revdb.db[ip.(string)] = dnsObj{name: make(map[string]struct{})}
						}
						revdb.db[ip.(string)].name[host] = struct{}{}
						writer.WriteDB(ip.(string),
							DnsVal{
								Domains: map[string]DnsInfo{
									query: DnsInfo{
										Source: map[string]struct{}{
											"ES-DNS": struct{}{},
										},
									},
								},
							})

						count++
					}
				} else {
					fmt.Println(logStr)
				}
			}
		}
		res.Body.Close()
		fromIndx += defaultSz
	}
	return count
}

//ImportBroSSLEntries imports ssl domain information from elastic search to db
func ImportBroSSLEntries(writer DBIface) int {
	revdb = &revdbs{db: make(map[string]dnsObj)}
	es, err := elasticsearch.NewClient(elasticsearch.Config{})

	if err != nil {
		fmt.Println(err)
		return 0
	}

	fromIndx := 0
	defaultSz := 100
	count := 0
	for {
		r := make(map[string]interface{})
		res, err := es.Search(es.Search.WithContext(context.Background()),
			es.Search.WithIndex(broDNSIndex),
			es.Search.WithBody(strings.NewReader(sslQuery)),
			es.Search.WithFrom(fromIndx),
			es.Search.WithSize(defaultSz),
		)

		if err != nil {
			log.Fatalf("ERROR: %s", err)
			break
		}

		if err := json.NewDecoder(res.Body).Decode(&r); err == nil {
			log.Println("Test")
			broHits := r["hits"]
			if broHits == nil {
				log.Println("No Hits")
				break
			}
			broRecords := broHits.(map[string]interface{})["hits"].([]interface{})

			for _, broRecord := range broRecords {
				if broRecord.(map[string]interface{})["_source"] == nil {
					log.Println("Invalid Bro Record")
					break
				}
				broSSL := broRecord.(map[string]interface{})["_source"].(map[string]interface{})["ssl"]
				ip := getVal(broSSL.(map[string]interface{}), "id_resp_h")
				host := getVal(broSSL.(map[string]interface{}), "server_name")
				ts := getVal(broSSL.(map[string]interface{}), "ts")
				logStr := fmt.Sprintf("%s %s %s ", ts, host, ip)
				log.Print(logStr)
				writer.WriteDB(ip,
					DnsVal{
						Domains: map[string]DnsInfo{
							host: DnsInfo{
								Source: map[string]struct{}{
									"ES-SSL": struct{}{},
								},
							},
						},
					})

				count++
			}
		}
		res.Body.Close()
		fromIndx += defaultSz
	}
	return count
}
