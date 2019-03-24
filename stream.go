package main

import (
	"log"

	"github.com/Shopify/sarama"
	"github.com/gviz/revDNS/internal/revconfig"
	"github.com/gviz/revDNS/internal/revdb"
)

//Input Stream Handling .
type stream struct {
	brokers   []string
	topic     string
	consumer  sarama.Consumer
	pConsumer sarama.PartitionConsumer
	writer    chan writeReq
	conf      *revconfig.RevConfig
}

func (s *stream) getNewWriteReq(kv map[string]string) writeReq {
	var info revdb.DnsInfo

	for k := range kv {
		switch k {
		case "dnsinfo.source":
			info.Source = map[string]struct{}{
				kv[k]: struct{}{},
			}
		case "dnsinfo.referer":
			info.Referers = map[string]struct{}{
				kv[k]: struct{}{},
			}

		}
	}

	return writeReq{
		key: kv["ip"],
		info: revdb.DnsVal{
			Domains: map[string]revdb.DnsInfo{
				kv["domain"]: info,
			},
		},
	}
}

func (s *stream) Init(conf *revconfig.RevConfig) {
	if len(s.brokers) == 0 {
		log.Panic("No brokers specified for kafka..")
	}
	log.Printf("Kafka Brokers: %v", s.brokers)

	consumer, err := sarama.NewConsumer(s.brokers, nil)
	if err != nil {
		log.Fatalln(err)
	}

	s.consumer = consumer
	pConsumer, err := consumer.ConsumePartition(s.topic, 0, sarama.OffsetNewest)
	if err != nil {
		log.Fatalln(err)
	}

	s.pConsumer = pConsumer
	s.conf = conf
}

//DNS responses
func (s *stream) processDNS(js *revJson) {
	qtype, err := js.getValStr("qtype_name")
	if qtype != "A" && qtype != "AAA" {
		return
	}

	answers, err := js.getValStrSlice("answers")
	if err != nil {
		return
	}
	query, err := js.getValStr("query")
	if err != nil {
		return
	}

	for indx := range answers {
		kv := map[string]string{
			"ip":             answers[indx],
			"domain":         query,
			"dnsinfo.source": "DNS",
		}
		s.writer <- s.getNewWriteReq(kv)
		//fmt.Println(string(answers[indx]))
		/*
			s.writer <- writeReq{
				ip:      answers[indx],
				DnsVal: DnsVal{
					Domains:{
						query: DnsInfo{
							Source: map[string]struct{}{
								"DNS": struct{}{},
							},
						},
					},
				},
			}
		*/
	}
}

//SSL SNI
func (s *stream) processSSL(js *revJson) {
	server, err := js.getValStr("server_name")
	if err != nil {
		return
	}

	host, err := js.getValStr("id_resp_h")
	if err != nil {
		return
	}

	kv := map[string]string{
		"ip":             host,
		"domain":         server,
		"dnsinfo.source": "SSL",
	}

	s.writer <- s.getNewWriteReq(kv)
	/*
		s.writer <- writeReq{
			ip:      host,
			DnsVal: DnsVal{
				Domains:{
					server: DnsInfo{
						Source: "SSL"
					}
				},
			},
		}
	*/
}

//Extract Host Fields
func (s *stream) processHTTP(js *revJson) {
	server, err := js.getValStr("host")
	if err != nil {
		return
	}

	host, err := js.getValStr("id_resp_h")
	if err != nil {
		return
	}

	kv := map[string]string{
		"ip":             host,
		"domain":         server,
		"dnsinfo.source": "HTTP",
	}

	s.writer <- s.getNewWriteReq(kv)
	/*
		s.writer <- writeReq{
			ip:      host,
			DnsVal: DnsVal{
				Domains:{
					server: DnsInfo{
						Source: "http"
					}
				},
			},
		}
	*/
}

func (s *stream) Run() {
	log.Println("Run...")
	for {
		select {
		case msg := <-s.pConsumer.Messages():
			go func(val []byte) {
				js := NewRevJson(val)
				if js == nil {
					log.Println("Error getting json object")
					return
				}
				sType, err := js.getValStr("@stream")
				if err != nil {
					return
				}
				//				log.Println("stype:", sType)
				switch sType {
				case s.conf.Kafka.DnsStream:
					//log.Println(string(val))
					s.processDNS(js)
				case s.conf.Kafka.SslStream:
					s.processSSL(js)
				case s.conf.Kafka.HttpStream:
					s.processHTTP(js)
					/*
						case s.conf.Kafka.FlowStream:
							s.processFlow(js)
					*/
				default:
					return
				}
			}(msg.Value)

		}
	}
}
