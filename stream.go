package main

import (
	"log"

	"github.com/Shopify/sarama"
	"github.com/gviz/revDNS/internal/revconfig"
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
		//fmt.Println(string(answers[indx]))
		s.writer <- writeReq{
			ip:      answers[indx],
			domains: []string{query},
		}
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

	s.writer <- writeReq{
		ip:      host,
		domains: []string{server},
	}
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

	s.writer <- writeReq{
		ip:      host,
		domains: []string{server},
	}
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
				default:
					return
				}
			}(msg.Value)

		}
	}
}
