# revDNS
revDNS is a passive host information collector written for NSM platforms ingesting data from Bro IDS. 

revDNS builds a passive database of reverse DNS information from DNS, SSL and HTTP metadata ingested from bro logs.  
It currently supports ingesting data from Kafka and provides a REST interface to lookup information using IP.


## Install
> go get github.com/gviz/revDNS/...

## Configuration
revDNS reads its configuraiton from revdns.yaml. 
```
> api:
>>  port: 9090
>
>input: 
>>    type: "kafka"  
>>    host: "localhost:9092"  
>>    topic: "bro-raw"  
>>    stream_dns:  "dns"  
>>    stream_ssl:  "ssl"  
>>    stream_http: "http"  
```

## Usage
```
> go run github.com/gviz/revDNS/revDNS.go 
```
### Reverse DNS Query
```
> curl http://localhost:9090/revdns/api/v1/ip/<IP Address>
```

## License
The contents of this repository are covered under the GPL V3 License.
