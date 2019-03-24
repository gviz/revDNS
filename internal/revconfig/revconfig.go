package revconfig

import (
	"log"

	"github.com/spf13/viper"
)

type KafkaConfig struct {
	Host         string `yaml: host`
	Topic        string
	AlertChannel string
	SslStream    string
	DnsStream    string
	HttpStream   string
	FlowStream   string
}
type RevAPI struct {
	Port int
}
type RevConfig struct {
	InputType string
	Api       RevAPI
	Kafka     KafkaConfig
	Checks    ProcessingConfig
}

type ProcessingConfig struct {
	Alexa         bool
	AlexaFile     string
	Blacklist     bool
	BlacklistFile string
	Suricata      bool
	Similarity    bool
}

func InitConfig() *RevConfig {
	viper.SetConfigName("revdns")
	viper.AddConfigPath(".")
	viper.SetDefault("api.port", 9090)
	viper.SetDefault("input.type", "kafka")
	viper.SetDefault("input.ssl.stream", "network")
	viper.SetDefault("input.dns.stream", "network")
	viper.SetDefault("Processing.Lists.Alexa", true)

	err := viper.ReadInConfig()
	if err != nil {
		log.Println(err)
		return nil
	}
	return &RevConfig{
		InputType: viper.GetString("intput.type"),
		Api: RevAPI{
			Port: viper.GetInt("api.port"),
		},
		Kafka: KafkaConfig{
			Host:         viper.GetString("input.host"),
			Topic:        viper.GetString("input.topic"),
			AlertChannel: viper.GetString("output.alert-channel"),
			SslStream:    viper.GetString("input.stream_ssl"),
			DnsStream:    viper.GetString("input.stream_dns"),
			HttpStream:   viper.GetString("input.stream_http"),
			FlowStream:   viper.GetString("input.stream_flow"),
		},
		Checks: ProcessingConfig{
			Alexa:         viper.GetBool("Processing.Lists.Alexa.enabled"),
			AlexaFile:     viper.GetString("Processing.Lists.Alexa.file"),
			Blacklist:     viper.GetBool("Processing.Lists.Blacklist.enabled"),
			BlacklistFile: viper.GetString("Processing.Lists.Blacklist.file"),
			Suricata:      viper.GetBool("Processing.Attacks.Suricata"),
		},
	}
}
