package cfg

import (
	"time"
)

const ServiceName = `antizapret-go`

type Upstream struct {
	Address string        `yaml:"address"`
	Network string        `yaml:"network"`
	Timeout time.Duration `yaml:"timeout"`
}

type Nft struct {
	Set   string `yaml:"set"`
	Chain string `yaml:"chain"`
}

type AntizapretConfig struct {
	Listen struct {
		Address  string `yaml:"address"`
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
	} `yaml:"listen"`
	Upstream Upstream `yaml:"upstream"`
	FakeCIDR string   `yaml:"fake_cidr"`
	Cache    struct {
		Capacity int           `yaml:"capacity"`
		TTL      time.Duration `yaml:"ttl"`
	} `yaml:"cache"`
	Nft             Nft    `yaml:"nft"`
	LoggingSeverity string `yaml:"logging_severity"`
}

var Antizapret AntizapretConfig

const AntizapretDefaultConfig = `listen:
  address: "127.0.0.1"
  protocol: "udp"
  port: 53
upstream:
  address: "8.8.8.8:53"
  timeout: 5s
fake_cidr: "10.30.0.0/15"
cache:
  capacity: 20000
  ttl: 5m
nft:
  set: "antizapret_mapping"
  chain: "antizapret" 
logging_severity: "debug"`

func ReadConfig(configFilename string) error {
	return readConfig(configFilename, AntizapretDefaultConfig, &Antizapret)
}
