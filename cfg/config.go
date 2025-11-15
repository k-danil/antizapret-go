package cfg

import (
	"time"
)

const ServiceName = `antizapret-go`

type Upstream struct {
	Name    string        `yaml:"name"`
	DSN     string        `yaml:"dsn"`
	Timeout time.Duration `yaml:"timeout"`
}

type Nft struct {
	Set   string `yaml:"set"`
	Chain string `yaml:"chain"`
}

type RouterType string

const (
	RouterTypeBlackhole   RouterType = "blackhole"
	RouterTypeRemap       RouterType = "remap"
	RouterTypePassthrough RouterType = "passthrough"
)

type Router struct {
	Name   string     `yaml:"name"`
	Type   RouterType `yaml:"type"`
	Source string     `yaml:"source"`
	Regexp *Regexp    `yaml:"regexp,omitempty"`
}

type Regexp struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type AntizapretConfig struct {
	Listen struct {
		Address  string `yaml:"address"`
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
	} `yaml:"listen"`
	Upstreams []Upstream `yaml:"upstreams"`
	Routers   []Router   `yaml:"routers"`
	FakeCIDR  string     `yaml:"fake_cidr"`
	Cache     struct {
		ClearInterval time.Duration `yaml:"clear_interval"`
		Capacity      int           `yaml:"capacity"`
		TTL           time.Duration `yaml:"ttl"`
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
  address: "udp://8.8.8.8:53"
  timeout: 5s
fake_cidr: "10.30.0.0/15"
cache:
  clear_interval: 1m
  capacity: 20000
  ttl: 5m
nft:
  set: "ANTIZAPRET_SET"
  chain: "ANTIZAPRET_CHAIN" 
logging_severity: "debug"`

func ReadConfig(configFilename string) error {
	return readConfig(configFilename, AntizapretDefaultConfig, &Antizapret)
}
