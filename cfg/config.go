package cfg

import (
	"time"
)

const ServiceName = `antizapret-go`

type Bind struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

type Cache struct {
	Capacity int           `yaml:"capacity"`
	TTL      time.Duration `yaml:"ttl"`
}

type Upstream struct {
	Name    string        `yaml:"name"`
	DSN     string        `yaml:"dsn"`
	Timeout time.Duration `yaml:"timeout"`
}

type Nft struct {
	Set   string        `yaml:"set"`
	Chain string        `yaml:"chain"`
	TTL   time.Duration `yaml:"ttl"`
}

type RouterType string

const (
	RouterTypeBlackhole   RouterType = "blackhole"
	RouterTypeRemap       RouterType = "remap"
	RouterTypePassthrough RouterType = "passthrough"
)

type Policy struct {
	ReloadInterval time.Duration `yaml:"reload_interval"`
	Matchers       []Matcher     `yaml:"matchers"`
}

type Matcher struct {
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
	Bindings        []Bind        `yaml:"bindings"`
	Upstreams       []Upstream    `yaml:"upstreams"`
	Policy          Policy        `yaml:"policy"`
	FakeCIDR        string        `yaml:"fake_cidr"`
	Cache           Cache         `yaml:"cache"`
	NFT             Nft           `yaml:"nft"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	LoggingSeverity string        `yaml:"logging_severity"`
}

var Antizapret AntizapretConfig

const AntizapretDefaultConfig = `bindings:
  - address: "127.0.0.1"
    protocol: "udp"
    port: 53
upstreams:
  - name: google
    dsn: "udp://8.8.8.8:53"
    timeout: 1s
policy:
  reload_interval: 6h
  matchers:
    - name: "antizapret"
      type: "remap"
      source: https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/include-hosts.txt
      regexp:
        from: "^([^#].*)$"
        to: ".$1"
fake_cidr: "10.30.0.0/15"
cache:
  capacity: 20000
  ttl: 24h
nft:
  set: "ANTIZAPRET_SET"
  chain: "ANTIZAPRET_CHAIN"
  ttl: 5m
request_timeout: 2s
logging_severity: "debug"`

func ReadConfig(configFilename string) error {
	return readConfig(configFilename, AntizapretDefaultConfig, &Antizapret)
}
