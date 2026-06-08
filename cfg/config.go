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
	MinTTL   time.Duration `yaml:"min_ttl"`
	MaxTTL   time.Duration `yaml:"max_ttl"`
}

type Upstream struct {
	Name    string        `yaml:"name"`
	DSN     string        `yaml:"dsn"`
	Timeout time.Duration `yaml:"timeout"`
}

type Firewall struct {
	Backend BackendType   `yaml:"backend"` // nft | iptables
	Set     string        `yaml:"set"`     // только для nft
	Chain   string        `yaml:"chain"`
	TTL     time.Duration `yaml:"ttl"`
}

type BackendType string

const (
	BackendNFT      BackendType = "nft"
	BackendIPTables BackendType = "iptables"
)

type RouterType string

const (
	RouterTypeBlackhole   RouterType = "blackhole"
	RouterTypeRemap       RouterType = "remap"
	RouterTypePassthrough RouterType = "passthrough"
)

const (
	FormatPlain  = "plain"
	FormatRegexp = "regexp"
)

type Policy struct {
	ReloadInterval time.Duration `yaml:"reload_interval"`
	Matchers       []Matcher     `yaml:"matchers"`
}

type Matcher struct {
	Name       string     `yaml:"name"`
	Type       RouterType `yaml:"type"`
	Source     string     `yaml:"source"`
	Format     string     `yaml:"format"`
	Subdomains *bool      `yaml:"subdomains"`
	Prune      bool       `yaml:"prune"`
	Regexp     *Regexp    `yaml:"regexp,omitempty"`
	Filter     *Filter    `yaml:"filter,omitempty"`
}

type Filter struct {
	Exclude []string `yaml:"exclude"`
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
	Firewall        Firewall      `yaml:"firewall"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	LoggingSeverity string        `yaml:"logging_severity"`
	StatePath       string        `yaml:"state_path"`
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
    - name: "hosts"
      type: "remap"
      source: file:///etc/antizapret-go/hosts.txt
      format: plain
      subdomains: true
fake_cidr: "10.30.0.0/15"
cache:
  capacity: 20000
  ttl: 24h
  min_ttl: 1m
  max_ttl: 24h
firewall:
  backend: nft
  set: "ANTIZAPRET_SET"
  chain: "ANTIZAPRET_CHAIN"
  ttl: 5m
request_timeout: 2s
logging_severity: "debug"
state_path: "/var/lib/antizapret-go/state.db"`

func ReadConfig(configFilename string) error {
	return readConfig(configFilename, AntizapretDefaultConfig, &Antizapret)
}
