package cfg

import (
	"time"
)

const ServiceName = `antizapret-go`

type Bind struct {
	Address  string `yaml:"address" validate:"omitempty,ip"`
	Port     int    `yaml:"port" validate:"min=1,max=65535"`
	Protocol string `yaml:"protocol" validate:"required,oneof=udp tcp"`
}

type Cache struct {
	Capacity int           `yaml:"capacity" validate:"min=1"`
	TTL      time.Duration `yaml:"ttl" validate:"gt=0"`
	MinTTL   time.Duration `yaml:"min_ttl" validate:"gt=0"`
	MaxTTL   time.Duration `yaml:"max_ttl" validate:"gt=0,gtefield=MinTTL"`
}

type Upstream struct {
	Name    string        `yaml:"name"`
	DSN     string        `yaml:"dsn" validate:"required,uri"`
	Timeout time.Duration `yaml:"timeout" validate:"gt=0"`
}

type Firewall struct {
	Backend BackendType   `yaml:"backend" validate:"omitempty,oneof=nft iptables"`
	Set     string        `yaml:"set" validate:"required_unless=Backend iptables"`
	Chain   string        `yaml:"chain" validate:"required"`
	TTL     time.Duration `yaml:"ttl" validate:"gt=0"`
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
	ReloadInterval time.Duration `yaml:"reload_interval" validate:"gt=0"`
	RebuildTimeout time.Duration `yaml:"rebuild_timeout" validate:"gt=0"`
	Matchers       []Matcher     `yaml:"matchers" validate:"dive"`
}

type Matcher struct {
	Name       string     `yaml:"name" validate:"required"`
	Type       RouterType `yaml:"type" validate:"required,oneof=blackhole remap passthrough"`
	Source     string     `yaml:"source" validate:"required,uri"`
	Format     string     `yaml:"format" validate:"omitempty,oneof=plain regexp"`
	Subdomains *bool      `yaml:"subdomains"`
	Prune      bool       `yaml:"prune"`
	Regexp     *Regexp    `yaml:"regexp,omitempty" validate:"required_if=Format regexp"`
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
	Bindings        []Bind        `yaml:"bindings" validate:"min=1,dive"`
	Processes       int           `yaml:"processes" validate:"omitempty,min=1"`
	Upstreams       []Upstream    `yaml:"upstreams" validate:"min=1,dive"`
	Policy          Policy        `yaml:"policy"`
	FakeCIDR        string        `yaml:"fake_cidr" validate:"required,cidrv4"`
	Cache           Cache         `yaml:"cache"`
	Firewall        Firewall      `yaml:"firewall"`
	RequestTimeout  time.Duration `yaml:"request_timeout" validate:"gt=0"`
	LoggingSeverity string        `yaml:"logging_severity"`
	StatePath       string        `yaml:"state_path" validate:"required"`
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
  rebuild_timeout: 1m
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
