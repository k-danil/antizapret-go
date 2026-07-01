package matcher

type Action uint8

const (
	ActionBlackhole Action = iota
	ActionRemap
	ActionPass
	ActionNXDomain
)

func (a Action) String() string {
	switch a {
	case ActionRemap:
		return "remap"
	case ActionBlackhole:
		return "blackhole"
	case ActionPass:
		return "passthrough"
	case ActionNXDomain:
		return "nxdomain"
	default:
		return "unknown"
	}
}
