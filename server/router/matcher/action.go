package matcher

type Action uint8

const (
	ActionBlackhole Action = iota
	ActionRemap
	ActionPass
)

func (a Action) String() string {
	switch a {
	case ActionRemap:
		return "remap"
	case ActionBlackhole:
		return "blackhole"
	case ActionPass:
		return "passthrough"
	default:
		return "unknown"
	}
}
