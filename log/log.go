package log

import (
	"errors"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"syscall"
)

var (
	level  = zap.NewAtomicLevel()
	Logger *zap.Logger
	L      *zap.SugaredLogger
)

func init() {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder

	Logger = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(cfg),
		zapcore.Lock(os.Stderr),
		level,
	))
	L = Logger.Sugar()
}

func SetDebug(debug bool) {
	if debug {
		level.SetLevel(zap.DebugLevel)
	} else {
		level.SetLevel(zap.InfoLevel)
	}
}

func SetSeverity(severity string) error {
	return level.UnmarshalText([]byte(severity))
}

func Sync() {
	if err := Logger.Sync(); err != nil && !errors.Is(err, syscall.ENOTTY) {
		_, _ = fmt.Fprintf(os.Stderr, "Can't sync logger: %v", err)
	}
}
