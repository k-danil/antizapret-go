package cfg

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/k-danil/antizapret-go/log"
	"go.uber.org/config"
)

var (
	BuildCommitSha = "unknown"
	BuildTimestamp = "unknown"
)

func ShowVersion() string {
	return fmt.Sprintf("%s @ %s", BuildCommitSha, BuildTimestamp)
}

func readConfig(configFilename, defaultConfig string, target interface{}) error {
	opts := []config.YAMLOption{
		config.Permissive(),
		config.Source(strings.NewReader(defaultConfig)),
	}

	if configFilename != "" {
		cfgFile, err := os.Open(configFilename)
		if err != nil {
			return err
		}
		opts = append(opts, config.Source(cfgFile))
	}

	provider, err := config.NewYAML(opts...)
	if err != nil {
		return err
	}

	if err = provider.Get(config.Root).Populate(target); err != nil {
		return err
	}

	if err = validator.New(validator.WithRequiredStructEnabled()).Struct(target); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	log.L.Infow("Configuration loaded",
		"configFilename", configFilename,
		"config", target)

	return nil
}
