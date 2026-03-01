package commons

import "os"

type EnvVar struct {
	ConfigFile string
}

func Load() *EnvVar {
	configFile, ok := os.LookupEnv("MFT_CONFIG")
	if !ok {
		configFile = "./mft.yaml"
	}

	return &EnvVar{
		ConfigFile: configFile,
	}
}
