package conf

import (
	"fmt"

	"github.com/spf13/viper"
)

// Configuration is the global configuration
var Configuration SicConfiguration

func InitConfiguration(confPath string) {
	viper.SetConfigName("sic-conf")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(confPath)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			panic(fmt.Errorf("config file not found"))
		} else {
			panic(err)
		}
	}
	if err := viper.Unmarshal(&Configuration); err != nil {
		panic(err)
	}
}
