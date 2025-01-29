package conf

import "fmt"

type SicConfiguration struct {
	Ldap      LdapConfig
	Databases struct {
		Proxy      DbConfig
		Management DbConfig
	}
	Email             EmailConfig
	SecurityQuestions SecurityQuestionsConfig
	Vpn               VpnConfig
}

type LdapConfig struct {
	Addr struct {
		Host string
		Port uint32
	}
	Ous   []string
	Admin struct {
		Uid      string
		Password string
	}
}

func (c LdapConfig) BuildAddr() string {
	return fmt.Sprintf("%s:%d", c.Addr.Host, c.Addr.Port)
}

type DbConfig struct {
	Uri string
}

type EmailConfig struct {
	Matches []struct {
		Ou      string
		Address string
	}
	ServiceKey string
}

type SecurityQuestionsConfig struct {
	Count uint32
}

type VpnConfig struct {
	Uri      string
	Template string
}
