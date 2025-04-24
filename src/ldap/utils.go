package ldap

import (
	"fmt"
	"reflect"

	"github.com/NODO-UH/gestion-go/src/conf"
	"gopkg.in/ldap.v2"
)

const (
	IsLocked          = "EsBloqueado"
	LockedDescription = "DescripcionBloqueo"
	WorkerClass       = "worker"
)

func connectAsAdmin() (*ldap.Conn, error) {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return nil, err
	}
	return l, nil
}

func translate(x interface{}) string {
	switch reflect.TypeOf(x).Kind() {
	case reflect.Bool:
		if x == true {
			return "TRUE"
		} else {
			return "FALSE"
		}
	case reflect.Int64:
		return fmt.Sprintf("%d", x)
	case reflect.String:
		return fmt.Sprint(x)
	default:
		return "UNKNOWN"
	}
}
