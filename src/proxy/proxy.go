package proxy

import (
	"github.com/NODO-UH/gestion-go/src/database"
)

type Quota struct {
	Quota    int64
	Bonus    int64
	Consumed int64
}

func GetQuota(user string) (*Quota, error) {
	if qm, err := database.Proxy.GetProxyQuota(user); err != nil {
		return nil, err
	} else {
		return &Quota{
			Quota:    qm.Max,
			Bonus:    0,
			Consumed: qm.Consumed,
		}, nil
	}
}
