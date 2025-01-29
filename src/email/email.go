package email

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/NODO-UH/gestion-go/src/conf"
	logs "github.com/NODO-UH/gestion-go/src/log"
)

type Quota struct {
	Quota    int64
	Consumed int64
}

type quota struct {
	Value int64 `json:"Value"`
	Limit int64 `json:"Limit"`
}

func GetQuota(user, ou string) (*Quota, error) {
	for _, item := range conf.Configuration.Email.Matches {
		if ou == item.Ou {
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s:8080/quota?userEmail=%s", item.Address, user), nil)
			req.Header.Set("X-API-Key", conf.Configuration.Email.ServiceKey)
			client := http.Client{}
			if response, err := client.Do(req); err != nil {
				logs.Err(err.Error(), "email")
				return nil, errors.New("unknown quota")
			} else if response.StatusCode != http.StatusOK {
				logs.Err(fmt.Sprintf("unexpected StatusCode %d", response.StatusCode), "email")
				return nil, errors.New("email")
			} else {
				q := &quota{}
				if err := json.NewDecoder(response.Body).Decode(q); err != nil {
					logs.Err("error decoding response from email quota service", "email")
					return nil, errors.New("email")
				} else {
					return &Quota{
						Consumed: q.Value * 1024, // Convert to bytes
						Quota:    q.Limit * 1024, // Convert to bytes
					}, nil
				}
			}
		}
	}
	logs.Err(fmt.Sprintf("unknown email address for user OU %s", ou), "email")
	return nil, errors.New("unknown quota")
}
