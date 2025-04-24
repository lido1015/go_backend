package vpn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"

	"github.com/NODO-UH/gestion-go/src/conf"
	"github.com/NODO-UH/gestion-go/src/database"
	"github.com/NODO-UH/gestion-go/src/ldap"
	logger "github.com/NODO-UH/gestion-go/src/log"
	mongo_manager "github.com/NODO-UH/mongo-manager"
)

type Params struct {
	CI string `json:"CI"`
}

func CreateVPN(ci string) (string, error) {
	values := map[string]string{
		"CI": ci,
	}
	jsonData, err := json.Marshal(values)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := http.Post(conf.Configuration.Vpn.Uri+"/create_vpn", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", errors.New("Error getting vpn profile " + err.Error())
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(resp.Body)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if err := ldap.SetVPN(ci, true); err != nil {
		return "", err
	}

	return string(body), nil
}

func DeleteVPN(ci string) error {
	values := map[string]string{
		"CI": ci,
	}
	jsonData, err := json.Marshal(values)
	if err != nil {
		log.Fatal(err)
	}

	_, err = http.Post(conf.Configuration.Vpn.Uri+"/delete_vpn", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return errors.New("Error deleting the vpn profile " + err.Error())
	}
	return nil
}

func GetVPN(uid string, ci string) (string, error) {
	userData, err := database.Management.GetVpnData(ci)
	if err != nil {
		return "", err
	}
	if userData.Uid != uid {
		return "", fmt.Errorf("the current user doesn't have access to the requested CI")
	}
	tmpFile, err := ioutil.ReadFile(conf.Configuration.Vpn.Template)
	if err != nil {
		logger.Err(err.Error(), "[VPN]")
		return "", errors.New("unexpected error: " + err.Error())
	}
	tmpl, err := template.New("vpn").Parse(string(tmpFile))
	if err != nil {
		logger.Err(err.Error(), "[VPN]")
		return "", errors.New("unexpected error: " + err.Error())
	}
	vpn := bytes.NewBufferString("")
	err = tmpl.Execute(vpn, userData)
	if err != nil {
		logger.Err(err.Error(), "[VPN]")
		return "", errors.New("unexpected error: " + err.Error())
	}
	return vpn.String(), nil
}

func EnableVPN(ci string) error {
	return ldap.SetVPN(ci, true)
}

func DisableVPN(ci string) error {
	return ldap.SetVPN(ci, false)
}

func HasVPN(ci string) (bool, error) {
	_, err := database.Management.GetVpnData(ci)
	if err != nil {
		if errors.Is(err, mongo_manager.ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
