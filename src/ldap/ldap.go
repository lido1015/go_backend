package ldap

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/NODO-UH/gestion-go/src/log"

	"github.com/NODO-UH/gestion-go/src/conf"
	"gopkg.in/ldap.v2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrMultipleUsers      = errors.New("multiple users")
	ErrUserAlreadyEnabled = errors.New("user already enabled")
	ErrUserLocked         = errors.New("user is locked")
	ErrUnexpected         = errors.New("unexpected internal error")
)

type UserData struct {
	CI               string `ldap:"CI"`
	Email            string `ldap:"uid"`
	Name             string `ldap:"cn"`
	ObjectClass      string `ldap:"objectClass"`
	Position         string `ldap:"Cargo"`
	CareerName       string `ldap:"NombreCarrera"`
	Salary           string `ldap:"Salario"`
	SubArea          string `ldap:"Subarea"`
	ServiceTime      string `ldap:"TiempoServicio"`
	Vacations        string `ldap:"Vacaciones"`
	SubCategory      string `ldap:"Subcategoria"`
	ActiveYears      string `ldap:"AnosActivos"`
	CurseType        string `ldap:"TipoCurso"`
	ScientificDegree string `ldap:"GradoCientifico"`
	Militancy        string `ldap:"Militancia"`
	HasVC            bool   `ldap:"TieneVC"`
	HasInternet      bool   `ldap:"TieneInternet"`
	HasCloud         bool   `ldap:"TieneNube"`
	HasEmail         bool   `ldap:"TieneCorreo"`
	HasVPN           bool   `ldap:"TieneVPN"`
}

type UserAccountDetails struct {
	UserData
	AlreadySignIn bool
}

func authenticateUser(user, password, ou string) error {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		fmt.Println(err)
		return err
	}

	defer func() {
		l.Close()
	}()

	err = l.Bind(fmt.Sprintf("uid=%s,ou=%s,dc=uh,dc=cu", user, ou), password)
	if err != nil {
		return err
	}
	if locked, _, err := IsBlocked(user); locked {
		return ErrUserLocked
	} else if err != nil {
		return err
	}
	return nil
}

func AuthenticateUser(user, password string) (*string, error) {
	for _, ou := range conf.Configuration.Ldap.Ous {
		if err := authenticateUser(user, password, ou); err == nil {
			return &ou, nil
		} else if err == ErrUserLocked {
			return nil, ErrUserLocked
		}
	}
	return nil, ErrUserNotFound
}

func ChangePassword(user, oldPassword, newPassword string) error {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		fmt.Println(err)
		return err
	}

	defer func() {
		l.Close()
	}()

	var ou string
	find := false
	for _, ou = range conf.Configuration.Ldap.Ous {
		if err = l.Bind(fmt.Sprintf("uid=%s,ou=%s,dc=uh,dc=cu", user, ou), oldPassword); err == nil {
			find = true
			break
		}
	}

	if !find || !isValidPassword(oldPassword) {
		return errors.New("invalid credentials")
	}

	if _, err := l.PasswordModify(&ldap.PasswordModifyRequest{
		UserIdentity: fmt.Sprintf("uid=%s,ou=%s,dc=uh,dc=cu", user, ou),
		OldPassword:  oldPassword,
		NewPassword:  newPassword,
	}); err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

func ForcedChangePassword(user, newPassword string) error {
	for _, ou := range conf.Configuration.Ldap.Ous {
		if err := forcedChangePassword(user, newPassword, ou); err == nil {
			return nil
		}
	}
	return fmt.Errorf("couldn't change password for user %s", user)
}

func forcedChangePassword(user, newPassword, ou string) error {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer func() {
		l.Close()
	}()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	if !isValidPassword(newPassword) {
		return errors.New("password not valid")
	}

	if _, err := l.PasswordModify(&ldap.PasswordModifyRequest{
		UserIdentity: fmt.Sprintf("uid=%s,ou=%s,dc=uh,dc=cu", user, ou),
		OldPassword:  "",
		NewPassword:  newPassword,
	}); err != nil {
		return err
	}
	return nil
}

func FindByCI(ci, uid string) (dn string, err error) {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return "", err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return "", err
	}

	query := "(&"
	if ci != "" {
		query += "(CI=" + ci + ")"
	}
	if uid != "" {
		query += "(uid=" + uid + ")"
	}
	query += ")"

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		query,
		[]string{"uid"},
		nil,
	))
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", ErrUserNotFound
	}

	if len(sr.Entries) != 1 {
		return "", ErrMultipleUsers
	}

	return sr.Entries[0].DN, nil
}

func GetDisableUser(ci string) (uid string, ou string, dn string, lockedDescription string, err error) {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return "", "", "", "", err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return "", "", "", "", err
	}

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(CI=%s))", ci),
		[]string{"uid", "objectClass", "userPassword", LockedDescription, IsLocked},
		nil,
	))
	if err != nil {
		return "", "", "", "", err
	}

	if len(sr.Entries) == 0 {
		return "", "", "", "", ErrUserNotFound
	}

	for _, user := range sr.Entries {
		if user.GetAttributeValue("userPassword") == "" {
			if user.GetAttributeValue(IsLocked) == "TRUE" {
				return "", "", "", user.GetAttributeValue(LockedDescription), ErrUserLocked
			}
			return user.GetAttributeValue("uid"), user.GetAttributeValue("objectClass"), user.DN, "", nil
		}
	}
	return "", "", "", "", ErrUserAlreadyEnabled
}

func SetPassword(dn, password string) error {
	// Check if password is valid
	if !isValidPassword(password) {
		return ErrInvalidCredentials
	}

	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	modifyRequest := ldap.NewPasswordModifyRequest(dn, "", password)
	_, err = l.PasswordModify(modifyRequest)
	if err != nil {
		return err
	}
	return nil
}

func GeUserData(user string) (*UserData, error) {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return nil, err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return nil, err
	}
	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", user),
		[]string{
			"uid", "TieneCorreo", "TieneNube", "TieneInternet", "Cargo", "NombreCarrera", "cn", "sn",
			"objectClass", "Salario", "Subarea", "TiempoServicio", "Vacaciones", "Subcategoria", "GradoCientifico",
			"Militancia", "TieneVC", "AnosActivos", "TipoCurso", "TieneVPN",
		},
		nil,
	))
	if err != nil {
		return nil, err
	}
	return &UserData{
		Email:            sr.Entries[0].GetAttributeValue("uid"),
		Name:             fmt.Sprintf("%s %s", sr.Entries[0].GetAttributeValue("cn"), sr.Entries[0].GetAttributeValue("sn")),
		ObjectClass:      sr.Entries[0].GetAttributeValue("objectClass"),
		CareerName:       sr.Entries[0].GetAttributeValue("NombreCarrera"),
		Position:         sr.Entries[0].GetAttributeValue("Cargo"),
		Salary:           sr.Entries[0].GetAttributeValue("Salario"),
		SubArea:          sr.Entries[0].GetAttributeValue("Subarea"),
		ServiceTime:      sr.Entries[0].GetAttributeValue("TiempoServicio"),
		Vacations:        sr.Entries[0].GetAttributeValue("Vacaciones"),
		SubCategory:      sr.Entries[0].GetAttributeValue("Subcategoria"),
		ActiveYears:      sr.Entries[0].GetAttributeValue("AnosActivos"),
		CurseType:        sr.Entries[0].GetAttributeValue("TipoCurso"),
		ScientificDegree: sr.Entries[0].GetAttributeValue("GradoCientifico"),
		Militancy:        sr.Entries[0].GetAttributeValue("Militancia"),
		HasVC:            sr.Entries[0].GetAttributeValue("TieneVC") == "TRUE",
		HasInternet:      sr.Entries[0].GetAttributeValue("TieneInternet") == "TRUE",
		HasCloud:         sr.Entries[0].GetAttributeValue("TieneNube") == "TRUE",
		HasEmail:         sr.Entries[0].GetAttributeValue("TieneCorreo") == "TRUE",
		HasVPN:           sr.Entries[0].GetAttributeValue("TieneVPN") == "TRUE",
	}, nil
}

func GetAdminUserData(ci string, uid string) ([]UserAccountDetails, bool, error) {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return nil, false, err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return nil, false, err
	}

	var conditions string
	if ci != "" {
		conditions += fmt.Sprintf("(CI=%s)", ci)
	}
	if uid != "" {
		conditions += fmt.Sprintf("(uid=%s)", uid)
	}
	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&%s)", conditions),
		[]string{"uid", "TieneCorreo", "TieneNube", "TieneInternet", "Cargo", "NombreCarrera", "cn", "sn", "objectClass", "userPassword", "TieneVPN", "CI"},
		nil,
	))
	if err != nil {
		return nil, false, err
	}

	if len(sr.Entries) == 0 {
		return nil, false, nil
	}

	data := make([]UserAccountDetails, 0)
	for _, userEntry := range sr.Entries {
		user := &UserData{
			CI:          userEntry.GetAttributeValue("CI"),
			Email:       userEntry.GetAttributeValue("uid"),
			Name:        fmt.Sprintf("%s %s", sr.Entries[0].GetAttributeValue("cn"), userEntry.GetAttributeValue("sn")),
			ObjectClass: userEntry.GetAttributeValue("objectClass"),
			Position:    userEntry.GetAttributeValue("Cargo"),
			CareerName:  userEntry.GetAttributeValue("NombreCarrera"),
			HasInternet: userEntry.GetAttributeValue("TieneInternet") == "TRUE",
			HasCloud:    userEntry.GetAttributeValue("TieneNube") == "TRUE",
			HasEmail:    userEntry.GetAttributeValue("TieneCorreo") == "TRUE",
			HasVPN:      userEntry.GetAttributeValue("TieneVPN") == "TRUE",
		}
		data = append(data, UserAccountDetails{
			*user,
			userEntry.GetAttributeValue("userPassword") != "",
		})

	}

	return data, true, nil
}

func ResetPassword(dn, newPassword string) error {
	if !isValidPassword(newPassword) {
		return ErrInvalidCredentials
	}

	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	if _, err = l.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", newPassword)); err != nil {
		return err
	}

	return nil
}

func isValidPassword(s string) bool {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(s) > 7 {
		hasMinLen = true
	}
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

func EnableServices(dn string) error {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	modify := ldap.NewModifyRequest(dn)
	modify.Replace("TieneCorreo", []string{"TRUE"})
	modify.Replace("TieneInternet", []string{"TRUE"})
	modify.Replace("TieneNube", []string{"FALSE"})

	if err = l.Modify(modify); err != nil {
		return err
	}

	return nil
}

func ResetUser(ci string, uid string) error {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(CI=%s)(uid=%s))", ci, uid),
		[]string{"uid"},
		nil,
	))
	if err != nil {
		return err
	}

	if len(sr.Entries) == 0 {
		return ErrUserNotFound
	}

	m := ldap.NewModifyRequest(sr.Entries[0].DN)
	m.Replace("userPassword", []string{""})
	m.Replace("TieneCorreo", []string{"FALSE"})
	m.Replace("TieneInternet", []string{"FALSE"})
	m.Replace("TieneNube", []string{"FALSE"})
	m.Replace("TieneVPN", []string{"FALSE"})

	if err := l.Modify(m); err != nil {
		log.Err(err.Error(), "[LDAP]")
		return err
	}

	return nil
}

// UserExists check if a user with UID exists. If the user exists and is unique in LDAP, then nil is returned.
// If an error occurs during LDAP search then that error is returned. If are multiple users with the same UID,
// the ErrMultipleUsers are returned. If not exist user with UID, then ErrUserNotFound is returned.
func UserExists(uid string) error {
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer l.Close()

	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", uid),
		[]string{"uid"},
		nil,
	))
	if err != nil {
		return err
	}

	if len(sr.Entries) == 0 {
		return ErrUserNotFound
	}

	if len(sr.Entries) != 1 {
		return ErrMultipleUsers
	}

	return nil
}

// ChangeEmail change user uid with currentEmail to newEmail
func ChangeEmail(currentEmail, newEmail string) error {
	// Connect to LDAP
	l, err := ldap.Dial("tcp", conf.Configuration.Ldap.BuildAddr())
	if err != nil {
		return err
	}

	defer l.Close()

	// Bind as admin
	if err := l.Bind(conf.Configuration.Ldap.Admin.Uid, conf.Configuration.Ldap.Admin.Password); err != nil {
		return err
	}

	// Search by UID for get OU
	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", currentEmail),
		nil,
		nil,
	))
	if err != nil {
		return err
	}
	if len(sr.Entries) == 0 {
		return ErrUserNotFound
	}
	if len(sr.Entries) > 1 {
		return ErrMultipleUsers
	}

	// Extract user and user DN from LDAP request
	oldUser := sr.Entries[0]
	userDN := oldUser.DN

	// Build Delete request
	deleteRequest := ldap.NewDelRequest(userDN, nil)

	// Build new user DN
	sep := fmt.Sprintf("uid=%s", currentEmail)
	split := strings.Split(userDN, fmt.Sprintf("uid=%s", currentEmail))
	if len(split) != 2 || split[0] != "" {
		log.Err(fmt.Sprintf("error spliting %s with %s", userDN, sep), "[LDAP]")
		return ErrUnexpected
	}
	newDN := fmt.Sprintf("uid=%s", newEmail) + split[1]

	// Build add request with same attributes
	addRequest := ldap.NewAddRequest(newDN)
	for _, attr := range oldUser.Attributes {
		if attr.Name != "uid" {
			addRequest.Attribute(attr.Name, attr.Values)
		} else {
			addRequest.Attribute("uid", []string{newEmail})
		}
	}

	// Do Add request
	err = l.Add(addRequest)
	if err != nil {
		return err
	}

	// Do Delete request
	err = l.Del(deleteRequest)
	if err != nil {
		return err
	}

	return nil
}

// SetVPN set the "TieneVPN" attribute to TRUE or FALSE for the user with the given uid
func SetVPN(ci string, value bool) error {
	l, err := connectAsAdmin()
	defer l.Close()

	if err != nil {
		return err
	}

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(CI=%s)", ci),
		[]string{"uid"},
		nil,
	))
	if err != nil {
		return err
	}

	if len(sr.Entries) == 0 {
		return ErrUserNotFound
	}

	for _, entry := range sr.Entries {
		m := ldap.NewModifyRequest(entry.DN)
		if value {
			m.Replace("TieneVPN", []string{"TRUE"})
		} else {
			m.Replace("TieneVPN", []string{"FALSE"})
		}

		if err := l.Modify(m); err != nil {
			log.Err(err.Error(), "[LDAP]")
			return err
		}
	}

	return nil
}

func VPNEnabled(ci string) (bool, error) {
	l, err := connectAsAdmin()
	if err != nil {
		return false, err
	}
	defer l.Close()

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(CI=%s)", ci),
		[]string{"TieneVPN"},
		nil,
	))
	if err != nil {
		return false, err
	}

	if len(sr.Entries) == 0 {
		return false, ErrUserNotFound
	}

	enabled := true
	for _, entry := range sr.Entries {
		enabled = enabled && entry.GetAttributeValue("TieneVPN") == "TRUE"
	}

	return enabled, nil
}

type PatchData struct {
	HasEmail           *bool
	HasInternet        *bool
	HasVideoConference *bool
	HasCloud           *bool
	HasVPN             *bool
	EsBloqueado        *bool
	FechaBloqueo       *int64 // Unix time
	DescripcionBloqueo *string
}

func (p *PatchData) ToMap() map[string][]string {
	data := make(map[string][]string)
	if p.HasEmail != nil {
		data["TieneCorreo"] = []string{translate(*p.HasEmail)}
	}
	if p.HasInternet != nil {
		data["TieneInternet"] = []string{translate(*p.HasInternet)}
	}
	if p.HasVideoConference != nil {
		data["TieneVC"] = []string{translate(*p.HasVideoConference)}
	}
	if p.HasCloud != nil {
		data["TieneNube"] = []string{translate(*p.HasCloud)}
	}
	if p.HasVPN != nil {
		data["TieneVPN"] = []string{translate(*p.HasVPN)}
	}
	if p.EsBloqueado != nil {
		data[IsLocked] = []string{translate(*p.EsBloqueado)}
	}
	if p.FechaBloqueo != nil {
		data["FechaBloqueo"] = []string{translate(*p.FechaBloqueo)}
	}
	if p.DescripcionBloqueo != nil {
		data[LockedDescription] = []string{translate(*p.DescripcionBloqueo)}
	}
	return data
}

func PatchByEmail(email string, data *PatchData) error {
	d := data.ToMap()
	if len(d) == 0 {
		return nil
	}

	l, err := connectAsAdmin()
	if err != nil {
		return err
	}
	defer l.Close()

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", email),
		[]string{""},
		nil,
	))
	if err != nil {
		return err
	}

	if len(sr.Entries) == 0 {
		return ErrUserNotFound
	}

	entry := sr.Entries[0]
	modify := ldap.NewModifyRequest(entry.DN)
	for k, v := range data.ToMap() {
		modify.Replace(k, v)
	}

	err = l.Modify(modify)
	if err != nil {
		return err
	}

	return nil
}

// IsBlocked checks if user is locked or not
func IsBlocked(email string) (isLocked bool, lockedDescription string, err error) {
	isLocked = false
	lockedDescription = ""
	l, err := connectAsAdmin()
	if err != nil {
		return
	}
	defer l.Close()

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", email),
		[]string{IsLocked, LockedDescription},
		nil,
	))
	if err != nil {
		return
	}

	if len(sr.Entries) == 0 {
		err = ErrUserNotFound
		return
	}
	entry := sr.Entries[0]
	isLocked = entry.GetAttributeValue(IsLocked) == "TRUE"
	if isLocked {
		lockedDescription = entry.GetAttributeValue(LockedDescription)
	}
	return
}

// GetBlockedDescription Check if user is locked and returns the description in case is locked
func GetBlockedDescription(email string) (string, error) {
	l, err := connectAsAdmin()
	if err != nil {
		return "", err
	}
	defer l.Close()

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", email),
		[]string{IsLocked, LockedDescription},
		nil,
	))
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", ErrUserNotFound
	}
	entry := sr.Entries[0]
	if entry.GetAttributeValue(IsLocked) == "TRUE" {
		return entry.GetAttributeValue(LockedDescription), nil
	}
	return "", nil
}

func ResetWorkers() ([]error, error) {
	l, err := connectAsAdmin()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	sr, err := l.Search(ldap.NewSearchRequest(
		"dc=uh,dc=cu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=%s))", WorkerClass),
		[]string{"CI", "uid"},
		nil,
	))
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return []error{errors.New("nothing to reset")}, nil
	}

	var errs []error
	for _, entry := range sr.Entries {
		ci := entry.GetAttributeValue("CI")
		uid := entry.GetAttributeValue("uid")
		err := ResetUser(ci, uid)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs, nil
}
