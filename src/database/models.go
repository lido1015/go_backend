package database

import "go.mongodb.org/mongo-driver/bson/primitive"

// ==========
// Management
// ==========

type Question struct {
	Question string
}

type StoredQuestion struct {
	Question string
	Answer   string
}

type StoredQuestions struct {
	User      string
	Questions []StoredQuestion
}

type Permission string

type SimpleRole struct {
	Id   string
	Name string
}

type Role struct {
	Name        string
	Permissions []Permission
}

type userRole struct {
	User string
	Role primitive.ObjectID
}

type role struct {
	Id          primitive.ObjectID   `bson:"_id"`
	Name        string               `bson:"name"`
	Permissions []primitive.ObjectID `bson:"permissions"`
}

type permission struct {
	Name string
}

type VpnUserData struct {
	Id       primitive.ObjectID `bson:"_id"`
	LastName string             `bson:"apellidos"`
	Ci       string             `bson:"ci"`
	Ip       string             `bson:"ip"`
	Name     string             `bson:"nombres"`
	Uid      string             `bson:"uid"`
	CA       string             `bson:"CA"`
	CERT     string             `bson:"CERT"`
	KEY      string             `bson:"KEY"`
	TLS      string             `bson:"TLS"`
}

// =====
// Proxy
// =====

type QuotaLog struct {
	DateTime float64
	User     string
	Size     int64
	URL      string
	From     string
}

type QuotaMonth struct {
	User     string
	Max      int64
	Consumed int64
	Enabled  bool
}

type DBProperty struct {
	ScraperID string
	Prop      string
	Value     interface{}
}

type FreeItem struct {
	Regex *string
}
