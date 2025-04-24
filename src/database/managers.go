package database

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/event"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	loggerErr  *log.Logger
	loggerInfo *log.Logger
)

func init() {
	loggerErr = log.New(os.Stderr, "ERROR: ", log.LstdFlags|log.Lmsgprefix)
	loggerInfo = log.New(os.Stdout, "INFO: ", log.LstdFlags|log.Lmsgprefix)
}

// ==========
// Management
// ==========

func InitializeManagementManager(dbURI, id string, debug bool) (*ManagementManager, error) {
	mm := &ManagementManager{}
	mm.closeConnection = make(chan bool, 1)
	mm.scraperID = id
	err := mm.StartDatabase(dbURI, debug)
	if err != nil {
		loggerErr.Println(err)
	}
	return mm, err
}

type ManagementManager struct {
	scraperID                 string
	closeConnection           chan bool
	ctx                       context.Context
	client                    *mongo.Client
	ctxCancel                 context.CancelFunc
	questionsCollection       *mongo.Collection
	storedQuestionsCollection *mongo.Collection
	rolesCollection           *mongo.Collection
	userRolesCollection       *mongo.Collection
	rolesNewCollection        *mongo.Collection
	permissionsCollection     *mongo.Collection
	vpnCollection             *mongo.Collection
	seguridadInformatica      *mongo.Database
}

func (mm *ManagementManager) StartDatabase(dbURI string, debug bool) error {
	mm.ctx, mm.ctxCancel = context.WithTimeout(context.Background(), 3*time.Second)

	opts := options.Client().ApplyURI(dbURI)
	if debug {
		cmdMonitor := &event.CommandMonitor{
			Started: func(_ context.Context, evt *event.CommandStartedEvent) {
				log.Print(evt.Command)
			},
		}
		opts = opts.SetMonitor(cmdMonitor)
	}

	client, err := mongo.Connect(mm.ctx, opts)
	mm.client = client

	if err != nil {
		return err
	}

	if err := client.Ping(mm.ctx, readpref.Primary()); err != nil {
		return err
	}

	mm.questionsCollection = client.Database("questions").Collection("questions")
	mm.storedQuestionsCollection = client.Database("questions").Collection("storedQuestions")
	mm.rolesCollection = client.Database("gestionRoles").Collection("roles")
	mm.userRolesCollection = client.Database("gestionRoles").Collection("userRoles")
	mm.rolesNewCollection = client.Database("gestionRoles").Collection("rolesNew")
	mm.permissionsCollection = client.Database("gestionRoles").Collection("permissions")
	mm.vpnCollection = client.Database("VPN").Collection("user_data")
	mm.seguridadInformatica = client.Database("seguridadInformatica")

	loggerInfo.Println("Successfully connected and pinged")

	return nil
}

func (mm *ManagementManager) Disconnect() error {
	return mm.client.Disconnect(mm.ctx)
}

// =====
// Proxy
// =====

func InitializeProxyManager(dbURI, id string) (*ProxyManager, error) {
	pm := &ProxyManager{}
	pm.closeConnection = make(chan bool, 1)
	pm.scraperID = id
	err := pm.StartDatabase(dbURI)
	if err != nil {
		loggerErr.Println(err)
	}
	return pm, err
}

type ProxyManager struct {
	scraperID              string
	closeConnection        chan bool
	ctx                    context.Context
	client                 *mongo.Client
	ctxCancel              context.CancelFunc
	dbStatusCollection     *mongo.Collection
	historyCollection      *mongo.Collection
	currentMonthCollection *mongo.Collection
	freeCollection         *mongo.Collection
}

func (m *ProxyManager) StartDatabase(dbUri string) error {
	m.ctx, m.ctxCancel = context.WithTimeout(context.Background(), 3*time.Second)

	client, err := mongo.Connect(m.ctx, options.Client().ApplyURI(dbUri))
	m.client = client

	if err != nil {
		return err
	}

	if err := client.Ping(m.ctx, readpref.Primary()); err != nil {
		return err
	}

	m.dbStatusCollection = client.Database("quota").Collection("status")
	m.historyCollection = client.Database("quota").Collection("history")
	m.currentMonthCollection = client.Database("quota").Collection("current_month")
	m.freeCollection = client.Database("quota").Collection("free")

	loggerInfo.Println("Successfully connected and pinged")

	return nil
}

func (m *ProxyManager) Disconnect() error {
	return m.client.Disconnect(m.ctx)
}
