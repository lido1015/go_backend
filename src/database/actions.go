package database

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
)

// ==========
// Management
// ==========

// GetSecurityQuestions return the security questions saved in db or []string empty if error
func (mm *ManagementManager) GetSecurityQuestions() ([]Question, error) {
	var questions []Question
	// Load security questions from db
	if cur, err := mm.questionsCollection.Find(context.Background(), bson.D{}); err != nil {
		loggerErr.Println(err)
		return nil, ErrUnexpected
	} else if err := cur.All(context.TODO(), &questions); err != nil {
		loggerErr.Println(err)
		return nil, ErrUnexpected
	}
	return questions, nil
}

// GetUserSecurityQuestions return the security questions saved in db or []string empty if error of one user
func (mm *ManagementManager) GetUserSecurityQuestions(userId string) (*StoredQuestions, error) {
	storedQuestions := StoredQuestions{}
	// Load security storedQuestions from db
	if err := mm.storedQuestionsCollection.FindOne(context.Background(), bson.M{"user": userId}).Decode(&storedQuestions); err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			return nil, ErrUserNotFound
		default:
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
	}
	return &storedQuestions, nil
}

// GetSecurityQuestionsLength return the security questions length saved in db or 0 if error
func (mm *ManagementManager) GetSecurityQuestionsLength() (int64, error) {
	// Load security storedQuestions from db
	if number, err := mm.storedQuestionsCollection.CountDocuments(context.Background(), bson.D{}); err != nil {
		return 0, ErrUnexpected
	} else {
		return number, nil
	}
}

// SetSecurityQuestions Save security questions of one user to db
func (mm *ManagementManager) SetSecurityQuestions(storedQuestions StoredQuestions) error {
	// Check questions
	for _, q := range storedQuestions.Questions {
		if result := mm.questionsCollection.FindOne(context.TODO(), bson.M{"question": q.Question}); result.Err() != nil {
			err := result.Err()
			switch err {
			case mongo.ErrNoDocuments:
				return ErrQuestionNotFound
			default:
				loggerErr.Println(err)
				return ErrUnexpected
			}
		}
	}
	// Update if exists
	if result := mm.storedQuestionsCollection.FindOneAndUpdate(context.TODO(), bson.M{"user": storedQuestions.User},
		bson.D{{"$set", bson.D{{"questions", storedQuestions.Questions}}}}); result.Err() != nil {
		err := result.Err()
		switch err {
		case mongo.ErrNoDocuments:
			// Insert security questions
			if _, err := mm.storedQuestionsCollection.InsertOne(context.TODO(), &storedQuestions); err != nil {
				loggerErr.Println(err)
				return ErrUnexpected
			}
		default:
			// Unexpected error
			loggerErr.Println(err)
			return ErrUnexpected
		}
	}
	return nil
}

func (mm *ManagementManager) IsAdmin(userId string) (bool, error) {
	if result := mm.rolesCollection.FindOne(context.TODO(), bson.M{"user": userId}); result.Err() != nil {
		switch result.Err() {
		case mongo.ErrNoDocuments:
			return false, nil
		default:
			loggerErr.Println(result.Err())
			return false, ErrUnexpected
		}
	}
	return true, nil
}

func (mm *ManagementManager) GetUserRole(userId string, loadPermissions bool) (*Role, error) {
	if result := mm.userRolesCollection.FindOne(context.TODO(), bson.M{"user": userId}); result.Err() != nil {
		switch result.Err() {
		case mongo.ErrNoDocuments:
			return nil, nil
		default:
			loggerErr.Println(result.Err())
			return nil, ErrUnexpected
		}
	} else {
		ur := &userRole{}
		if err := result.Decode(ur); err != nil {
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
		role, err := mm.getRole(ur.Role)
		if err != nil {
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
		if !loadPermissions {
			return &Role{
				Name:        role.Name,
				Permissions: nil,
			}, nil
		}
		permissions, err := mm.getPermissions(role.Permissions)
		if err != nil {
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
		result := &Role{
			Name:        role.Name,
			Permissions: []Permission{},
		}
		for _, p := range permissions {
			result.Permissions = append(result.Permissions, Permission(p.Name))
		}
		return result, nil
	}
}

func (mm *ManagementManager) getRole(oId primitive.ObjectID) (*role, error) {
	if result := mm.rolesNewCollection.FindOne(context.TODO(), bson.M{"_id": oId}); result.Err() != nil {
		loggerErr.Println(result.Err())
		return nil, result.Err()
	} else {
		r := &role{}
		if err := result.Decode(&r); err != nil {
			loggerErr.Println(err)
			return nil, err
		}
		return r, nil
	}
}

func (mm *ManagementManager) GetPermissions(roleName string) ([]Permission, error) {
	if result := mm.rolesNewCollection.FindOne(context.TODO(), bson.M{"name": roleName}); result.Err() != nil {
		loggerErr.Println(result.Err())
		return nil, result.Err()
	} else {
		r := &role{}
		if err := result.Decode(&r); err != nil {
			loggerErr.Println(err)
			return nil, err
		}
		if p, err := mm.getPermissions(r.Permissions); err != nil {
			loggerErr.Println(err)
			return nil, err
		} else {
			var out []Permission
			for _, x := range p {
				out = append(out, Permission(x.Name))
			}
			return out, nil
		}
	}
}

func (mm *ManagementManager) getPermissions(oIds []primitive.ObjectID) ([]permission, error) {
	var permissions []permission
	if cursor, err := mm.permissionsCollection.Find(context.TODO(), bson.M{"_id": bson.D{{"$in", oIds}}}); err != nil {
		return nil, err
	} else if err = cursor.All(context.TODO(), &permissions); err != nil {
		return nil, err
	} else {
		return permissions, nil
	}
}

func (mm *ManagementManager) SetRole(userId string, roleId string) error {
	id, err := primitive.ObjectIDFromHex(roleId)
	if err != nil {
		return ErrInvalidId
	}
	// Check if role exists
	if err := mm.rolesNewCollection.FindOne(context.TODO(), bson.M{"_id": id}).Err(); err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			return ErrRoleNotFound
		default:
			loggerErr.Println(err)
			return ErrUnexpected
		}
	}
	if err := mm.userRolesCollection.FindOneAndUpdate(context.TODO(), bson.M{"user": userId}, bson.D{{"$set", bson.D{{"role", id}}}}).Err(); err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			if _, err := mm.userRolesCollection.InsertOne(context.TODO(), &userRole{
				User: userId,
				Role: id,
			}); err != nil {
				loggerErr.Println(err)
				return ErrUnexpected
			}
		default:
			loggerErr.Println(err)
			return ErrUnexpected
		}
	}
	return nil
}

func (mm *ManagementManager) GetRoles() ([]SimpleRole, error) {
	var _out []role
	var out []SimpleRole
	if cursor, err := mm.rolesNewCollection.Find(context.TODO(), bson.M{}); err != nil {
		loggerErr.Println(err)
		return nil, ErrUnexpected
	} else if err := cursor.All(context.TODO(), &_out); err != nil {
		loggerErr.Println(err)
		return nil, ErrUnexpected
	} else {
		for _, r := range _out {
			out = append(out, SimpleRole{
				Id:   r.Id.Hex(),
				Name: r.Name,
			})
		}
		return out, nil
	}
}

// ChangeUserEmail change user email in gestionRoles/userRoles and in questions/storedQuestions collections.
func (mm *ManagementManager) ChangeUserEmail(old, new string) error {
	// Start session and configuration for transaction
	wc := writeconcern.New(writeconcern.WMajority())
	rc := readconcern.Snapshot()
	txnOptions := options.Transaction().SetWriteConcern(wc).SetReadConcern(rc)
	session, err := mm.client.StartSession()
	if err != nil {
		loggerErr.Println(err)
		return ErrUnexpected
	}
	defer session.EndSession(context.Background())

	// Do transaction
	err = mongo.WithSession(context.Background(), session, func(sessionContext mongo.SessionContext) error {
		// Start transaction
		if err = session.StartTransaction(txnOptions); err != nil {
			return err
		}
		// Change in roles
		result := mm.userRolesCollection.FindOneAndUpdate(
			context.TODO(),
			bson.M{"user": old},
			bson.D{
				{"$set", bson.D{{"user", new}}},
			})
		err := result.Err()
		if err != nil && err != mongo.ErrNoDocuments {
			loggerErr.Println(err)
			return ErrUnexpected
		}
		// Change stored questions
		result = mm.storedQuestionsCollection.FindOneAndUpdate(
			context.TODO(),
			bson.M{"user": old},
			bson.D{
				{"$set", bson.D{{"user", new}}},
			})
		err = result.Err()
		if err != nil {
			switch err {
			case mongo.ErrNoDocuments:
				return nil
			default:
				loggerErr.Println(err)
				return ErrUnexpected
			}
		}
		// Try commit transaction
		if err = session.CommitTransaction(sessionContext); err != nil {
			return err
		}
		return nil
	})

	// Abort transaction if error occurred
	if err != nil {
		if abortErr := session.AbortTransaction(context.Background()); abortErr != nil {
			panic(abortErr)
		}
	}
	return nil
}

func (mm *ManagementManager) GetVpnData(ci string) (*VpnUserData, error) {
	result := mm.vpnCollection.FindOne(context.Background(), bson.M{"ci": ci})
	if result.Err() != nil {
		err := result.Err()
		switch result.Err() {
		case mongo.ErrNoDocuments:
			return nil, ErrUserNotFound
		default:
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
	}
	var userData VpnUserData
	if err := result.Decode(&userData); err != nil {
		loggerErr.Println(err)
		return nil, ErrUnexpected
	}
	return &userData, nil
}

type BlockedUserItem struct {
	UserId  string `bson:"userId"`
	Comment string `bson:"comment"`
	Start   int64  `bson:"start"`
	End     int64  `bson:"end"`
}

func (mm *ManagementManager) AddUserToCurrentBlocks(data BlockedUserItem) error {
	currentBlockCollection := mm.seguridadInformatica.Collection("bloqueosActuales")
	_, err := currentBlockCollection.InsertOne(
		context.Background(),
		data)
	if err != nil {
		loggerErr.Println(err)
		return ErrUnexpected
	}
	return nil
}

func (mm *ManagementManager) UnblockUser(userId string) error {
	currentBlock := mm.seguridadInformatica.Collection("bloqueosActuales")
	blockHistory := mm.seguridadInformatica.Collection("bloqueosHistorial")
	session, err := mm.client.StartSession()
	if err != nil {
		loggerErr.Println(err)
		return ErrUnexpected
	}
	defer session.EndSession(context.Background())

	wc := writeconcern.New(writeconcern.WMajority())
	rc := readconcern.Snapshot()
	txnOpts := options.Transaction().SetWriteConcern(wc).SetReadConcern(rc)

	err = mongo.WithSession(context.Background(), session, func(sessionContext mongo.SessionContext) error {
		if err := session.StartTransaction(txnOpts); err != nil {
			return err
		}
		var item BlockedUserItem
		if err := currentBlock.FindOneAndDelete(context.Background(), bson.M{"userId": userId}).Decode(&item); err != nil {
			return err
		}
		item.End = time.Now().Unix()
		if _, err := blockHistory.InsertOne(context.Background(), item); err != nil {
			return err
		}
		if err := session.CommitTransaction(sessionContext); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if abortErr := session.AbortTransaction(context.Background()); abortErr != nil {
			loggerErr.Println(err)
			return ErrUnexpected
		}
		if err == mongo.ErrNoDocuments {
			return ErrUserNotFound
		}
		return ErrUnexpected
	}
	return nil
}

// =====
// Proxy
// =====

func (m *ProxyManager) InsertQuotaLog(quotaLog *QuotaLog) error {
	if _, err := m.historyCollection.InsertOne(context.TODO(), quotaLog); err != nil {
		loggerErr.Panicln(err)
		return ErrUnexpected
	}
	m.updateLastDateTime(quotaLog.DateTime)
	return nil
}

func (m *ProxyManager) updateLastDateTime(lastDateTime float64) {
	if _, err := m.dbStatusCollection.UpdateOne(
		context.Background(),
		bson.M{"prop": "lastDateTime", "scraperid": m.scraperID},
		bson.D{
			{"$set", bson.D{{"value", lastDateTime}}},
		},
	); err != nil {
		loggerErr.Println(err)
	}
}

func (m *ProxyManager) GetLastDateTime() float64 {
	lastDateTime := DBProperty{}
	// Load db status
	if err := m.dbStatusCollection.FindOne(context.Background(), bson.M{"prop": "lastDateTime", "scraperid": m.scraperID}).Decode(&lastDateTime); err != nil {
		if err == mongo.ErrNoDocuments {
			lastDateTime = DBProperty{
				ScraperID: m.scraperID,
				Prop:      "lastDateTime",
				Value:     0,
			}
			// Create db status
			if _, err := m.dbStatusCollection.InsertOne(context.TODO(), lastDateTime); err != nil {
				loggerErr.Println(err)
			}
		} else {
			loggerErr.Println(err)
		}
		return 0
	}
	switch t := lastDateTime.Value.(type) {
	case float64:
		return t
	default:
		return 0
	}
}

func (m *ProxyManager) GetProxyQuota(user string) (*QuotaMonth, error) {
	result := m.currentMonthCollection.FindOne(
		context.Background(),
		bson.M{"user": user},
	)
	err := result.Err()
	switch err {
	case nil:
		quotaMonth := QuotaMonth{}
		if err = result.Decode(&quotaMonth); err != nil {
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
		return &quotaMonth, nil
	case mongo.ErrNoDocuments:
		return nil, ErrUserNotFound
	default:
		loggerErr.Println(err)
		return nil, ErrUnexpected
	}
}

func (m *ProxyManager) UpdateConsume(user string, increase int64) (*QuotaMonth, error) {
	result := m.currentMonthCollection.FindOneAndUpdate(
		context.Background(),
		bson.M{"user": user},
		bson.D{
			{"$inc", bson.D{{"consumed", increase}}},
		})
	err := result.Err()
	switch err {
	case nil:
		quotaMonth := QuotaMonth{}
		if err = result.Decode(&quotaMonth); err != nil {
			loggerErr.Println(err)
			return nil, ErrUnexpected
		}
		return &quotaMonth, nil
	case mongo.ErrNoDocuments:
		return nil, ErrUserNotFound
	default:
		loggerErr.Println(err)
		return nil, ErrUnexpected
	}
}

func (m *ProxyManager) DisableCurrentMonth(user string) error {
	result := m.currentMonthCollection.FindOneAndUpdate(
		context.Background(),
		bson.M{"user": user},
		bson.D{
			{"$set", bson.D{{"enabled", false}}},
			{"$set", bson.D{{"cutter", m.scraperID}}},
		})
	err := result.Err()
	switch err {
	case nil:
		return nil
	case mongo.ErrNoDocuments:
		return ErrUserNotFound
	default:
		loggerErr.Println(err)
		return ErrUnexpected
	}
}

func (m *ProxyManager) GetAllFree() []FreeItem {
	var free []FreeItem
	if cur, err := m.freeCollection.Find(context.Background(), bson.D{}); err != nil {
		loggerErr.Println(err)
	} else if err = cur.All(context.TODO(), &free); err != nil {
		loggerErr.Println(err)
	}
	return free
}

// ChangeUserEmail change user email in quota/current_month collection
func (m *ProxyManager) ChangeUserEmail(old, new string) error {
	result := m.currentMonthCollection.FindOneAndUpdate(
		context.TODO(),
		bson.M{"user": old},
		bson.D{
			{"$set", bson.D{{"user", new}}},
		})
	err := result.Err()
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			// If user does not exist, do nothing
			return nil
		default:
			loggerErr.Println(err)
			return ErrUnexpected
		}
	}
	return nil
}
