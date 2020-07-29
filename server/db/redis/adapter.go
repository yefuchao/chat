package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	redis "github.com/go-redis/redis/v8"
	"github.com/tinode/chat/server/auth"
	t "github.com/tinode/chat/server/store/types"
	"log"
	"time"
)

type adapter struct {
	conn    *redis.Client
	dbName  string
	version int
	ctx     context.Context
}

const (
	defaultHost = "localhost:6379"
	adapterName = "redis"
	adpVersion  = 0
)

type configType struct {
	Address  string `json:"addresses,omitempty"`
	DB       int    `json:"db,omitempty"`
	UserName string `json:"username,omitempty"`
	Password string `json:"Password,omitempty"`
}

func (a *adapter) Open(jsonConfig json.RawMessage) error {

	if a.conn != nil {
		return errors.New("adapter redis is already connected")
	}

	var err error
	var config configType

	if err = json.Unmarshal(jsonConfig, &config); err != nil {
		return errors.New("adapter failed to parse config: " + err.Error())
	}

	var opts redis.Options

	if config.Address == "" {
		opts.Addr = defaultHost
	} else {
		opts.Addr = config.Address
	}

	opts.DB = config.DB

	if config.UserName != "" {
		opts.Username = config.UserName
	}
	if config.Password != "" {
		opts.Password = config.Password
	}

	a.ctx = context.Background()
	a.conn = redis.NewClient(&opts)

	_, err = a.conn.Ping(a.ctx).Result()

	if err != nil {
		return errors.New("Connect Redis Failed :" + err.Error())
	}

	a.version = -1

	return nil
}

func (a *adapter) Close() error {
	err := a.conn.Close()
	return err
}

func (a *adapter) IsOpen() bool {
	return a.conn != nil
}

func (a *adapter) GetDbVersion() (int, error) {
	//TODO GetDbVersion
	return 0, nil
}
func (a *adapter) CheckDbVersion() error {
	//TODO CheckDbVersion()
	return nil
}

func (a *adapter) GetName() string {
	return adapterName
}

// SetMaxResults configures how many results can be returned in a single DB call.
func (a *adapter) SetMaxResults(val int) error {

	return nil
}

// CreateDb creates the database optionally dropping an existing database first.
func (a *adapter) CreateDb(reset bool) error {
	if reset {
		r := a.conn.FlushAll(a.ctx)
		log.Println(r.Result())
	}
	//TODO IMPL CreateDb
	return nil
}

// UpgradeDb upgrades database to the current adapter version.
func UpgradeDb() error {
	//TODO IMPL UpgradeDb
	return nil
}

// Version returns adapter version
func (a *adapter) Version() int {
	return adpVersion
}

// User management

// UserCreate creates user record
func (a *adapter) UserCreate(user *t.User) error {

	key := "user_" + user.Id

	_, err := a.conn.Set(a.ctx, key, user, 0).Result()

	return err
}

// UserGet returns record for a given user ID
func (a *adapter) UserGet(uid t.Uid) (*t.User, error) {

	v, err := a.conn.Get(a.ctx, "user_"+uid.String()).Result()

	var user t.User

	err = json.Unmarshal([]byte(v), &user)

	return &user, err
}

// UserGetAll returns user records for a given list of user IDs
func (a *adapter) UserGetAll(ids ...t.Uid) ([]t.User, error) {

	idsStr := make([]string, 0)

	for i := 0; i < len(ids); i++ {
		idsStr = append(idsStr, "user_"+ids[i].String())
	}

	values, err := a.conn.MGet(a.ctx, idsStr...).Result()

	if err != nil {
		return nil, err
	}

	users := make([]t.User, len(values))

	for i := 0; i < len(values); i++ {
		b, err := getBytes(values[i])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(b, &users[i])
		if err != nil {
			return nil, err
		}
	}

	return users, nil
}

func getBytes(key interface{}) ([]byte, error) {

	str := fmt.Sprintf("%v", key)

	return []byte(str), nil

}

// UserDelete deletes user record
func (a *adapter) UserDelete(uid t.Uid, hard bool) error {
	//TODO Impl UserDelete
	return nil
}

// UserUpdate updates user record
func (a *adapter) UserUpdate(uid t.Uid, update map[string]interface{}) error {

	u, err := a.UserGet(uid)

	if err != nil {
		return err
	}

	updateState := false

	for key, value := range update {
		fmt.Println(value)
		switch key {
		case "Devices":
			devices, ok := value.(map[string]*t.DeviceDef)
			if !ok {
				return t.ErrMalformed
			}
			u.Devices = devices
		case "Access":
			access, ok := value.(t.DefaultAccess)
			if !ok {
				return t.ErrMalformed
			}
			u.Access = access
		case "Tags":
			tags, ok := value.(t.StringSlice)
			if !ok {
				return t.ErrMalformed
			}
			u.Tags = tags
		case "LastSeen":
			lastSeen, ok := value.(*time.Time)
			if !ok {
				return t.ErrMalformed
			}
			u.LastSeen = lastSeen
		case "UserAgent":
			userAgent, ok := value.(string)
			if !ok {
				return t.ErrMalformed
			}
			u.UserAgent = userAgent
		case "State":
			state, ok := value.(t.ObjState)
			if !ok {
				return t.ErrMalformed
			}
			u.State = state
			updateState = true
		case "StateAt":
			stateAt, ok := value.(*time.Time)
			if !ok {
				return t.ErrMalformed
			}
			u.StateAt = stateAt
		default:
		}
	}

	if updateState {
		//TODO update topics
	}

	return a.UserCreate(u)
}

// UserUpdateTags adds, removes, or resets user's tags
func (a *adapter) UserUpdateTags(uid t.Uid, add, remove, reset []string) ([]string, error) {

	if reset != nil {
		return reset, a.UserUpdate(uid, map[string]interface{}{"Tags": reset})
	}

	u, err := a.UserGet(uid)
	if err != nil {
		return nil, err
	}

	if len(add) > 0 {
		u.Tags = union(u.Tags, add)
	}

	if len(remove) > 0 {
		u.Tags = diff(u.Tags, remove)
	}

	a.UserUpdate(uid, map[string]interface{}{"Tags": u.Tags})

	u, err = a.UserGet(uid)

	if err != nil {
		return nil, err
	}

	return u.Tags, nil
}

func contains(a []string, b string) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == b {
			return true
		}
	}
	return false
}

func union(newTags []string, add []string) []string {
	for i := 0; i < len(add); i++ {
		if !contains(newTags, add[i]) {
			newTags = append(newTags, add[i])
		}
	}
	return newTags
}

func diff(userTags []string, remove []string) []string {
	newTags := make([]string, 0)

	for _, tag := range userTags {
		if !contains(remove, tag) {
			newTags = append(newTags, tag)
		}
	}

	return newTags
}

// UserGetByCred returns user ID for the given validated credential.
func (a *adapter) UserGetByCred(method, value string) (t.Uid, error) {

	r, err := a.conn.Get(a.ctx, "cred_"+method+"_"+value).Result()

	if err != nil {
		return t.ZeroUid, err
	}

	var c *t.Credential

	err = json.Unmarshal([]byte(r), c)

	if err != nil {
		return t.ZeroUid, err
	}

	var uid t.Uid
	err = uid.UnmarshalText([]byte(c.User))
	if err != nil {
		return 0, err
	}

	return uid, nil
}

// UserUnreadCount returns the total number of unread messages in all topics with
// the R permission.
func (a *adapter) UserUnreadCount(uid t.Uid) (int, error) {
	//TODO Impl UserUnreadCount
	return 0, nil
}

// Credential management
// CredUpsert adds or updates a credential record. Returns true if record was inserted, false if updated.
func (a *adapter) CredUpsert(cred *t.Credential) (bool, error) {

	_, err := a.conn.Set(a.ctx, "cred_"+cred.Method+"_"+cred.Value+"_"+cred.User, cred, 0).Result()

	return err != nil, err
}

// CredGetActive returns the currently active credential record for the given method.
func (a *adapter) CredGetActive(uid t.Uid, method string) (*t.Credential, error) {

	key := "cred_" + method + "_*_" + uid.String()

	v, _, err := a.conn.Scan(a.ctx, 0, key, 0).Result()
	if err != nil {
		return nil, err
	}

	if len(v) == 0 {
		return nil, errors.New("not found")
	}

	r, err := a.conn.Get(a.ctx, v[0]).Result()

	if err != nil {
		return nil, err
	}

	var cred t.Credential

	err = json.Unmarshal([]byte(r), &cred)

	if err != nil {
		return nil, err
	}

	return &cred, nil
}

// CredGetAll returns credential records for the given user and method, validated only or all.
func (a *adapter) CredGetAll(uid t.Uid, method string, validatedOnly bool) ([]t.Credential, error) {
	return nil, nil
}

// CredDel deletes credentials for the given method/value. If method is empty, deletes all
// user's credentials.
func (a *adapter) CredDel(uid t.Uid, method, value string) error {
	return nil
}

// CredConfirm marks given credential as validated.
func (a *adapter) CredConfirm(uid t.Uid, method string) error {
	return nil
}

// CredFail increments count of failed validation attepmts for the given credentials.
func (a *adapter) CredFail(uid t.Uid, method string) error {
	return nil
}

// Authentication management for the basic authentication scheme

// AuthGetUniqueRecord returns authentication record for a given unique value i.e. login.
func (a *adapter) AuthGetUniqueRecord(unique string) (t.Uid, auth.Level, []byte, time.Time, error) {
	return t.ZeroUid, 0, nil, time.Now(), nil
}

// AuthGetRecord returns authentication record given user ID and method.
func (a *adapter) AuthGetRecord(user t.Uid, scheme string) (string, auth.Level, []byte, time.Time, error) {
	return "", 0, nil, time.Now(), nil
}

// AuthAddRecord creates new authentication record
func (a *adapter) AuthAddRecord(user t.Uid, scheme, unique string, authLvl auth.Level, secret []byte, expires time.Time) error {
	return nil
}

// AuthDelScheme deletes an existing authentication scheme for the user.
func (a *adapter) AuthDelScheme(user t.Uid, scheme string) error {
	return nil
}

// AuthDelAllRecords deletes all records of a given user.
func (a *adapter) AuthDelAllRecords(uid t.Uid) (int, error) {
	return 0, nil
}

// AuthUpdRecord modifies an authentication record.
func (a *adapter) AuthUpdRecord(user t.Uid, scheme, unique string, authLvl auth.Level, secret []byte, expires time.Time) error {
	return nil
}

// Topic management

// TopicCreate creates a topic
func (a *adapter) TopicCreate(topic *t.Topic) error {
	return nil
}

// TopicCreateP2P creates a p2p topic
func (a *adapter) TopicCreateP2P(initiator, invited *t.Subscription) error {
	return nil
}

// TopicGet loads a single topic by name, if it exists. If the topic does not exist the call returns (nil, nil)
func (a *adapter) TopicGet(topic string) (*t.Topic, error) {
	return nil, nil
}

// TopicsForUser loads subscriptions for a given user. Reads public value.
func (a *adapter) TopicsForUser(uid t.Uid, keepDeleted bool, opts *t.QueryOpt) ([]t.Subscription, error) {
	return nil, nil
}

// UsersForTopic loads users' subscriptions for a given topic. Public is loaded.
func (a *adapter) UsersForTopic(topic string, keepDeleted bool, opts *t.QueryOpt) ([]t.Subscription, error) {
	return nil, nil
}

// OwnTopics loads a slice of topic names where the user is the owner.
func (a *adapter) OwnTopics(uid t.Uid) ([]string, error) {
	return nil, nil
}

// TopicShare creates topc subscriptions
func (a *adapter) TopicShare(subs []*t.Subscription) error {
	return nil
}

// TopicDelete deletes topic, subscription, messages
func (a *adapter) TopicDelete(topic string, hard bool) error {
	return nil
}

// TopicUpdateOnMessage increments Topic's or User's SeqId value and updates TouchedAt timestamp.
func (a *adapter) TopicUpdateOnMessage(topic string, msg *t.Message) error {
	return nil
}

// TopicUpdate updates topic record.
func (a *adapter) TopicUpdate(topic string, update map[string]interface{}) error {
	return nil
}

// TopicOwnerChange updates topic's owner
func (a *adapter) TopicOwnerChange(topic string, newOwner t.Uid) error {
	return nil
}

// Topic subscriptions

// SubscriptionGet reads a subscription of a user to a topic
func (a *adapter) SubscriptionGet(topic string, user t.Uid) (*t.Subscription, error) {
	return nil, nil
}

// SubsForUser gets a list of topics of interest for a given user. Does NOT load Public value.
func (a *adapter) SubsForUser(user t.Uid, keepDeleted bool, opts *t.QueryOpt) ([]t.Subscription, error) {
	return nil, nil
}

// SubsForTopic gets a list of subscriptions to a given topic.. Does NOT load Public value.
func (a *adapter) SubsForTopic(topic string, keepDeleted bool, opts *t.QueryOpt) ([]t.Subscription, error) {
	return nil, nil
}

// SubsUpdate updates pasrt of a subscription object. Pass nil for fields which don't need to be updated
func (a *adapter) SubsUpdate(topic string, user t.Uid, update map[string]interface{}) error {
	return nil
}

// SubsDelete deletes a single subscription
func (a *adapter) SubsDelete(topic string, user t.Uid) error {
	return nil
}

// SubsDelForTopic deletes all subscriptions to the given topic
func (a *adapter) SubsDelForTopic(topic string, hard bool) error {
	return nil
}

// SubsDelForUser deletes or marks as deleted all subscriptions of the given user.
func (a *adapter) SubsDelForUser(user t.Uid, hard bool) error {
	return nil
}

// Search

// FindUsers searches for new contacts given a list of tags
func (a *adapter) FindUsers(user t.Uid, req [][]string, opt []string) ([]t.Subscription, error) {
	return nil, nil
}

// FindTopics searches for group topics given a list of tags
func (a *adapter) FindTopics(req [][]string, opt []string) ([]t.Subscription, error) {
	return nil, nil
}

// Messages

// MessageSave saves message to database
func (a *adapter) MessageSave(msg *t.Message) error {
	return nil
}

// MessageGetAll returns messages matching the query
func (a *adapter) MessageGetAll(topic string, forUser t.Uid, opts *t.QueryOpt) ([]t.Message, error) {
	return nil, nil
}

// MessageDeleteList marks messages as deleted.
// Soft- or Hard- is defined by forUser value: forUSer.IsZero == true is hard.
func (a *adapter) MessageDeleteList(topic string, toDel *t.DelMessage) error {
	return nil
}

// MessageGetDeleted returns a list of deleted message Ids.
func (a *adapter) MessageGetDeleted(topic string, forUser t.Uid, opts *t.QueryOpt) ([]t.DelMessage, error) {
	return nil, nil
}

// MessageAttachments connects given message to a list of file record IDs.
func (a *adapter) MessageAttachments(msgId t.Uid, fids []string) error {
	return nil
}

// Devices (for push notifications)

// DeviceUpsert creates or updates a device record
func (a *adapter) DeviceUpsert(uid t.Uid, dev *t.DeviceDef) error {
	return nil
}

// DeviceGetAll returns all devices for a given set of users
func (a *adapter) DeviceGetAll(uid ...t.Uid) (map[t.Uid][]t.DeviceDef, int, error) {
	return nil, 0, nil
}

// DeviceDelete deletes a device record
func (a *adapter) DeviceDelete(uid t.Uid, deviceID string) error {
	return nil
}

// File upload records. The files are stored outside of the database.

// FileStartUpload initializes a file upload
func (a *adapter) FileStartUpload(fd *t.FileDef) error {
	return nil
}

// FileFinishUpload marks file upload as completed, successfully or otherwise.
func (a *adapter) FileFinishUpload(fid string, status int, size int64) (*t.FileDef, error) {
	return nil, nil
}

// FileGet fetches a record of a specific file
func (a *adapter) FileGet(fid string) (*t.FileDef, error) {
	return nil, nil
}

// FileDeleteUnused deletes records where UseCount is zero. If olderThan is non-zero, deletes
// unused records with UpdatedAt before olderThan.
// Returns array of FileDef.Location of deleted filerecords so actual files can be deleted too.
func (a *adapter) FileDeleteUnused(olderThan time.Time, limit int) ([]string, error) {
	return nil, nil
}
