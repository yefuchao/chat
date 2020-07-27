package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	redis "github.com/go-redis/redis/v8"
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
	//TODO Impl UserGetByCred
	return t.ZeroUid, nil
}

// UserUnreadCount returns the total number of unread messages in all topics with
// the R permission.
func (a *adapter) UserUnreadCount(uid t.Uid) (int, error) {


}
