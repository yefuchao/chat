package redis

import (
	"context"
	"encoding/json"
	"errors"
	redis "github.com/go-redis/redis/v8"
	"log"
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

	return nil
}

// UpgradeDb upgrades database to the current adapter version.
func UpgradeDb() error {
	return nil
}

// Version returns adapter version
func (a *adapter) Version() int {
	return adpVersion
}
