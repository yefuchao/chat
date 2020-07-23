package redis

import (
	"context"
	"github.com/go-redis/redis/v8"
	"testing"
)


func Test_adapter_GetDbVersion(t *testing.T) {
	type fields struct {
		conn    *redis.Client
		dbName  string
		version int
		ctx     context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &adapter{
				conn:    tt.fields.conn,
				dbName:  tt.fields.dbName,
				version: tt.fields.version,
				ctx:     tt.fields.ctx,
			}
			got, err := a.GetDbVersion()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDbVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetDbVersion() got = %v, want %v", got, tt.want)
			}
		})
	}
}