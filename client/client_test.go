package client

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv(appAPIKeyEnvVar, "service-key")
	os.Exit(m.Run())
}
