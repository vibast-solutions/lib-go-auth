package client

import (
	"fmt"
	"os"
	"strings"
)

const appAPIKeyEnvVar = "APP_API_KEY"

func requiredAPIKeyFromEnv() (string, error) {
	apiKey := strings.TrimSpace(os.Getenv(appAPIKeyEnvVar))
	if apiKey == "" {
		return "", fmt.Errorf("%s is required", appAPIKeyEnvVar)
	}
	return apiKey, nil
}
