package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateFullServiceAccountName(t *testing.T) {
	t.Run("ReturnsTrueIfProjectAndPrefixMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			projectID:            "my-service-account-container",
			serviceAccountPrefix: "dev",
		}

		// act
		valid := service.ValidateFullServiceAccountName("projects/my-service-account-container/serviceAccounts/dev-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.True(t, valid)
	})

	t.Run("ReturnsFalseIfFullServiceAccountNameDoesNotMatchURL", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			projectID:            "my-service-account-container",
			serviceAccountPrefix: "dev",
		}

		// act
		valid := service.ValidateFullServiceAccountName("organization/my-service-account-container/serviceAccounts/dev-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfProjectDoesNotMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			projectID:            "my-service-account-container",
			serviceAccountPrefix: "dev",
		}

		// act
		valid := service.ValidateFullServiceAccountName("projects/another-project/serviceAccounts/dev-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfProjectInEmailDoesNotMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			projectID:            "my-service-account-container",
			serviceAccountPrefix: "dev",
		}

		// act
		valid := service.ValidateFullServiceAccountName("projects/my-service-account-container/serviceAccounts/dev-my-service-account-asdi@another-project.iam.gserviceaccount.com")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfAccountNameIsNotPrefixedWithCorrectPrefix", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			projectID:            "my-service-account-container",
			serviceAccountPrefix: "dev",
		}

		// act
		valid := service.ValidateFullServiceAccountName("projects/my-service-account-container/serviceAccounts/stg-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.False(t, valid)
	})
}
