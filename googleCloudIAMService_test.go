package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateFullServiceAccountName(t *testing.T) {
	t.Run("ReturnsTrueIfProjectAndPrefixMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateFullServiceAccountName("projects/my-service-account-container/serviceAccounts/dev-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.True(t, valid)
	})

	t.Run("ReturnsFalseIfFullServiceAccountNameDoesNotMatchURL", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateFullServiceAccountName("organization/my-service-account-container/serviceAccounts/dev-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfProjectDoesNotMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateFullServiceAccountName("projects/another-project/serviceAccounts/dev-my-service-account-asdi@my-service-account-container.iam.gserviceaccount.com")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfProjectInEmailDoesNotMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateFullServiceAccountName("projects/my-service-account-container/serviceAccounts/dev-my-service-account-asdi@another-project.iam.gserviceaccount.com")

		assert.False(t, valid)
	})
}

func TestValidateDisplayName(t *testing.T) {
	t.Run("ReturnsTrueIfProjectAndPrefixMatch", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateDisplayName("my-dev-project/my-service-account")

		assert.True(t, valid)
	})

	t.Run("ReturnsFalseIfDisplayNameDoesNotMatchTemplate", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateDisplayName("not-my-dev-project|my-service-account")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfProjectPartDoesNotMatchLocalProjectID", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		valid := service.validateDisplayName("not-my-dev-project/my-service-account")

		assert.False(t, valid)
	})
}

func TestGetServiceAccountIDAndDisplayName(t *testing.T) {
	t.Run("ReturnsAnErrorWhenNameIsLessThan5Characters", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		_, _, err := service.getServiceAccountIDAndDisplayName("abcd")

		assert.NotNil(t, err)
	})

	t.Run("ReturnsAnErrorWhenNameIsMoreThan69Characters", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		_, _, err := service.getServiceAccountIDAndDisplayName("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqr")

		assert.NotNil(t, err)
	})

	t.Run("ReturnsAccountIDWithEntireNameAndRandomSuffixIfNameIsEqualTo25Characters", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		accountID, _, err := service.getServiceAccountIDAndDisplayName("bcdefghijklmnopqrstuvwxyz")

		assert.Nil(t, err)
		assert.True(t, strings.HasPrefix(accountID, "bcdefghijklmnopqrstuvwxyz-"))
		assert.Equal(t, 30, len(accountID))
	})

	t.Run("ReturnsAccountIDWithEntireNameAndRandomSuffixIfNameIsLessThan25Characters", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		accountID, _, err := service.getServiceAccountIDAndDisplayName("hijklmnopqrst")

		assert.Nil(t, err)
		assert.True(t, strings.HasPrefix(accountID, "hijklmnopqrst-"))
		assert.Equal(t, 18, len(accountID))
	})

	t.Run("ReturnsAccountIDWithShortenedNameAndRandomSuffixIfNameIsLongerThan25Characters", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		accountID, _, err := service.getServiceAccountIDAndDisplayName("abcdefghijklmnopqrstuvwxyz")

		assert.Nil(t, err)
		assert.True(t, strings.HasPrefix(accountID, "abcdefghijklmnopqrstuvwxy-"))
		assert.Equal(t, 30, len(accountID))
	})

	t.Run("ReturnsDisplayNameWithLocalProjectIDSlashNameIfItFitsIn100Characters", func(t *testing.T) {

		service := &GoogleCloudIAMService{
			serviceAccountProjectID: "my-service-account-container",
			localProjectID:          "my-dev-project",
		}

		// act
		_, displayName, err := service.getServiceAccountIDAndDisplayName("my-application")

		assert.Nil(t, err)
		assert.Equal(t, "my-dev-project/my-application", displayName)
		assert.Equal(t, 29, len(displayName))
	})
}
