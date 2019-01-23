package main

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

// GoogleCloudIAMService is the service that allows to create service accounts
type GoogleCloudIAMService struct {
	service              *iam.Service
	projectID            string
	serviceAccountPrefix string
}

// NewGoogleCloudIAMService returns an initialized GoogleCloudIAMService
func NewGoogleCloudIAMService(projectID, serviceAccountPrefix string) *GoogleCloudIAMService {

	ctx := context.Background()
	googleClient, err := google.DefaultClient(ctx, iam.CloudPlatformScope)
	if err != nil {
		log.Fatal().Err(err).Msg("Creating google cloud client failed")
	}

	iamService, err := iam.New(googleClient)
	if err != nil {
		log.Fatal().Err(err).Msg("Creating google cloud iam service failed")
	}

	return &GoogleCloudIAMService{
		service:              iamService,
		projectID:            projectID,
		serviceAccountPrefix: serviceAccountPrefix,
	}
}

// CreateServiceAccount creates a service account
func (iamService *GoogleCloudIAMService) CreateServiceAccount(serviceAccountName string) (fullServiceAccountName string, err error) {

	if len(serviceAccountName) < 3 {
		return "", fmt.Errorf("Service account name %v is too short; set at least name of 3 characters or more in the estafette.io/gcp-service-account-name annotation", serviceAccountName)
	}

	// shorted serviceAccountName for account id if needed
	const randomStringLength = 4
	prefixLength := len(*serviceAccountPrefix)
	maxFirstSectionLength := 30 - randomStringLength - 1 - prefixLength - 1

	shortenedServiceAccountName := serviceAccountName
	if len(shortenedServiceAccountName) > maxFirstSectionLength {
		shortenedServiceAccountName = serviceAccountName[:maxFirstSectionLength]
	}

	randomString := randStringBytesMaskImprSrc(randomStringLength)

	serviceAccount, err := iamService.service.Projects.ServiceAccounts.Create("projects/"+iamService.projectID, &iam.CreateServiceAccountRequest{
		AccountId: fmt.Sprintf("%v-%v-%v", iamService.serviceAccountPrefix, shortenedServiceAccountName, randomString),
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: fmt.Sprintf("%v-%v-%v", iamService.serviceAccountPrefix, serviceAccountName, randomString),
		},
	}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	fullServiceAccountName = serviceAccount.Name

	return
}

// CreateServiceAccountKey creates a key file for an existing account
func (iamService *GoogleCloudIAMService) CreateServiceAccountKey(fullServiceAccountName string) (serviceAccountKey *iam.ServiceAccountKey, err error) {

	serviceAccountKey, err = iamService.service.Projects.ServiceAccounts.Keys.Create(fullServiceAccountName, &iam.CreateServiceAccountKeyRequest{}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	return
}

// CreateServiceAccountWithKey creates a service account with key file and returns the key file
func (iamService *GoogleCloudIAMService) CreateServiceAccountWithKey(serviceAccountName string) (fullServiceAccountName string, serviceAccountKey *iam.ServiceAccountKey, err error) {

	fullServiceAccountName, err = iamService.CreateServiceAccount(serviceAccountName)
	if err != nil {
		return
	}

	serviceAccountKey, err = iamService.CreateServiceAccountKey(fullServiceAccountName)
	if err != nil {
		return
	}

	return
}

// DeleteServiceAccount deletes a service account
func (iamService *GoogleCloudIAMService) DeleteServiceAccount(fullServiceAccountName string) (deleted bool, err error) {

	resp, err := iamService.service.Projects.ServiceAccounts.Delete(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	if resp.HTTPStatusCode == 200 {
		deleted = true
	}

	return
}
