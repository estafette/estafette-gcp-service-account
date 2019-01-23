package main

import (
	"context"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

// GoogleCloudIAMService is the service that allows to create service accounts
type GoogleCloudIAMService struct {
	service   *iam.Service
	projectID string
}

// NewGoogleCloudIAMService returns an initialized GoogleCloudIAMService
func NewGoogleCloudIAMService(projectID string) *GoogleCloudIAMService {

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
		service:   iamService,
		projectID: projectID,
	}
}

// CreateServiceAccount creates a service account
func (iamService *GoogleCloudIAMService) CreateServiceAccount(serviceAccountName string) (fullServiceAccountName string, err error) {

	serviceAccount, err := iamService.service.Projects.ServiceAccounts.Create("projects/"+iamService.projectID, &iam.CreateServiceAccountRequest{
		AccountId: serviceAccountName,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: serviceAccountName,
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
