package main

import (
	"context"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

// GoogleCloudIAMService is the service that allows to create service accounts
type GoogleCloudIAMService struct {
	service *iam.Service
	// project string
	// zone    string
}

// NewGoogleCloudIAMService returns an initialized GoogleCloudIAMService
func NewGoogleCloudIAMService() *GoogleCloudIAMService {

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
		service: iamService,
		// project: project,
		// zone:    zone,
	}
}

// CreateServiceAccount creates a service account
func (iamService *GoogleCloudIAMService) CreateServiceAccount(serviceAccountName string) (name string, err error) {

	resp, err := iamService.service.Projects.ServiceAccounts.Create(serviceAccountName, &iam.CreateServiceAccountRequest{}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	name = resp.Name

	// ServiceAccount serviceAccount = s_iam.Projects.ServiceAccounts
	// .Create(request, "projects/" + projectId).Execute();

	// resp, err := dnsService.service.Changes.Create(dnsService.project, dnsService.zone, &change).Context(context.Background()).Do()

	// var request = new CreateServiceAccountRequest
	// {
	// 		AccountId = name,
	// 		ServiceAccount = new ServiceAccount
	// 		{
	// 				DisplayName = displayName
	// 		}
	// };

	// POST https://iam.googleapis.com/v1/projects/[PROJECT-ID]/serviceAccounts

	// {
	//   "accountId": "[SA-NAME]",
	//   "serviceAccount": {
	//       "displayName": "[SA-DISPLAY-NAME]",
	//   }
	// }

	// response:

	// {
	//   "name": "projects/PROJECT-ID/serviceAccounts/SA-NAME@PROJECT-ID.iam.gserviceaccount.com",
	//   "projectId": "PROJECT-ID",
	//   "uniqueId": "113948692397867021414",
	//   "email": "SA-NAME@PROJECT-ID.iam.gserviceaccount.com",
	//   "displayName": "SA-DISPLAY-NAME",
	//   "etag": "BwUp3rVlzes=",
	//   "oauth2ClientId": "117249000288840666939"
	// }

	return
}

// CreateServiceAccountKey creates a key file for an existing account
func (iamService *GoogleCloudIAMService) CreateServiceAccountKey(name string) (keyfile string, err error) {

	resp, err := iamService.service.Projects.ServiceAccounts.Keys.Create(name, &iam.CreateServiceAccountKeyRequest{}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	keyfile = resp.PrivateKeyData

	// ServiceAccountKey key = s_service.Projects.ServiceAccounts.Keys.Create(
	// 	new CreateServiceAccountKeyRequest(),
	// 	"projects/-/serviceAccounts/" + serviceAccountEmail)
	// 	.Execute();

	// POST https://iam.googleapis.com/v1/projects/[PROJECT-ID]/serviceAccounts/[SA-NAME]@[PROJECT-ID].iam.gserviceaccount.com/keys

	// response:

	// {
	//   "name":"projects/PROJECT-ID/serviceAccounts/SA-NAME@PROJECT-ID.iam.gserviceaccount.com/keys/90c48f61c65cd56224a12ab18e6ee9ca9c3aee7c",
	//   "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
	//   "privateKeyData":"MIIJqAIB . . .",
	//   "validBeforeTime": "2028-05-08T21:00:00Z",
	//   "validAfterTime": "2016-01-25T18:38:09.000Z",
	//   "keyAlgorithm": "KEY_ALG_RSA_2048"
	// }

	return
}

// CreateServiceAccountWithKey creates a service account with key file and returns the key file
func (iamService *GoogleCloudIAMService) CreateServiceAccountWithKey(serviceAccountName string) (name string, keyfile string, err error) {

	name, err = iamService.CreateServiceAccount(serviceAccountName)
	if err != nil {
		return
	}

	keyfile, err = iamService.CreateServiceAccountKey(name)
	if err != nil {
		return
	}

	return
}

// DeleteServiceAccount deletes a service account
func (iamService *GoogleCloudIAMService) DeleteServiceAccount(serviceAccountName string) (deleted bool, err error) {

	// DELETE https://iam.googleapis.com/v1/projects/[PROJECT-ID]/serviceAccounts/[SA-NAME]@[PROJECT-ID].iam.gserviceaccount.com

	resp, err := iamService.service.Projects.ServiceAccounts.Delete(serviceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	if resp.HTTPStatusCode == 200 {
		deleted = true
	}

	return
}
