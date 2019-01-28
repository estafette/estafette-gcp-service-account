package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

// GoogleCloudIAMService is the service that allows to create service accounts
type GoogleCloudIAMService struct {
	service              *iam.Service
	watcher              *fsnotify.Watcher
	projectID            string
	serviceAccountPrefix string
}

// NewGoogleCloudIAMService returns an initialized GoogleCloudIAMService
func NewGoogleCloudIAMService(projectID, serviceAccountPrefix string) (*GoogleCloudIAMService, error) {

	ctx := context.Background()
	googleClient, err := google.DefaultClient(ctx, iam.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	iamService, err := iam.New(googleClient)
	if err != nil {
		return nil, err
	}

	return &GoogleCloudIAMService{
		service:              iamService,
		projectID:            projectID,
		serviceAccountPrefix: serviceAccountPrefix,
	}, nil
}

// CreateServiceAccount creates a service account
func (googleCloudIAMService *GoogleCloudIAMService) CreateServiceAccount(serviceAccountName string) (fullServiceAccountName string, err error) {

	if len(serviceAccountName) < 3 {
		return "", fmt.Errorf("Service account name %v is too short; set at least name of 3 characters or more in the estafette.io/gcp-service-account-name annotation", serviceAccountName)
	}

	// shorted serviceAccountName for account id if needed
	const randomStringLength = 4
	prefixLength := len(googleCloudIAMService.serviceAccountPrefix)
	maxFirstSectionLength := 30 - randomStringLength - 1 - prefixLength - 1

	shortenedServiceAccountName := serviceAccountName
	if len(shortenedServiceAccountName) > maxFirstSectionLength {
		shortenedServiceAccountName = serviceAccountName[:maxFirstSectionLength]
	}

	randomString := randStringBytesMaskImprSrc(randomStringLength)

	serviceAccount, err := googleCloudIAMService.service.Projects.ServiceAccounts.Create("projects/"+googleCloudIAMService.projectID, &iam.CreateServiceAccountRequest{
		AccountId: fmt.Sprintf("%v-%v-%v", googleCloudIAMService.serviceAccountPrefix, shortenedServiceAccountName, randomString),
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: fmt.Sprintf("%v-%v-%v", googleCloudIAMService.serviceAccountPrefix, serviceAccountName, randomString),
		},
	}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	fullServiceAccountName = serviceAccount.Name

	return
}

// CreateServiceAccountKey creates a key file for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) CreateServiceAccountKey(fullServiceAccountName string) (serviceAccountKey *iam.ServiceAccountKey, err error) {

	if !googleCloudIAMService.ValidateFullServiceAccountName(fullServiceAccountName) {
		return nil, fmt.Errorf("The full service account is not valid")
	}

	serviceAccountKey, err = googleCloudIAMService.service.Projects.ServiceAccounts.Keys.Create(fullServiceAccountName, &iam.CreateServiceAccountKeyRequest{}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	return
}

// ListServiceAccountKeys lists all keys for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) ListServiceAccountKeys(fullServiceAccountName string) (serviceAccountKeys []*iam.ServiceAccountKey, err error) {

	if !googleCloudIAMService.ValidateFullServiceAccountName(fullServiceAccountName) {
		return nil, fmt.Errorf("The full service account is not valid")
	}

	keyListResponse, err := googleCloudIAMService.service.Projects.ServiceAccounts.Keys.List(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	serviceAccountKeys = keyListResponse.Keys

	return
}

// PurgeServiceAccountKeys purges all keys older than x hours for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) PurgeServiceAccountKeys(fullServiceAccountName string, purgeKeysAfterHours int) (err error) {

	if !googleCloudIAMService.ValidateFullServiceAccountName(fullServiceAccountName) {
		return fmt.Errorf("The full service account is not valid")
	}

	serviceAccountKeys, err := googleCloudIAMService.ListServiceAccountKeys(fullServiceAccountName)
	if err != nil {
		return
	}

	for _, key := range serviceAccountKeys {

		// parse validAfterTime to get key creation date
		keyCreatedAt := time.Time{}
		if key.ValidAfterTime == "" {
			log.Warn().Msgf("Key %v has empty ValidAfterTime, skipping...", key.Name)
			continue
		}

		keyCreatedAt, err = time.Parse(time.RFC3339, key.ValidAfterTime)
		if err != nil {
			log.Warn().Msgf("Can't parse ValidAfterTime %v for key %v, skipping...", key.ValidAfterTime, key.Name)
			continue
		}

		// check if it's old enough to purge
		if time.Since(keyCreatedAt).Hours() > float64(purgeKeysAfterHours) {
			log.Info().Msgf("Deleting key %v created at %v (parsed to %v) because it is more than %v hours old...", key.Name, key.ValidAfterTime, keyCreatedAt, purgeKeysAfterHours)
			_, err := googleCloudIAMService.DeleteServiceAccountKey(key)
			if err != nil {
				return err
			}
		}
	}

	return
}

// DeleteServiceAccountKey deletes a key file for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) DeleteServiceAccountKey(serviceAccountKey *iam.ServiceAccountKey) (deleted bool, err error) {

	_, err = googleCloudIAMService.service.Projects.ServiceAccounts.Keys.Delete(serviceAccountKey.Name).Context(context.Background()).Do()
	if err != nil {
		return
	}

	deleted = true

	return
}

// DeleteServiceAccount deletes a service account
func (googleCloudIAMService *GoogleCloudIAMService) DeleteServiceAccount(fullServiceAccountName string) (deleted bool, err error) {

	if !googleCloudIAMService.ValidateFullServiceAccountName(fullServiceAccountName) {
		return false, fmt.Errorf("The full service account is not valid")
	}

	resp, err := googleCloudIAMService.service.Projects.ServiceAccounts.Delete(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	if resp.HTTPStatusCode == 200 {
		deleted = true
	}

	return
}

// ValidateFullServiceAccountName validates whether this controller is allowed to do anything with the service account
func (googleCloudIAMService *GoogleCloudIAMService) ValidateFullServiceAccountName(fullServiceAccountName string) (valid bool) {

	// only allow for service accounts with same prefix
	r, _ := regexp.Compile(`^projects/([^/]+)/serviceAccounts/([^@]+)@([^.]+)\.(.+)$`)

	matches := r.FindStringSubmatch(fullServiceAccountName)
	if len(matches) != 5 {
		log.Warn().Msgf("Full service account '%v' name doesn't have a valid structure", fullServiceAccountName)
		return false
	}

	if matches[1] != googleCloudIAMService.projectID {
		log.Warn().Msgf("Project '%v' in full service account '%v' doesn't match project '%v' as set for this controller", matches[1], fullServiceAccountName, googleCloudIAMService.projectID)
		return false
	}

	if matches[3] != googleCloudIAMService.projectID {
		log.Warn().Msgf("Project '%v' in service account email '%v@%v.%v' doesn't match project '%v' as set for this controller", matches[3], matches[2], matches[3], matches[4], googleCloudIAMService.projectID)
		return false
	}

	if !strings.HasPrefix(fmt.Sprintf("%v-", matches[2]), googleCloudIAMService.serviceAccountPrefix) {
		log.Warn().Msgf("Service account '%v' is not prefixed by '%v' as set for this controller", matches[2], googleCloudIAMService.serviceAccountPrefix)
		return false
	}

	return true
}

// SetServiceAccountRoleBinding sets the desired permissions for this service account
func (googleCloudIAMService *GoogleCloudIAMService) SetServiceAccountRoleBinding(fullServiceAccountName string, permissions []GCPServiceAccountPermission) (err error) {

	// get current iam policies for service account
	policy, err := googleCloudIAMService.service.Projects.ServiceAccounts.GetIamPolicy(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	log.Debug().Interface("policy", policy).Msgf("Retrieved service account %v iam policy", fullServiceAccountName)

	return nil
}
