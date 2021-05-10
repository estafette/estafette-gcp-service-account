package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

// GoogleCloudIAMService is the service that allows to create service accounts
type GoogleCloudIAMService struct {
	service                 *iam.Service
	watcher                 *fsnotify.Watcher
	serviceAccountProjectID string
	localProjectID          string
}

// NewGoogleCloudIAMService returns an initialized GoogleCloudIAMService
func NewGoogleCloudIAMService(serviceAccountProjectID, localProjectID string) (*GoogleCloudIAMService, error) {

	if serviceAccountProjectID == "" {
		return nil, fmt.Errorf("Parameter serviceAccountProjectID should not be empty")
	}
	if localProjectID == "" {
		return nil, fmt.Errorf("Parameter serviceAccountProjectID should not be empty")
	}

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
		service:                 iamService,
		serviceAccountProjectID: serviceAccountProjectID,
		localProjectID:          localProjectID,
	}, nil
}

// CreateServiceAccount creates a service account
func (googleCloudIAMService *GoogleCloudIAMService) CreateServiceAccount(name string) (fullServiceAccountName string, err error) {

	// generate random account id and structured display name to serve as 'metadata'
	accountID, displayName, err := googleCloudIAMService.getServiceAccountIDAndDisplayName(name)
	if err != nil {
		return
	}

	// ensure account doesn't already exist
	for {
		serviceAccount, _ := googleCloudIAMService.service.Projects.ServiceAccounts.Get("projects/" + googleCloudIAMService.serviceAccountProjectID + "/serviceAccounts/" + accountID).Context(context.Background()).Do()

		// if the service account doesn't exist, it's free to create a new one with this account id
		if serviceAccount == nil {
			break
		}

		// generate new random account id to see if it's free
		accountID, displayName, err = googleCloudIAMService.getServiceAccountIDAndDisplayName(name)
		if err != nil {
			return
		}
	}

	// create the service account
	serviceAccount, err := googleCloudIAMService.service.Projects.ServiceAccounts.Create("projects/"+googleCloudIAMService.serviceAccountProjectID, &iam.CreateServiceAccountRequest{
		AccountId: accountID,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: displayName,
		},
	}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	fullServiceAccountName = serviceAccount.Name

	return
}

// GetServiceAccountByDisplayName retrieves the full service account name based on the display name format '<local project id>/serviceAccountName'
func (googleCloudIAMService *GoogleCloudIAMService) GetServiceAccountByDisplayName(name string) (fullServiceAccountName string, fullServiceAccountEmail string, err error) {

	// generate structured display name to be able to retrieve the service account with random account id
	_, displayName, err := googleCloudIAMService.getServiceAccountIDAndDisplayName(name)
	if err != nil {
		return
	}

	matchingServiceAccounts := []*iam.ServiceAccount{}
	nextPageToken := ""

	for {
		// retrieving service accounts (by page)
		log.Info().Msgf("Retrieving service accounts with page token '%v'...", nextPageToken)
		listCall := googleCloudIAMService.service.Projects.ServiceAccounts.List("projects/" + googleCloudIAMService.serviceAccountProjectID)
		if nextPageToken != "" {
			listCall.PageToken(nextPageToken)
		}
		resp, err := listCall.Context(context.Background()).Do()
		if err != nil {
			return "", "", err
		}

		// filter on display names
		log.Info().Msgf("Checking %v service accounts for matching display name...", len(resp.Accounts))
		for _, sa := range resp.Accounts {
			if sa.DisplayName == displayName {
				matchingServiceAccounts = append(matchingServiceAccounts, sa)
			}
		}

		if resp.NextPageToken == "" {
			break
		}
		nextPageToken = resp.NextPageToken
	}

	log.Info().Msgf("Found %v service accounts with matching display name...", len(matchingServiceAccounts))
	if len(matchingServiceAccounts) > 0 {
		// reverse sort to have highest uniqueid first
		sort.Slice(matchingServiceAccounts, func(i, j int) bool {
			return matchingServiceAccounts[i].UniqueId > matchingServiceAccounts[j].UniqueId
		})

		// pick service account with highest unique id
		fullServiceAccountName = matchingServiceAccounts[0].Name
		fullServiceAccountEmail = matchingServiceAccounts[0].Email

		return
	}

	return "", "", fmt.Errorf("There is no service account with display name %v in project %v", displayName, googleCloudIAMService.serviceAccountProjectID)
}

// GetServiceAccountIDAndDisplayName generates account id and display name if mode is set to normal or convenient
func (googleCloudIAMService *GoogleCloudIAMService) getServiceAccountIDAndDisplayName(name string) (accountID, displayName string, err error) {

	if len(name) < 5 {
		return "", "", fmt.Errorf("Name '%v' is too short; set at least a name of 5 characters or more in the estafette.io/gcp-service-account-name annotation", name)
	}
	if len(name) > 69 {
		return "", "", fmt.Errorf("Name '%v' is too long; set at most a name of 69 characters or more in the estafette.io/gcp-service-account-name annotation", name)
	}

	// shorted name for account id if needed
	const randomStringLength = 4
	maxFirstSectionLength := 30 - randomStringLength - 1

	shortenedName := name
	if len(shortenedName) > maxFirstSectionLength {
		shortenedName = name[:maxFirstSectionLength]
	}

	randomString := randStringBytesMaskImprSrc(randomStringLength)

	accountID = fmt.Sprintf("%v-%v", shortenedName, randomString)
	displayName = fmt.Sprintf("%v/%v", googleCloudIAMService.localProjectID, name)

	return
}

// CreateServiceAccountKey creates a key file for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) CreateServiceAccountKey(fullServiceAccountName string) (serviceAccountKey *iam.ServiceAccountKey, err error) {

	if !googleCloudIAMService.validateServiceAccount(fullServiceAccountName) {
		return nil, fmt.Errorf("The service account is not valid for this controller to create keys for")
	}

	serviceAccountKey, err = googleCloudIAMService.service.Projects.ServiceAccounts.Keys.Create(fullServiceAccountName, &iam.CreateServiceAccountKeyRequest{}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	return
}

// listServiceAccountKeys lists all keys for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) listServiceAccountKeys(fullServiceAccountName string) (serviceAccountKeys []*iam.ServiceAccountKey, err error) {

	if !googleCloudIAMService.validateServiceAccount(fullServiceAccountName) {
		return nil, fmt.Errorf("The service account is not valid for this controller to list keys for")
	}

	keyListResponse, err := googleCloudIAMService.service.Projects.ServiceAccounts.Keys.List(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	serviceAccountKeys = keyListResponse.Keys

	return
}

// PurgeServiceAccountKeys purges all keys older than x hours for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) PurgeServiceAccountKeys(fullServiceAccountName string, purgeKeysAfterHours int) (deleteCount int, err error) {

	serviceAccountKeys, err := googleCloudIAMService.listServiceAccountKeys(fullServiceAccountName)
	if err != nil {
		return
	}

	if len(serviceAccountKeys) > 1 {
		// reverse sort with newest first
		sort.Slice(serviceAccountKeys, func(i, j int) bool {
			return serviceAccountKeys[i].ValidAfterTime > serviceAccountKeys[j].ValidAfterTime
		})

		// check all but the newest to see if it's old enough to be purged
		for _, key := range serviceAccountKeys[1:] {

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
				deleted, err := googleCloudIAMService.deleteServiceAccountKey(key)
				if err != nil {
					log.Error().Err(err).Msgf("Failed deleting key %v", key.Name)
					continue
				} else if deleted {
					deleteCount++
				}
			}
		}
	}

	return
}

// deleteServiceAccountKey deletes a key file for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) deleteServiceAccountKey(serviceAccountKey *iam.ServiceAccountKey) (deleted bool, err error) {

	log.Debug().Msgf("Deleting key %v...", serviceAccountKey.Name)
	resp, err := googleCloudIAMService.service.Projects.ServiceAccounts.Keys.Delete(serviceAccountKey.Name).Context(context.Background()).Do()
	if err != nil {
		return
	}

	if resp.HTTPStatusCode == 200 {
		deleted = true
	}

	return
}

// DeleteServiceAccount deletes a service account
func (googleCloudIAMService *GoogleCloudIAMService) DeleteServiceAccount(fullServiceAccountName string) (deleted bool, err error) {

	if !googleCloudIAMService.validateServiceAccount(fullServiceAccountName) {
		return false, fmt.Errorf("The service account is not valid for this controller to delete")
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

// validateFullServiceAccountName validates whether this controller is allowed to do anything with the service account
func (googleCloudIAMService *GoogleCloudIAMService) validateServiceAccount(fullServiceAccountName string) (valid bool) {

	if !googleCloudIAMService.validateFullServiceAccountName(fullServiceAccountName) {
		return false
	}

	serviceAccount, err := googleCloudIAMService.service.Projects.ServiceAccounts.Get(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return false
	}

	if serviceAccount == nil {
		return false
	}

	if !googleCloudIAMService.validateDisplayName(serviceAccount.DisplayName) {
		return false
	}

	return true
}

// validateFullServiceAccountName validates whether this controller is allowed to do anything with the service account
func (googleCloudIAMService *GoogleCloudIAMService) validateFullServiceAccountName(fullServiceAccountName string) (valid bool) {

	// only allow for service accounts with same prefix
	r, _ := regexp.Compile(`^projects/([^/]+)/serviceAccounts/([^@]+)@([^.]+)\.(.+)$`)

	matches := r.FindStringSubmatch(fullServiceAccountName)
	if len(matches) != 5 {
		log.Warn().Msgf("Full service account '%v' name doesn't have a valid structure", fullServiceAccountName)
		return false
	}

	if matches[1] != googleCloudIAMService.serviceAccountProjectID {
		log.Warn().Msgf("Project '%v' in full service account '%v' doesn't match project '%v' as set for this controller", matches[1], fullServiceAccountName, googleCloudIAMService.serviceAccountProjectID)
		return false
	}

	if matches[3] != googleCloudIAMService.serviceAccountProjectID {
		log.Warn().Msgf("Project '%v' in service account email '%v@%v.%v' doesn't match project '%v' as set for this controller", matches[3], matches[2], matches[3], matches[4], googleCloudIAMService.serviceAccountProjectID)
		return false
	}

	return true
}

// validateDisplayName validates whether this controller is allowed to do anything with the service account
func (googleCloudIAMService *GoogleCloudIAMService) validateDisplayName(displayName string) (valid bool) {

	// only allow for service accounts with display name of format '<local project id>/>service account name>'
	r, _ := regexp.Compile(`^([^/]+)/(.+)$`)

	matches := r.FindStringSubmatch(displayName)
	if len(matches) != 3 {
		log.Warn().Msgf("Display name '%v' doesn't have a valid structure", displayName)
		return false
	}

	if matches[1] != googleCloudIAMService.localProjectID {
		log.Warn().Msgf("Project '%v' in display name '%v' doesn't match local project '%v' as set for this controller", matches[1], displayName, googleCloudIAMService.localProjectID)
		return false
	}

	return true
}

// SetServiceAccountRoleBinding sets the desired permissions for this service account
func (googleCloudIAMService *GoogleCloudIAMService) SetServiceAccountRoleBinding(fullServiceAccountName string, permissions []GCPServiceAccountPermission) (err error) {

	if !googleCloudIAMService.validateServiceAccount(fullServiceAccountName) {
		return fmt.Errorf("The service account is not valid for this controller to modify roles for")
	}

	// get current iam policies for service account
	policy, err := googleCloudIAMService.service.Projects.ServiceAccounts.GetIamPolicy(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	log.Debug().Interface("policy", policy).Msgf("Retrieved service account %v iam policy", fullServiceAccountName)

	return nil
}
