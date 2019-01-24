package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

	googleCloudIAMService := &GoogleCloudIAMService{
		projectID:            projectID,
		serviceAccountPrefix: serviceAccountPrefix,
	}

	err := googleCloudIAMService.createIAMService()
	if err != nil {
		return nil, err
	}

	return googleCloudIAMService, nil
}

func (googleCloudIAMService *GoogleCloudIAMService) createIAMService() error {

	ctx := context.Background()
	googleClient, err := google.DefaultClient(ctx, iam.CloudPlatformScope)
	if err != nil {
		return err
	}

	iamService, err := iam.New(googleClient)
	if err != nil {
		return err
	}

	googleCloudIAMService.service = iamService

	return nil
}

// WatchForKeyfileChanges sets up a file watcher to ensure correct behaviour after key rotation
func (googleCloudIAMService *GoogleCloudIAMService) WatchForKeyfileChanges() {
	// copied from https://github.com/spf13/viper/blob/v1.3.1/viper.go#L282-L348
	initWG := sync.WaitGroup{}
	initWG.Add(1)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal().Err(err).Msg("Creating file system watcher failed")
		}
		defer watcher.Close()

		// we have to watch the entire directory to pick up renames/atomic saves in a cross-platform way
		keyFilePath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		keyFile := filepath.Clean(keyFilePath)
		keyFileDir, _ := filepath.Split(keyFile)
		realKeyFile, _ := filepath.EvalSymlinks(keyFilePath)

		eventsWG := sync.WaitGroup{}
		eventsWG.Add(1)
		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok { // 'Events' channel is closed
						eventsWG.Done()
						return
					}
					currentKeyFile, _ := filepath.EvalSymlinks(keyFilePath)
					// we only care about the key file with the following cases:
					// 1 - if the key file was modified or created
					// 2 - if the real path to the key file changed (eg: k8s ConfigMap/Secret replacement)
					const writeOrCreateMask = fsnotify.Write | fsnotify.Create
					if (filepath.Clean(event.Name) == keyFile &&
						event.Op&writeOrCreateMask != 0) ||
						(currentKeyFile != "" && currentKeyFile != realKeyFile) {
						realKeyFile = currentKeyFile

						log.Info().Interface("event", event).Msg("File watcher triggered event, recreating service...")

						err := googleCloudIAMService.createIAMService()
						if err != nil {
							log.Fatal().Err(err).Msg("Recreating iam service to pick up key rotation failed")
						}

					} else if filepath.Clean(event.Name) == keyFile &&
						event.Op&fsnotify.Remove&fsnotify.Remove != 0 {
						eventsWG.Done()
						return
					}

				case err, ok := <-watcher.Errors:
					if ok { // 'Errors' channel is not closed
						log.Printf("watcher error: %v\n", err)
					}
					eventsWG.Done()
					return
				}
			}
		}()
		watcher.Add(keyFileDir)
		initWG.Done()   // done initalizing the watch in this go routine, so the parent routine can move on...
		eventsWG.Wait() // now, wait for event loop to end in this go-routine...
	}()
	initWG.Wait() // make sure that the go routine above fully ended before returning
}

// CreateServiceAccount creates a service account
func (googleCloudIAMService *GoogleCloudIAMService) CreateServiceAccount(serviceAccountName string) (fullServiceAccountName string, err error) {

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

	serviceAccountKey, err = googleCloudIAMService.service.Projects.ServiceAccounts.Keys.Create(fullServiceAccountName, &iam.CreateServiceAccountKeyRequest{}).Context(context.Background()).Do()
	if err != nil {
		return
	}

	return
}

// ListServiceAccountKeys lists all keys for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) ListServiceAccountKeys(fullServiceAccountName string) (serviceAccountKeys []*iam.ServiceAccountKey, err error) {

	keyListResponse, err := googleCloudIAMService.service.Projects.ServiceAccounts.Keys.List(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	serviceAccountKeys = keyListResponse.Keys

	return
}

// PurgeServiceAccountKeys purges all keys older than x hours for an existing account
func (googleCloudIAMService *GoogleCloudIAMService) PurgeServiceAccountKeys(fullServiceAccountName string, purgeKeysAfterHours int) (err error) {

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

	resp, err := googleCloudIAMService.service.Projects.ServiceAccounts.Delete(fullServiceAccountName).Context(context.Background()).Do()
	if err != nil {
		return
	}

	if resp.HTTPStatusCode == 200 {
		deleted = true
	}

	return
}
