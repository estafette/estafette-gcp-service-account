package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/alecthomas/kingpin"
	foundation "github.com/estafette/estafette-foundation"
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/sethgrid/pester"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ericchiang/k8s"
	corev1 "github.com/ericchiang/k8s/apis/core/v1"
)

const annotationGCPServiceAccount string = "estafette.io/gcp-service-account"
const annotationGCPServiceAccountName string = "estafette.io/gcp-service-account-name"
const annotationGCPServiceAccountFilename string = "estafette.io/gcp-service-account-filename"
const annotationGCPServiceAccountDisableKeyRotation string = "estafette.io/gcp-service-account-disable-key-rotation"
const annotationGCPServiceAccountPermissions string = "estafette.io/gcp-service-account-permissions"
const annotationGCPServiceAccountState string = "estafette.io/gcp-service-account-state"

// GCPServiceAccountState represents the state of the secret with respect to GCP service accounts
type GCPServiceAccountState struct {
	Enabled                string                        `json:"enabled"`
	Name                   string                        `json:"name"`
	Filename               string                        `json:"filename,omitempty"`
	DisableKeyRotation     bool                          `json:"disableKeyRotation"`
	FullServiceAccountName string                        `json:"fullServiceAccountName"`
	Permissions            []GCPServiceAccountPermission `json:"permissions,omitempty"`
	LastRenewed            string                        `json:"lastRenewed"`
	LastAttempt            string                        `json:"lastAttempt"`
}

// GCPServiceAccountPermission represents a permission for a service account
type GCPServiceAccountPermission struct {
	Project string `json:"project"`
	Role    string `json:"role"`
}

var (
	mode                            = kingpin.Flag("mode", "The mode this controller can run in.").Default("normal").Envar("MODE").Enum("normal", "convenient", "rotate_keys_only")
	serviceAccountProjectID         = kingpin.Flag("service-account-project-id", "The Google Cloud project id in which to create service accounts.").Envar("SERVICE_ACCOUNT_PROJECT_ID").Required().String()
	keyRotationAfterHours           = kingpin.Flag("key-rotation-after-hours", "How many hours before a key is rotated.").Envar("KEY_ROTATION_AFTER_HOURS").Required().Int()
	purgeKeysAfterHours             = kingpin.Flag("purge-keys-after-hours", "How many hours before a key is purged.").Envar("PURGE_KEYS_AFTER_HOURS").Required().Int()
	allowDisableKeyRotationOverride = kingpin.Flag("allow-disable-key-rotation-override", "If set on a per secret basis key rotation can be disabled with an annotation.").Default("false").OverrideDefaultFromEnvar("ALLOW_DISABLE_KEY_ROTATION_OVERRIDE").Bool()

	app       string
	version   string
	branch    string
	revision  string
	buildDate string

	// define prometheus counter
	serviceAccountCreateTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_gcp_service_account_create_totals",
			Help: "Number of generated service accounts in GCP.",
		},
		[]string{"namespace", "status", "initiator", "type", "mode"},
	)
	serviceAccountRetrieveTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_gcp_service_account_retrieve_totals",
			Help: "Number of retrieved (by display name) service accounts in GCP.",
		},
		[]string{"namespace", "status", "initiator", "type", "mode"},
	)
	serviceAccountDeleteTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_gcp_service_account_delete_totals",
			Help: "Number of generated service accounts in GCP.",
		},
		[]string{"namespace", "status", "initiator", "type", "mode"},
	)
	keyRotationTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_gcp_key_rotation_totals",
			Help: "Number of rotated service account keys GCP.",
		},
		[]string{"namespace", "status", "initiator", "type", "mode"},
	)
	keyPurgeTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_gcp_key_purge_totals",
			Help: "Number of purged service account keys GCP.",
		},
		[]string{"namespace", "status", "initiator", "type", "mode"},
	)
)

func init() {
	// metrics have to be registered to be exposed
	prometheus.MustRegister(serviceAccountCreateTotals)
	prometheus.MustRegister(serviceAccountRetrieveTotals)
	prometheus.MustRegister(serviceAccountDeleteTotals)
	prometheus.MustRegister(keyRotationTotals)
	prometheus.MustRegister(keyPurgeTotals)
}

func main() {

	// parse command line parameters
	kingpin.Parse()

	foundation.InitLogging(app, version, branch, revision, buildDate)

	// create kubernetes api client
	kubeClient, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatal().Err(err)
	}

	// get project id from metadata server (might be impossible with metadata disabled, see https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata)
	client := pester.New()
	request, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/project/project-id", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	request.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(request)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal().Err(err)
	}
	localProjectID := string(body)
	if resp.StatusCode != http.StatusOK {
		log.Fatal().Str("body", string(body)).Msgf("Failed retrieving project id from metadata with status code %v", resp.StatusCode)
	}

	// create service to Google Cloud IAM
	iamService, err := NewGoogleCloudIAMService(*serviceAccountProjectID, localProjectID)
	if err != nil {
		log.Fatal().Err(err).Msg("Creating GoogleCloudIAMService failed")
	}

	foundation.WatchForFileChanges(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), func(event fsnotify.Event) {
		log.Info().Msg("Key file changed, reinitializing iam service...")
		iamService, err = NewGoogleCloudIAMService(*serviceAccountProjectID, localProjectID)
		if err != nil {
			log.Fatal().Err(err).Msg("Creating GoogleCloudIAMService failed")
		}
	})

	foundation.InitMetrics()

	gracefulShutdown, waitGroup := foundation.InitGracefulShutdownHandling()

	// watch secrets for all namespaces
	go func(waitGroup *sync.WaitGroup) {
		// loop indefinitely
		for {
			log.Info().Msg("Watching secrets for all namespaces...")

			var secret corev1.Secret
			watcher, err := kubeClient.Watch(context.Background(), k8s.AllNamespaces, &secret, k8s.Timeout(time.Duration(300)*time.Second))
			defer watcher.Close()

			if err != nil {
				log.Error().Err(err)
			} else {
				// loop indefinitely, unless it errors
				for {
					secret := new(corev1.Secret)
					event, err := watcher.Next(secret)
					if err != nil {
						log.Error().Err(err)
						break
					}

					if event == k8s.EventAdded || event == k8s.EventModified {
						waitGroup.Add(1)
						err := processSecret(kubeClient, iamService, secret, event)
						waitGroup.Done()

						if err != nil {
							log.Error().Err(err)
						}
					}

					if event == k8s.EventDeleted {
						waitGroup.Add(1)
						err := deleteSecret(kubeClient, iamService, secret, event)
						waitGroup.Done()

						if err != nil {
							log.Error().Err(err)
						}
					}
				}
			}

			// sleep random time between 22 and 37 seconds
			sleepTime := foundation.ApplyJitter(30)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	go func(waitGroup *sync.WaitGroup) {

		// sleep random time before polling in order to avoid race conditions (look at waitgroups in the future)
		sleepTime := foundation.ApplyJitter(30)
		log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
		time.Sleep(time.Duration(sleepTime) * time.Second)

		// loop indefinitely
		for {

			// get secrets for all namespaces
			log.Info().Msg("Listing secrets for all namespaces...")
			var secrets corev1.SecretList
			err := kubeClient.List(context.Background(), k8s.AllNamespaces, &secrets)
			if err != nil {
				log.Error().Err(err)
			}
			log.Info().Msgf("Cluster has %v secrets", len(secrets.Items))

			// loop all secrets
			for _, secret := range secrets.Items {
				waitGroup.Add(1)
				err := processSecret(kubeClient, iamService, secret, "POLLER")
				waitGroup.Done()

				if err != nil {
					log.Error().Err(err)
				}
			}

			// sleep random time around 900 seconds
			sleepTime := foundation.ApplyJitter(900)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	foundation.HandleGracefulShutdown(gracefulShutdown, waitGroup)
}

func getDesiredSecretState(secret *corev1.Secret) (state GCPServiceAccountState) {

	var ok bool

	// get annotations or set default value
	state.Enabled, ok = secret.Metadata.Annotations[annotationGCPServiceAccount]
	if !ok {
		state.Enabled = "false"
	}

	state.Name, ok = secret.Metadata.Annotations[annotationGCPServiceAccountName]
	if !ok {
		state.Name = ""
	}

	state.Filename, ok = secret.Metadata.Annotations[annotationGCPServiceAccountFilename]
	if !ok {
		state.Filename = "service-account-key.json"
	}

	disableKeyRotationValue, ok := secret.Metadata.Annotations[annotationGCPServiceAccountDisableKeyRotation]
	if !ok {
		state.DisableKeyRotation = false
	} else {
		var err error
		state.DisableKeyRotation, err = strconv.ParseBool(disableKeyRotationValue)
		if err != nil {
			state.DisableKeyRotation = false
		}
	}

	serviceAccountPermissionsString, ok := secret.Metadata.Annotations[annotationGCPServiceAccountPermissions]
	if !ok {
		state.Permissions = []GCPServiceAccountPermission{}
	} else {
		err := json.Unmarshal([]byte(serviceAccountPermissionsString), &state.Permissions)
		if err != nil {
			state.Permissions = []GCPServiceAccountPermission{}
		}
	}

	return
}

func getCurrentSecretState(secret *corev1.Secret) (state GCPServiceAccountState) {

	// get state stored in annotations if present or set to empty struct
	letsEncryptCertificateStateString, ok := secret.Metadata.Annotations[annotationGCPServiceAccountState]
	if !ok {
		// couldn't find saved state, setting to default struct
		state = GCPServiceAccountState{}
		return
	}

	if err := json.Unmarshal([]byte(letsEncryptCertificateStateString), &state); err != nil {
		// couldn't deserialize, setting to default struct
		state = GCPServiceAccountState{}
		return
	}

	// return deserialized state
	return
}

func makeSecretChanges(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, desiredState, currentState GCPServiceAccountState) (err error) {

	// parse last renewed time from state
	lastRenewed := time.Time{}
	if currentState.LastRenewed != "" {
		var err error
		lastRenewed, err = time.Parse(time.RFC3339, currentState.LastRenewed)
		if err != nil {
			lastRenewed = time.Time{}
		}
	}

	lastAttempt := time.Time{}
	if currentState.LastAttempt != "" {
		var err error
		lastAttempt, err = time.Parse(time.RFC3339, currentState.LastAttempt)
		if err != nil {
			lastAttempt = time.Time{}
		}
	}

	newAccount, err := makeSecretChangesGetOrCreateServiceAccount(kubeClient, iamService, secret, initiator, desiredState, &currentState, lastAttempt)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed creating service account %v", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)
	}

	err = makeSecretChangesSetPermissions(kubeClient, iamService, secret, initiator, desiredState, &currentState, lastAttempt, lastRenewed, newAccount)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed setting permissions for service account %v", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)
	}

	err = makeSecretChangesRotateKeys(kubeClient, iamService, secret, initiator, desiredState, &currentState, lastAttempt, lastRenewed, newAccount)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed rotating keys for service account %v", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)
	}

	err = makeSecretChangesPurgeKeys(kubeClient, iamService, secret, initiator, desiredState, &currentState, lastAttempt, lastRenewed)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed purging keys for service account %v", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)
	}

	return nil
}

func makeSecretChangesGetOrCreateServiceAccount(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, desiredState GCPServiceAccountState, currentState *GCPServiceAccountState, lastAttempt time.Time) (created bool, err error) {

	// if mode is rotate_keys_only it means the service account has been created in advance; if it's full qualified name isn't store in the FullServiceAccountName yet try and look it up by the predictable display name
	if (*mode == "rotate_keys_only") && desiredState.Enabled == "true" && desiredState.Name != "" && time.Since(lastAttempt).Minutes() > 15 && currentState.FullServiceAccountName == "" {

		log.Info().Msgf("[%v] Secret %v.%v - Service account %v has been created in advance, fetching its identifier...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)

		// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
		currentState.LastAttempt = time.Now().Format(time.RFC3339)

		err = updateSecret(kubeClient, secret, *currentState, initiator)
		if err != nil {
			serviceAccountRetrieveTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return
		}

		// fecth service account by display name
		fullServiceAccountName, err := iamService.GetServiceAccountByDisplayName(desiredState.Name)
		if err != nil {
			log.Error().Err(err).Msgf("Failed retrieving service account %v by display name", desiredState.Name)
			serviceAccountRetrieveTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return false, err
		}

		// update the secret
		currentState.Enabled = desiredState.Enabled
		currentState.Name = desiredState.Name
		currentState.FullServiceAccountName = fullServiceAccountName

		log.Info().Msgf("[%v] Secret %v.%v - Updating secret because a new service account has been created...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		err = updateSecret(kubeClient, secret, *currentState, initiator)
		if err != nil {
			serviceAccountRetrieveTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return false, err
		}

		log.Info().Msgf("[%v] Secret %v.%v - Service account name has been stored in secret successfully...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		serviceAccountRetrieveTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "succeeded", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()

		return true, nil
	}

	// check if gcp-service-account is enabled for this secret, and a service account doesn't already exist
	if (*mode == "normal" || *mode == "convenient") && desiredState.Enabled == "true" && desiredState.Name != "" && time.Since(lastAttempt).Minutes() > 15 && currentState.FullServiceAccountName == "" {

		log.Info().Msgf("[%v] Secret %v.%v - Service account %v hasn't been created yet, creating one now...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)

		// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
		currentState.LastAttempt = time.Now().Format(time.RFC3339)

		err = updateSecret(kubeClient, secret, *currentState, initiator)
		if err != nil {
			serviceAccountCreateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return
		}

		// create service account
		fullServiceAccountName, err := iamService.CreateServiceAccount(desiredState.Name)
		if err != nil {
			log.Error().Err(err).Msgf("Failed creating service account %v", desiredState.Name)
			serviceAccountCreateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return false, err
		}

		// update the secret
		currentState.Enabled = desiredState.Enabled
		currentState.Name = desiredState.Name
		currentState.FullServiceAccountName = fullServiceAccountName

		log.Info().Msgf("[%v] Secret %v.%v - Updating secret because a new service account has been created...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		err = updateSecret(kubeClient, secret, *currentState, initiator)
		if err != nil {
			serviceAccountCreateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return false, err
		}

		log.Info().Msgf("[%v] Secret %v.%v - Service account name has been stored in secret successfully...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		serviceAccountCreateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "succeeded", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()

		return true, nil
	}

	serviceAccountRetrieveTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "skipped", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
	serviceAccountCreateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "skipped", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()

	return false, nil
}

func makeSecretChangesSetPermissions(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, desiredState GCPServiceAccountState, currentState *GCPServiceAccountState, lastAttempt, lastRenewed time.Time, newAccount bool) (err error) {

	// check if gcp-service-account is enabled for this secret, and permissions have been defined
	if (*mode == "convenient") && desiredState.Enabled == "true" && desiredState.Name != "" && (time.Since(lastAttempt).Minutes() > 15 || newAccount) && currentState.FullServiceAccountName == "" && len(currentState.Permissions) != len(desiredState.Permissions) {
		// in convenient mode this controller can set the permissions as well; but awarding this controller with the possibility to set permissions is not without risk

		err = iamService.SetServiceAccountRoleBinding(currentState.FullServiceAccountName, desiredState.Permissions)
		if err != nil {
			log.Warn().Err(err).Msgf("Setting permissions for service account %v failed", desiredState.Name)
		}
	}

	return nil
}

func makeSecretChangesRotateKeys(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, desiredState GCPServiceAccountState, currentState *GCPServiceAccountState, lastAttempt, lastRenewed time.Time, newAccount bool) (err error) {

	// check if gcp-service-account is enabled for this secret, and a service account doesn't already exist
	if (*mode == "normal" || *mode == "convenient" || *mode == "rotate_keys_only") &&
		desiredState.Enabled == "true" &&
		desiredState.Name != "" &&
		(time.Since(lastAttempt).Minutes() > 15 || newAccount) &&
		(len(secret.Data) == 0 || !*allowDisableKeyRotationOverride || !desiredState.DisableKeyRotation) &&
		currentState.FullServiceAccountName != "" &&
		time.Since(lastRenewed).Hours() > float64(*keyRotationAfterHours) {

		log.Info().Msgf("[%v] Secret %v.%v - Service account %v key is up for rotation, requesting a new one now...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Name)

		if !newAccount {
			// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
			currentState.LastAttempt = time.Now().Format(time.RFC3339)

			err = updateSecret(kubeClient, secret, *currentState, initiator)
			if err != nil {
				keyRotationTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
				return
			}
		}

		// create service account
		serviceAccountKey, err := iamService.CreateServiceAccountKey(currentState.FullServiceAccountName)
		if err != nil {
			log.Error().Err(err).Msgf("Failed creating service account %v key", currentState.FullServiceAccountName)
			keyRotationTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return err
		}

		// update the secret
		currentState.LastRenewed = time.Now().Format(time.RFC3339)

		// store the key file
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}

		decodedPrivateKeyData, err := base64.StdEncoding.DecodeString(serviceAccountKey.PrivateKeyData)
		if err != nil {
			log.Error().Err(err)
			keyRotationTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return err
		}

		// service account keyfile
		filename := desiredState.Filename
		if filename == "" {
			filename = "service-account-key.json"
		}
		secret.Data[filename] = decodedPrivateKeyData

		err = updateSecret(kubeClient, secret, *currentState, initiator)
		if err != nil {
			keyRotationTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return err
		}

		log.Info().Msgf("[%v] Secret %v.%v - Service account keyfile has been renewed successfully...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		keyRotationTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "succeeded", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()

		return nil
	}

	keyRotationTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "skipped", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()

	return nil
}

func makeSecretChangesPurgeKeys(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, desiredState GCPServiceAccountState, currentState *GCPServiceAccountState, lastAttempt, lastRenewed time.Time) (err error) {

	if (*mode == "normal" || *mode == "convenient" || *mode == "rotate_keys_only") &&
		time.Since(lastAttempt).Minutes() > 15 &&
		currentState.Enabled == "true" &&
		currentState.LastRenewed != "" &&
		time.Since(lastRenewed).Hours() > 2 &&
		currentState.FullServiceAccountName != "" &&
		(!*allowDisableKeyRotationOverride || !desiredState.DisableKeyRotation) {

		log.Info().Msgf("[%v] Secret %v.%v - Checking %v for keys to purge...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, currentState.Name)

		// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
		currentState.LastAttempt = time.Now().Format(time.RFC3339)

		err = updateSecret(kubeClient, secret, *currentState, initiator)
		if err != nil {
			keyPurgeTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return err
		}

		// purge old service account keys
		deleteCount, err := iamService.PurgeServiceAccountKeys(currentState.FullServiceAccountName, *purgeKeysAfterHours)
		if err != nil {
			log.Error().Err(err).Msgf("Failed purging service account %v keys", currentState.FullServiceAccountName)
			keyPurgeTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()
			return err
		}

		keyPurgeTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "succeeded", "initiator": initiator, "mode": *mode, "type": "secret"}).Add(float64(deleteCount))

		return nil
	}

	keyPurgeTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "skipped", "initiator": initiator, "mode": *mode, "type": "secret"}).Inc()

	return nil
}

func processSecret(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string) (err error) {

	if secret != nil && secret.Metadata != nil && secret.Metadata.Annotations != nil {

		desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)

		err = makeSecretChanges(kubeClient, iamService, secret, initiator, desiredState, currentState)
		if err != nil {
			return
		}
	}

	return nil
}

func deleteSecret(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string) (err error) {

	log.Info().Msgf("[%v] Secret %v.%v - Deleting service account because secret has been deleted...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

	if (*mode == "normal" || *mode == "convenient") && secret != nil && secret.Metadata != nil && secret.Metadata.Annotations != nil {

		currentState := getCurrentSecretState(secret)

		if currentState.FullServiceAccountName != "" {
			deleted, err := iamService.DeleteServiceAccount(currentState.FullServiceAccountName)

			if err != nil {
				log.Error().Err(err).Msgf("Failed deleting service account %v", currentState.Name)
				serviceAccountDeleteTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "failed", "initiator": "watcher", "type": "secret"}).Inc()
				return err
			}

			if deleted {
				serviceAccountDeleteTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": "succeeded", "initiator": "watcher", "type": "secret"}).Inc()
				log.Info().Msgf("[%v] Secret %v.%v - Successfully deleted service account %v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, currentState.FullServiceAccountName)
			}
		}
	}

	return nil
}

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func updateSecret(kubeClient *k8s.Client, secret *corev1.Secret, currentState GCPServiceAccountState, initiator string) error {
	// serialize state and store it in the annotation
	gcpServiceAccountStateByteArray, err := json.Marshal(currentState)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed marshalling current state %v", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, currentState)
		return err
	}
	secret.Metadata.Annotations[annotationGCPServiceAccountState] = string(gcpServiceAccountStateByteArray)

	// update secret, with last attempt; this will fire an event for the watcher, but this shouldn't lead to any action because storing the last attempt locks the secret for 15 minutes
	err = kubeClient.Update(context.Background(), secret)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed updating current state in secret", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		return err
	}

	// refresh secret after update
	err = kubeClient.Get(context.Background(), *secret.Metadata.Namespace, *secret.Metadata.Name, secret)
	if err != nil {
		log.Error().Err(err).Msgf("[%v] Secret %v.%v - Failed refreshing secret after update", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		return err
	}

	return nil
}
