package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	stdlog "log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ericchiang/k8s"
	corev1 "github.com/ericchiang/k8s/apis/core/v1"
)

const annotationGCPServiceAccount string = "estafette.io/gcp-service-account"
const annotationGCPServiceAccountName string = "estafette.io/gcp-service-account-name"
const annotationGCPServiceAccountState string = "estafette.io/gcp-service-account-state"

// GCPServiceAccountState represents the state of the secret with respect to GCP service accounts
type GCPServiceAccountState struct {
	Enabled                string `json:"enabled"`
	ServiceAccountName     string `json:"serviceAccountName"`
	FullServiceAccountName string `json:"fullServiceAccountName"`
	LastRenewed            string `json:"lastRenewed"`
	LastAttempt            string `json:"lastAttempt"`
}

var (
	serviceAccountProjectID = kingpin.Flag("service-account-project-id", "The Google Cloud project id in which to create service accounts.").Envar("SERVICE_ACCOUNT_PROJECT_ID").Required().String()
	serviceAccountPrefix    = kingpin.Flag("service-account-prefix", "The prefix for service account names.").Envar("SERVICE_ACCOUNT_PREFIX").Required().String()
	keyRotationAfterHours   = kingpin.Flag("key-rotation-after-hours", "How many hours before a key is rotated.").Envar("KEY_ROTATION_AFTER_HOURS").Required().Int()
	purgeKeysAfterHours     = kingpin.Flag("purge-keys-after-hours", "How many hours before a key is purged.").Envar("PURGE_KEYS_AFTER_HOURS").Required().Int()

	version   string
	branch    string
	revision  string
	buildDate string
	goVersion = runtime.Version()
)

var (
	addr = flag.String("listen-address", ":9101", "The address to listen on for HTTP requests.")

	// seed random number
	r = rand.New(rand.NewSource(time.Now().UnixNano()))

	// define prometheus counter
	certificateTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_gcp_service_account_totals",
			Help: "Number of generated service accounts in GCP.",
		},
		[]string{"namespace", "status", "initiator", "type"},
	)
)

func init() {
	// metrics have to be registered to be exposed
	prometheus.MustRegister(certificateTotals)
}

func main() {

	// parse command line parameters
	flag.Parse()
	kingpin.Parse()

	// log as severity for stackdriver logging to recognize the level
	zerolog.LevelFieldName = "severity"

	// set some default fields added to all logs
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "estafette-gcp-service-account").
		Str("version", version).
		Logger()

	// use zerolog for any logs sent via standard log library
	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)

	// log startup message
	log.Info().
		Str("branch", branch).
		Str("revision", revision).
		Str("buildDate", buildDate).
		Str("goVersion", goVersion).
		Msg("Starting estafette-gcp-service-account...")

	// create kubernetes api client
	kubeClient, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatal().Err(err)
	}

	// create service to Google Cloud IAM
	iamService, err := NewGoogleCloudIAMService(*serviceAccountProjectID, *serviceAccountPrefix)
	if err != nil {
		log.Fatal().Err(err).Msg("Creating GoogleCloudIAMService failed")
	}
	go iamService.WatchForKeyfileChanges()

	// start prometheus
	go func() {
		log.Debug().
			Str("port", *addr).
			Msg("Serving Prometheus metrics...")

		http.Handle("/metrics", promhttp.Handler())

		if err := http.ListenAndServe(*addr, nil); err != nil {
			log.Fatal().Err(err).Msg("Starting Prometheus listener failed")
		}
	}()

	// define channel used to gracefully shutdown the application
	gracefulShutdown := make(chan os.Signal)

	signal.Notify(gracefulShutdown, syscall.SIGTERM, syscall.SIGINT)

	waitGroup := &sync.WaitGroup{}

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
						status, err := processSecret(kubeClient, iamService, secret, fmt.Sprintf("watcher:%v", event))
						certificateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": status, "initiator": "watcher", "type": "secret"}).Inc()
						waitGroup.Done()

						if err != nil {
							log.Error().Err(err)
							continue
						}
					}

					if event == k8s.EventDeleted {
						waitGroup.Add(1)
						status, err := deleteSecret(kubeClient, iamService, secret, fmt.Sprintf("watcher:%v", event))
						certificateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": status, "initiator": "watcher", "type": "secret"}).Inc()
						waitGroup.Done()

						if err != nil {
							log.Error().Err(err)
							continue
						}

					}
				}
			}

			// sleep random time between 22 and 37 seconds
			sleepTime := applyJitter(30)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	go func(waitGroup *sync.WaitGroup) {

		// sleep random time before polling in order to avoid race conditions (look at waitgroups in the future)
		sleepTime := applyJitter(30)
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
				status, err := processSecret(kubeClient, iamService, secret, "poller")
				certificateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": status, "initiator": "poller", "type": "secret"}).Inc()
				waitGroup.Done()

				if err != nil {
					log.Error().Err(err)
					continue
				}

				waitGroup.Add(1)
				status, err = purgeSecretKeys(kubeClient, iamService, secret, "poller")
				certificateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": status, "initiator": "purger", "type": "secret"}).Inc()
				waitGroup.Done()

				if err != nil {
					log.Error().Err(err)
					continue
				}
			}

			// sleep random time around 900 seconds
			sleepTime := applyJitter(900)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	signalReceived := <-gracefulShutdown
	log.Info().
		Msgf("Received signal %v. Waiting for running tasks to finish...", signalReceived)

	waitGroup.Wait()

	log.Info().Msg("Shutting down...")
}

func applyJitter(input int) (output int) {

	deviation := int(0.25 * float64(input))

	return input - deviation + r.Intn(2*deviation)
}

func getDesiredSecretState(secret *corev1.Secret) (state GCPServiceAccountState) {

	var ok bool

	// get annotations or set default value
	state.Enabled, ok = secret.Metadata.Annotations[annotationGCPServiceAccount]
	if !ok {
		state.Enabled = "false"
	}

	state.ServiceAccountName, ok = secret.Metadata.Annotations[annotationGCPServiceAccountName]
	if !ok {
		state.ServiceAccountName = ""
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

func makeSecretChanges(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, desiredState, currentState GCPServiceAccountState) (status string, err error) {

	status = "failed"

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

	newAccount := false

	// check if gcp-service-account is enabled for this secret, and a service account doesn't already exist
	if desiredState.Enabled == "true" && desiredState.ServiceAccountName != "" && time.Since(lastAttempt).Minutes() > 15 && currentState.FullServiceAccountName == "" {

		log.Info().Msgf("[%v] Secret %v.%v - Service account %v hasn't been created yet, creating one now...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.ServiceAccountName)

		// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
		currentState.LastAttempt = time.Now().Format(time.RFC3339)

		err = updateSecret(kubeClient, secret, currentState, initiator)
		if err != nil {
			return
		}

		// create service account
		fullServiceAccountName, err := iamService.CreateServiceAccount(desiredState.ServiceAccountName)
		if err != nil {
			log.Error().Err(err).Msgf("Failed creating service account %v", desiredState.ServiceAccountName)
			return status, err
		}

		// update the secret
		currentState.Enabled = desiredState.Enabled
		currentState.ServiceAccountName = desiredState.ServiceAccountName
		currentState.FullServiceAccountName = fullServiceAccountName

		log.Info().Msgf("[%v] Secret %v.%v - Updating secret because a new service account has been created...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		err = updateSecret(kubeClient, secret, currentState, initiator)
		if err != nil {
			return status, err
		}

		status = "succeeded"

		log.Info().Msgf("[%v] Secret %v.%v - Service account name has been stored in secret successfully...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		newAccount = true
	}

	// check if gcp-service-account is enabled for this secret, and a service account doesn't already exist
	if desiredState.Enabled == "true" && desiredState.ServiceAccountName != "" && (time.Since(lastAttempt).Minutes() > 15 || newAccount) && currentState.FullServiceAccountName != "" && time.Since(lastRenewed).Hours() > float64(*keyRotationAfterHours) {

		log.Info().Msgf("[%v] Secret %v.%v - Service account %v key is up for rotation, requesting a new one now...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.ServiceAccountName)

		if !newAccount {
			// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
			currentState.LastAttempt = time.Now().Format(time.RFC3339)

			err = updateSecret(kubeClient, secret, currentState, initiator)
			if err != nil {
				return
			}
		}

		// create service account
		serviceAccountKey, err := iamService.CreateServiceAccountKey(currentState.FullServiceAccountName)
		if err != nil {
			log.Error().Err(err).Msgf("Failed creating service account %v key", currentState.FullServiceAccountName)
			return "", err
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
			return "", err
		}

		// service account keyfile
		secret.Data["service-account-key.json"] = decodedPrivateKeyData

		err = updateSecret(kubeClient, secret, currentState, initiator)
		if err != nil {
			return status, err
		}

		status = "succeeded"

		log.Info().Msgf("[%v] Secret %v.%v - Service account keyfile has been renewed successfully...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		return status, nil
	}

	status = "skipped"

	return status, nil
}

func generateServiceAccountKey(iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string, currentState *GCPServiceAccountState) (err error) {

	return
}

func processSecret(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string) (status string, err error) {

	status = "failed"

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)

		status, err = makeSecretChanges(kubeClient, iamService, secret, initiator, desiredState, currentState)

		return
	}

	status = "skipped"

	return status, nil
}

func purgeSecretKeys(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string) (status string, err error) {

	status = "failed"

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		// desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)

		if currentState.LastAttempt == "" {
			return
		}

		lastAttempt, err := time.Parse(time.RFC3339, currentState.LastAttempt)
		if err != nil {
			return status, err
		}

		// check if there's any old keys to purge once every 2 hours
		if currentState.Enabled == "true" && currentState.LastAttempt != "" && time.Since(lastAttempt).Hours() > 2 && currentState.FullServiceAccountName != "" {

			log.Info().Msgf("[%v] Secret %v.%v - Checking %v for keys to purge...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, currentState.ServiceAccountName)

			// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Google Cloud IAM api call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
			currentState.LastAttempt = time.Now().Format(time.RFC3339)

			err = updateSecret(kubeClient, secret, currentState, initiator)
			if err != nil {
				return status, err
			}

			// purge old service account keys
			err = iamService.PurgeServiceAccountKeys(currentState.FullServiceAccountName, *purgeKeysAfterHours)
			if err != nil {
				log.Error().Err(err).Msgf("Failed purging service account %v keys", currentState.FullServiceAccountName)
				return status, err
			}

			status = "purged"

			return status, err
		}

		return status, err
	}

	status = "skipped"

	return status, nil

}

func deleteSecret(kubeClient *k8s.Client, iamService *GoogleCloudIAMService, secret *corev1.Secret, initiator string) (status string, err error) {

	status = "failed"

	log.Info().Msgf("[%v] Secret %v.%v - Deleting service account because secret has been deleted...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		currentState := getCurrentSecretState(secret)

		if currentState.FullServiceAccountName != "" {
			deleted, err := iamService.DeleteServiceAccount(currentState.FullServiceAccountName)

			if err != nil {
				log.Error().Err(err).Msgf("Failed deleting service account %v", currentState.ServiceAccountName)
				return status, err
			}

			if deleted {
				status = "deleted"
				log.Info().Msgf("[%v] Secret %v.%v - Successfully deleted service account %v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, currentState.FullServiceAccountName)
			}
		}

		return
	}

	status = "skipped"

	return status, nil
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
