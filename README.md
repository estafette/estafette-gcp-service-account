# estafette-gcp-service-account

This small Kubernetes application creates and renews Let's Encrypt SSL certificates in any secret with the correct annotations

[![License](https://img.shields.io/github/license/estafette/estafette-gcp-service-account.svg)](https://github.com/estafette/estafette-gcp-service-account/blob/master/LICENSE)

## Why?

In order to create GCP service accounts and store their keyfiles in Kubernetes secrets. This improves developer self-service.

## Usage

As a Kubernetes administrator, you first need to deploy the rbac.yaml file which set role and permissions.
Then deploy the application to Kubernetes cluster using the manifest below.

```
cat rbac.yaml | kubectl apply -f -
```

Create a google service account with keyfile and the following roles for bootstrapping only:

```
Service Account Admin
Service Account Key Admin
```

Create a secret with the bootstrap key only once:

```
cat bootstrap-secret.yaml | TEAM_NAME=tooling GOOGLE_SERVICE_ACCOUNT=<base64 encoded bootstrap service account keyfile> envsubst | kubectl apply -f -
```

Then create the deployment and other resources with

```
cat kubernetes.yaml | TEAM_NAME=tooling SERVICE_ACCOUNT_PREFIX=dev SERVICE_ACCOUNT_PROJECT_ID=my-gcp-sa-container-project-id KEY_ROTATION_AFTER_HOURS=360 envsubst | kubectl apply -f -
```

The bootstrap service account will be replaced with a dedicated service account, which now needs the same roles as well:

```
Service Account Admin
Service Account Key Admin
```

From now on the keys in the secrets will be rotated every KEY_ROTATION_AFTER_HOURS hours.