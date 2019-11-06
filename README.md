# estafette-gcp-service-account

This small Kubernetes application creates and renews Let's Encrypt SSL certificates in any secret with the correct annotations

[![License](https://img.shields.io/github/license/estafette/estafette-gcp-service-account.svg)](https://github.com/estafette/estafette-gcp-service-account/blob/master/LICENSE)

## Why?

In order to create GCP service accounts and store their keyfiles in Kubernetes secrets. This improves developer self-service.

## Installation

Create a google service account with keyfile and the following roles:

```
Service Account Admin
Service Account Key Admin
```

Prepare using Helm:

```
brew install kubernetes-helm
kubectl -n kube-system create serviceaccount tiller
kubectl create clusterrolebinding tiller --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
helm init --service-account tiller --wait
```

Then install or upgrade with Helm:

```
helm repo add estafette https://helm.estafette.io
helm upgrade --install estafette-gcp-service-account --namespace estafette estafette/estafette-gcp-service-account
```
