# Local Development Configuration

This directory contains Kustomize overlays for local development in KinD clusters.

## Usage

Deploy the operator to your local KinD cluster:

```bash
kubectl apply -k config/local
```

This overlay:
- Sets namespace to `stackrox`
- Sets namePrefix to `results-operator-`
- Uses local registry image: `kind-registry:5000/stackrox-results-operator:v2`
- Sets `imagePullPolicy: IfNotPresent` for local images

## Updating

To change the image tag, edit `kustomization.yaml`:

```yaml
images:
- name: controller
  newName: kind-registry:5000/stackrox-results-operator
  newTag: v3  # Change this
```

## Note

This directory is gitignored to prevent local development configs from being committed.
