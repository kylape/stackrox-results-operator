podman build -t localhost:5001/mock-central:latest -f test/mock-central/Dockerfile .
podman push --tls-verify=false localhost:5001/mock-central:latest
podman build -t localhost:5001/stackrox-results-operator:latest .
podman push --tls-verify=false  localhost:5001/stackrox-results-operator:latest
make install
make deploy
kubectl -n stackrox-results-operator-system  set image deploy/stackrox-results-operator-controller-manager '*=kind-registry:5000/stackrox-results-operator:latest'
