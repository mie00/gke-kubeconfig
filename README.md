# GKE Kubeconfig

This is made mainly to reduce the time of the deployment phase to gke as it usually requires a gcloud image which is very big. And it was created by reverse engineering gcloud.

usage:

```bash
cat /path/to/serviceaccount-creds-123432423.json | ./gke-kubeconfig -cluster mycluster -location us-central1-a -project mycluster-1234 > "$HOME"/.kube/config
```
