package resources

import (
	"fmt"
	"strings"

	"github.com/gardener/gardener/pkg/utils"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Goldmane(keyPair certificatemanagement.KeyPairInterface, trustBundle certificatemanagement.TrustedBundleRO) ([]client.Object, error) {
	comp := goldmane.Goldmane(&goldmane.Configuration{
		Installation: &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		},
		OpenShift:             false,
		ClusterDomain:         "cluster.local",
		GoldmaneServerKeyPair: keyPair,
		TrustedCertBundle:     trustBundle,
		Goldmane:              &operatorv1.Goldmane{},
	})
	if err := comp.ResolveImages(nil); err != nil {
		return nil, fmt.Errorf("could not resolve images: %w", err)
	}
	objsToCreate, _ := comp.Objects()

	for _, objToCreate := range objsToCreate {
		objToCreate.SetNamespace(metav1.NamespaceSystem)
		objToCreate.SetLabels(utils.MergeStringMaps(objToCreate.GetLabels(), map[string]string{
			"app.kubernetes.io/name": "goldmane",
			"k8s-app":                "goldmane",
		}))
		deployment, ok := objToCreate.(*appsv1.Deployment)
		if ok {
			deployment.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "goldmane",
				},
			}
			deployment.Spec.Template.Labels = utils.MergeStringMaps(deployment.Spec.Template.Labels, map[string]string{
				"app.kubernetes.io/name":                 "goldmane",
				"k8s-app":                                "goldmane",
				"networking.gardener.cloud/to-dns":       "allowed",
				"networking.gardener.cloud/to-apiserver": "allowed",
			})
			for i, container := range deployment.Spec.Template.Spec.Containers {
				for j, env := range container.Env {
					if strings.Contains(env.Value, "calico-system") {
						deployment.Spec.Template.Spec.Containers[i].Env[j].Value = strings.ReplaceAll(env.Value, "calico-system", metav1.NamespaceSystem)
					}
				}
			}
		}
	}
	return objsToCreate, nil
}
