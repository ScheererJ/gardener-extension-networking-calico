// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"fmt"
	"strings"

	"github.com/gardener/gardener/pkg/utils"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Whisker(keyPair certificatemanagement.KeyPairInterface, trustBundle certificatemanagement.TrustedBundleRO) ([]client.Object, error) {
	/*components.ComponentCalicoWhisker = components.Component{
		Image:    "calico/whisker",
		Version:  "v1.0.0",
		Registry: "quay.io/any/random/path/",
	}
	components.ComponentCalicoWhiskerBackend = components.Component{
		Image:    "calico/whisker-backend",
		Version:  "v1.0.0",
		Registry: "quay.io/any/random/path/",
	}*/
	w := whisker.Whisker(&whisker.Configuration{
		CalicoVersion: "3.30.3",
		ClusterDomain: "cluster.local",
		ClusterID:     "id",
		ClusterType:   "type",
		Installation: &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		},
		Whisker: &operatorv1.Whisker{
			Spec: operatorv1.WhiskerSpec{
				Notifications: ptr.To(operatorv1.Disabled),
			},
		},
		WhiskerBackendKeyPair: keyPair,
		TrustedCertBundle:     trustBundle,
	})
	if err := w.ResolveImages(nil); err != nil {
		return nil, fmt.Errorf("could not resolve images: %w", err)
	}
	objsToCreate, _ := w.Objects()
	for _, objToCreate := range objsToCreate {
		objToCreate.SetNamespace(metav1.NamespaceSystem)
		objToCreate.SetLabels(utils.MergeStringMaps(objToCreate.GetLabels(), map[string]string{
			"app.kubernetes.io/name": "whisker",
			"k8s-app":                "whisker",
		}))
		deployment, ok := objToCreate.(*appsv1.Deployment)
		if ok {
			deployment.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "whisker",
				},
			}
			deployment.Spec.Template.Labels = utils.MergeStringMaps(deployment.Spec.Template.Labels, map[string]string{
				"app.kubernetes.io/name":           "whisker",
				"k8s-app":                          "whisker",
				"networking.gardener.cloud/to-dns": "allowed",
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
