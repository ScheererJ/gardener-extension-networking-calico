// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"fmt"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/gardener/gardener/pkg/utils"
)

var (
	scheme *runtime.Scheme
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func WhiskerResources() (map[string][]byte, error) {
	components.ComponentCalicoWhisker = components.Component{
		Image:    "calico/whisker",
		Version:  "v1.0.0",
		Registry: "quay.io/any/random/path/",
	}
	components.ComponentCalicoWhiskerBackend = components.Component{
		Image:    "calico/whisker-backend",
		Version:  "v1.0.0",
		Registry: "quay.io/any/random/path/",
	}
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
		WhiskerBackendKeyPair: &whiskerBackendKeyPair{},
		TrustedCertBundle:     &trustedBundleR0{},
	})
	if err := w.ResolveImages(nil); err != nil {
		return nil, fmt.Errorf("could not resolve images: %w", err)
	}
	objsToCreate, _ := w.Objects()
	codec := serializer.NewCodecFactory(scheme)
	si, ok := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		return nil, fmt.Errorf("could not find encoder for media type %q", runtime.ContentTypeJSON)
	}
	result := map[string][]byte{}
	for _, objToCreate := range objsToCreate {
		objToCreate.SetNamespace(metav1.NamespaceSystem)
		objToCreate.SetLabels(utils.MergeStringMaps(objToCreate.GetLabels(), map[string]string{
			"app.kubernetes.io/name": "whisker",
			"k8s-app":                "whisker",
		}))
		gvk, err := apiutil.GVKForObject(objToCreate, scheme)
		if err != nil {
			return nil, fmt.Errorf("could not get gvk for object %q of type %T: %w", objToCreate.GetName(), objToCreate, err)
		}
		if gvk.Kind == "Deployment" {
			deployment := objToCreate.(*appsv1.Deployment)
			deployment.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "whisker",
				},
			}
			deployment.Spec.Template.Labels = utils.MergeStringMaps(deployment.Spec.Template.Labels, map[string]string{
				"app.kubernetes.io/name": "whisker",
				"k8s-app":                "whisker",
			})
			for i, container := range deployment.Spec.Template.Spec.Containers {
				for j, env := range container.Env {
					if strings.Contains(env.Value, "calico-system") {
						deployment.Spec.Template.Spec.Containers[i].Env[j].Value = strings.ReplaceAll(env.Value, "calico-system", metav1.NamespaceSystem)
					}
				}
			}
		}
		encoder := codec.EncoderForVersion(si.Serializer, gvk.GroupVersion())
		buffer := bytes.Buffer{}
		if err := encoder.Encode(objToCreate, &buffer); err != nil {
			return nil, fmt.Errorf("could not encode object %q of type %T: %w", objToCreate.GetName(), objToCreate, err)
		}
		result[gvk.Kind+"-"+objToCreate.GetName()] = buffer.Bytes()
	}
	return result, nil
}

type whiskerBackendKeyPair struct{}

func (w *whiskerBackendKeyPair) UseCertificateManagement() bool { return false }
func (w *whiskerBackendKeyPair) BYO() bool                      { return false }
func (w *whiskerBackendKeyPair) InitContainer(namespace string, securityContext *corev1.SecurityContext) corev1.Container {
	return corev1.Container{}
}
func (w *whiskerBackendKeyPair) VolumeMount(osType meta.OSType) corev1.VolumeMount {
	return corev1.VolumeMount{}
}
func (w *whiskerBackendKeyPair) VolumeMountKeyFilePath() string                        { return "" }
func (w *whiskerBackendKeyPair) VolumeMountCertificateFilePath() string                { return "" }
func (w *whiskerBackendKeyPair) Volume() corev1.Volume                                 { return corev1.Volume{} }
func (w *whiskerBackendKeyPair) Secret(namespace string) *corev1.Secret                { return &corev1.Secret{} }
func (w *whiskerBackendKeyPair) HashAnnotationKey() string                             { return "" }
func (w *whiskerBackendKeyPair) HashAnnotationValue() string                           { return "" }
func (w *whiskerBackendKeyPair) GetIssuer() certificatemanagement.CertificateInterface { return nil }
func (w *whiskerBackendKeyPair) GetCertificatePEM() []byte                             { return nil }
func (w *whiskerBackendKeyPair) GetName() string                                       { return "" }
func (w *whiskerBackendKeyPair) GetNamespace() string                                  { return "" }

type trustedBundleR0 struct{}

func (t *trustedBundleR0) MountPath() string                  { return "" }
func (t *trustedBundleR0) HashAnnotations() map[string]string { return map[string]string{} }
func (t *trustedBundleR0) VolumeMounts(osType meta.OSType) []corev1.VolumeMount {
	return []corev1.VolumeMount{}
}
func (t *trustedBundleR0) Volume() corev1.Volume { return corev1.Volume{} }
