package controller

import (
	"bytes"
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func GoldmaneResources(keyPair certificatemanagement.KeyPairInterface, trustBundle certificatemanagement.TrustedBundleRO) (map[string][]byte, error) {
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
	objsToCreate, _ := comp.Objects()

	codec := serializer.NewCodecFactory(scheme)
	si, ok := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		return nil, fmt.Errorf("could not find encoder for media type %q", runtime.ContentTypeJSON)
	}
	result := map[string][]byte{}
	for _, objToCreate := range objsToCreate {
		objToCreate.SetNamespace(metav1.NamespaceSystem)
		gvk, err := apiutil.GVKForObject(objToCreate, scheme)
		if err != nil {
			return nil, fmt.Errorf("could not get gvk for object %q of type %T: %w", objToCreate.GetName(), objToCreate, err)
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
