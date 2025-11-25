package resources

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Resources(ctx context.Context, cm *CertificateManager, trustBundle certificatemanagement.TrustedBundle) ([]client.Object, error) {
	goldmaneKey, err := cm.KeyPair(context.Background(), "goldmane", "client")
	if err != nil {
		panic(err)
	}
	goldmaneObjs, err := Goldmane(goldmaneKey, trustBundle)
	if err != nil {
		return nil, fmt.Errorf("creating goldmane resources: %w", err)
	}

	whiskerKey, err := cm.KeyPair(context.Background(), "whisker", "client")
	if err != nil {
		panic(err)
	}
	whiskerObjs, err := Whisker(whiskerKey, trustBundle)
	if err != nil {
		panic(err)
	}
	return append(whiskerObjs, goldmaneObjs...), nil
}
