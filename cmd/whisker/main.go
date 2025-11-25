// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/gardener/gardener-extension-networking-calico/pkg/controller"
)

func main() {
	cfg := config.GetConfigOrDie()
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		panic(err)
	}
	sm, err := manager.New(context.Background(), logr.Discard(), clock.RealClock{}, c, "kube-system", "calico", manager.Config{})
	if err != nil {
		panic(err)
	}
	cm := controller.NewCertificateManger(sm)
	tr, err := cm.TrustBundle(context.Background())
	if err != nil {
		panic(err)
	}
	trustBundleConfigMap := tr.ConfigMap("kube-system")
	_, err = controllerutil.CreateOrUpdate(context.Background(), c, trustBundleConfigMap, func() error {
		cp := trustBundleConfigMap.DeepCopy()
		trustBundleConfigMap.Data = cp.Data
		trustBundleConfigMap.Labels = cp.Labels
		trustBundleConfigMap.Annotations = cp.Annotations
		return nil
	})
	if err != nil {
		panic(err)
	}

	key, err := cm.KeyPair(context.Background(), "goldmane")
	if err != nil {
		panic(err)
	}
	data, err := controller.GoldmaneResources(key, tr)
	if err != nil {
		panic(err)
	}
	for k, v := range data {
		fmt.Printf("=== %s ===\n%s\n", k, v)
	}

	whiskerKey, err := cm.KeyPair(context.Background(), "whisker")
	if err != nil {
		panic(err)
	}
	whiskerData, err := controller.WhiskerResources(whiskerKey, tr)
	if err != nil {
		panic(err)
	}
	for k, v := range whiskerData {
		fmt.Printf("=== %s ===\n%s\n", k, v)
	}
}
