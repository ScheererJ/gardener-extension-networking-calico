// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/gardener/gardener-extension-networking-calico/pkg/controller"
)

func main() {
	data, err := controller.WhiskerResources()
	if err != nil {
		panic(err)
	}
	for k, v := range data {
		fmt.Printf("=== %s ===\n%s\n", k, v)
	}
}
