// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	extensionsconfig "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/apis/extensions/validation"
	gardenerkubernetes "github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/utils/chart"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	monitoringv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/gardener/gardener-extension-networking-calico/charts"
	calicov1alpha1 "github.com/gardener/gardener-extension-networking-calico/pkg/apis/calico/v1alpha1"
	calicov1alpha1helper "github.com/gardener/gardener-extension-networking-calico/pkg/apis/calico/v1alpha1/helper"
	"github.com/gardener/gardener-extension-networking-calico/pkg/calico"
	chartspkg "github.com/gardener/gardener-extension-networking-calico/pkg/charts"
	"github.com/gardener/gardener-extension-networking-calico/pkg/features"
	"github.com/gardener/gardener-extension-networking-calico/pkg/resources"
)

const (
	// CalicoConfigManagedResourceName is the name of the managed resource of networking calico
	CalicoConfigManagedResourceName = "extension-networking-calico-config"
)

func applyMonitoringConfig(ctx context.Context, seedClient client.Client, chartApplier gardenerkubernetes.ChartApplier, network *extensionsv1alpha1.Network, deleteChart bool) error {
	calicoControlPlaneMonitoringChart := &chart.Chart{
		Name:       calico.MonitoringName,
		EmbeddedFS: charts.InternalChart,
		Path:       calico.CalicoMonitoringChartPath,
		Objects: []*chart.Object{
			{
				Type: &corev1.ConfigMap{},
				Name: calico.MonitoringName,
			},
			{
				Type: &corev1.ConfigMap{},
				Name: "calico-dashboards",
			},
			{
				Type: &monitoringv1alpha1.ScrapeConfig{},
				Name: "shoot-calico-felix",
			},
			{
				Type: &monitoringv1alpha1.ScrapeConfig{},
				Name: "shoot-calico-typha",
			},
		},
	}

	if network.Spec.ProviderConfig != nil && network.Spec.ProviderConfig.Raw != nil {
		networkConfig, err := calicov1alpha1helper.CalicoNetworkConfigFromNetworkResource(network)
		if err != nil {
			return err
		}
		if networkConfig.BirdExporter != nil && networkConfig.BirdExporter.Enabled {
			calicoControlPlaneMonitoringChart.Objects = append(calicoControlPlaneMonitoringChart.Objects, &chart.Object{
				Type: &monitoringv1alpha1.ScrapeConfig{},
				Name: "shoot-calico-bird",
			})
		}
	}

	if deleteChart {
		return client.IgnoreNotFound(calicoControlPlaneMonitoringChart.Delete(ctx, seedClient, network.Namespace))
	}

	return calicoControlPlaneMonitoringChart.Apply(ctx, chartApplier, network.Namespace, nil, "", "", nil)
}

// Reconcile implements Network.Actuator.
func (a *actuator) Reconcile(ctx context.Context, l logr.Logger, network *extensionsv1alpha1.Network, cluster *extensionscontroller.Cluster) error {
	if extensionscontroller.IsHibernated(cluster) {
		return nil
	}
	if errList := validation.ValidateNetwork(network); len(errList) != 0 {
		return fmt.Errorf("invalid network resource: %w", errList.ToAggregate())
	}
	var (
		networkConfig *calicov1alpha1.NetworkConfig
		err           error
	)

	ipFamilies := slices.Clone(network.Spec.IPFamilies)

	if network.Spec.ProviderConfig != nil {
		networkConfig, err = calicov1alpha1helper.CalicoNetworkConfigFromNetworkResource(network)
		if err != nil {
			return err
		}
		if err := ValidateNetworkConfig(networkConfig); err != nil {
			return err
		}
	}

	if condition := gardencorev1beta1helper.GetCondition(cluster.Shoot.Status.Constraints, v1beta1.ShootDualStackNodesMigrationReady); condition != nil && condition.Status != v1beta1.ConditionTrue {
		if len(ipFamilies) > 1 {
			ipFamilies = ipFamilies[:1]
		}
	}

	if networkConfig == nil {
		networkConfig = &calicov1alpha1.NetworkConfig{}
	}

	if slices.Contains(ipFamilies, extensionsv1alpha1.IPFamilyIPv4) {
		if networkConfig.IPv4 == nil {
			networkConfig.IPv4 = &calicov1alpha1.IPv4{}
		}
	}
	if slices.Contains(ipFamilies, extensionsv1alpha1.IPFamilyIPv6) {
		if networkConfig.IPv6 == nil {
			networkConfig.IPv6 = &calicov1alpha1.IPv6{}
		}
	}

	if cluster.Shoot.Spec.Networking != nil && cluster.Shoot.Spec.Networking.Nodes != nil && len(*cluster.Shoot.Spec.Networking.Nodes) > 0 {
		autodetectionMode := fmt.Sprintf("cidr=%s", *cluster.Shoot.Spec.Networking.Nodes)
		setAutoDetectionMethod(networkConfig, ipFamilies, autodetectionMode)

		if cluster.Shoot.Status.Networking != nil && cluster.Shoot.Status.Networking.Nodes != nil && len(cluster.Shoot.Status.Networking.Nodes) > 0 {
			ipv4Nodes, ipv6Nodes, err := segregateNodeCIDRs(cluster.Shoot.Status.Networking.Nodes)
			if err != nil {
				return err
			}

			autodetectionMode = updateAutoDetectionMode(ipv4Nodes)
			setAutoDetectionMethod(networkConfig, ipFamilies, autodetectionMode)

			autodetectionModeV6 := updateAutoDetectionMode(ipv6Nodes)
			setAutoDetectionMethodV6(networkConfig, ipFamilies, autodetectionModeV6)
		}
	}

	if networkConfig != nil {
		if networkConfig.Overlay != nil {
			if networkConfig.Overlay.Enabled {
				setPoolMode(networkConfig, ipFamilies, calicov1alpha1.Always)
				if networkConfig.VXLAN != nil && networkConfig.VXLAN.Enabled {
					networkConfig.Backend = (*calicov1alpha1.Backend)(ptr.To(string(calicov1alpha1.VXLan)))
				}
			} else {
				setPoolMode(networkConfig, ipFamilies, calicov1alpha1.Never)
				if networkConfig.Overlay.CreatePodRoutes != nil && *networkConfig.Overlay.CreatePodRoutes {
					networkConfig.Backend = (*calicov1alpha1.Backend)(ptr.To(string(calicov1alpha1.Bird)))
				}
			}
		} else {
			if slices.Contains(ipFamilies, extensionsv1alpha1.IPFamilyIPv6) {
				setPoolMode(networkConfig, ipFamilies, calicov1alpha1.Never)
			}
		}
	}

	if cluster.Shoot.Spec.Kubernetes.KubeProxy != nil && cluster.Shoot.Spec.Kubernetes.KubeProxy.Enabled != nil && !*cluster.Shoot.Spec.Kubernetes.KubeProxy.Enabled {
		if networkConfig == nil || networkConfig.EbpfDataplane == nil || (networkConfig.EbpfDataplane != nil && !networkConfig.EbpfDataplane.Enabled) {
			return field.Forbidden(field.NewPath("spec", "kubernetes", "kubeProxy", "enabled"), "Disabling kube-proxy is forbidden in conjunction with calico without running in ebpf dataplane")
		}
	}

	kubeProxyEnabled := true
	if cluster.Shoot.Spec.Kubernetes.KubeProxy != nil && cluster.Shoot.Spec.Kubernetes.KubeProxy.Enabled != nil {
		kubeProxyEnabled = *cluster.Shoot.Spec.Kubernetes.KubeProxy.Enabled
	}

	// Create shoot chart renderer
	chartRenderer, err := a.chartRendererFactory.NewChartRendererForShoot(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return fmt.Errorf("could not create chart renderer for shoot '%s': %w", network.Namespace, err)
	}

	var podCIDRs []string
	if cluster.Shoot.Status.Networking != nil {
		podCIDRs = cluster.Shoot.Status.Networking.Pods
	}

	_, c, err := util.NewClientForShoot(ctx, a.client, network.Namespace, client.Options{}, extensionsconfig.RESTOptions{})
	if err != nil {
		return fmt.Errorf("could not create shoot client for shoot '%s': %w", network.Namespace, err)
	}
	sm, err := manager.New(ctx, l, clock.RealClock{}, c, metav1.NamespaceSystem, calico.Name, manager.Config{})
	if err != nil {
		panic(err)
	}
	cm := resources.NewCertificateManger(sm)
	trustBundle, err := cm.TrustBundle(ctx)
	if err != nil {
		panic(err)
	}
	typhaKey, err := cm.KeyPair(ctx, "typha", "server")
	if err != nil {
		return err
	}
	nodeKey, err := cm.KeyPair(ctx, "node", "client")
	if err != nil {
		return err
	}

	calicoChart, err := chartspkg.RenderCalicoChart(
		chartRenderer,
		network,
		networkConfig,
		cluster.Shoot.Spec.Kubernetes.Version,
		gardencorev1beta1helper.ShootWantsVerticalPodAutoscaler(cluster.Shoot),
		kubeProxyEnabled,
		features.FeatureGate.Enabled(features.NonPrivilegedCalicoNode),
		cluster.Shoot.Spec.Networking.Nodes,
		podCIDRs,
		ipFamilies,
		typhaKey.GetName(),
		nodeKey.GetName(),
	)
	if err != nil {
		return err
	}

	operatorResources, err := resources.Resources(ctx, cm, trustBundle)
	if err != nil {
		return fmt.Errorf("generating calico operator resources: %w", err)
	}
	operatorBytes, err := serializeObjects(c.Scheme(), operatorResources)
	if err != nil {
		return fmt.Errorf("serialzing operator resources: %w", err)
	}

	data := map[string][]byte{chartspkg.CalicoConfigKey: calicoChart, "operator-resources": operatorBytes}
	if err := managedresources.CreateForShoot(ctx, a.client, network.Namespace, CalicoConfigManagedResourceName, "extension-networking-calico", false, data); err != nil {
		return err
	}

	if err := applyMonitoringConfig(ctx, a.client, a.chartApplier, network, false); err != nil {
		return err
	}

	return a.updateProviderStatus(ctx, network, networkConfig)
}

func setPoolMode(networkConfig *calicov1alpha1.NetworkConfig, ipFamilies []extensionsv1alpha1.IPFamily, mode calicov1alpha1.PoolMode) {
	if slices.Contains(ipFamilies, extensionsv1alpha1.IPFamilyIPv6) {
		networkConfig.IPv6.Mode = (*calicov1alpha1.PoolMode)(ptr.To(string(mode)))
	} else {
		networkConfig.IPv4.Mode = (*calicov1alpha1.PoolMode)(ptr.To(string(mode)))
	}

	if mode == calicov1alpha1.Never {
		networkConfig.Backend = (*calicov1alpha1.Backend)(ptr.To(string(calicov1alpha1.None)))
	} else {
		networkConfig.Backend = (*calicov1alpha1.Backend)(ptr.To(string(calicov1alpha1.Bird)))
	}
}

func setAutoDetectionMethod(networkConfig *calicov1alpha1.NetworkConfig, ipFamilies []extensionsv1alpha1.IPFamily, autodetectionMode string) {
	if slices.Contains(ipFamilies, extensionsv1alpha1.IPFamilyIPv4) {
		networkConfig.IPv4.AutoDetectionMethod = &autodetectionMode
	}
}

func setAutoDetectionMethodV6(networkConfig *calicov1alpha1.NetworkConfig, ipFamilies []extensionsv1alpha1.IPFamily, autodetectionModeV6 string) {
	if slices.Contains(ipFamilies, extensionsv1alpha1.IPFamilyIPv6) {
		networkConfig.IPv6.AutoDetectionMethod = &autodetectionModeV6
	}
}

func segregateNodeCIDRs(nodeCIDRs []string) ([]string, []string, error) {
	var ipv4Nodes, ipv6Nodes []string
	for _, nodeCidr := range nodeCIDRs {
		_, cidr, err := net.ParseCIDR(nodeCidr)
		if err != nil {
			return nil, nil, err
		}
		if cidr.IP.To4() != nil {
			ipv4Nodes = append(ipv4Nodes, nodeCidr)
		} else {
			ipv6Nodes = append(ipv6Nodes, nodeCidr)
		}
	}
	return ipv4Nodes, ipv6Nodes, nil
}

func updateAutoDetectionMode(nodes []string) string {
	if len(nodes) > 0 {
		return fmt.Sprintf("cidr=%s", strings.Join(nodes, ","))
	}
	return ""
}

func serializeObjects(scheme *runtime.Scheme, objs []client.Object) ([]byte, error) {
	var data []byte
	codec := serializer.NewCodecFactory(scheme)
	si, ok := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		return nil, fmt.Errorf("could not find encoder for media type %q", runtime.ContentTypeJSON)
	}
	for _, obj := range objs {
		gvk, err := apiutil.GVKForObject(obj, scheme)
		if err != nil {
			return nil, fmt.Errorf("could not get gvk for %q of type %T: %w", obj.GetName(), obj, err)
		}
		encoder := codec.EncoderForVersion(si.Serializer, gvk.GroupVersion())
		buffer := bytes.Buffer{}
		if err := encoder.Encode(obj, &buffer); err != nil {
			return nil, fmt.Errorf("could not encode object %q of type %T: %w", obj.GetName(), obj, err)
		}
		data = append(data, []byte("\n---\n")...)
		data = append(data, buffer.Bytes()...)
	}
	return data, nil
}
