package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
)

const caName = "calico"

func NewCertificateManger(secretsManager secretsmanager.Interface) *certificateManager {
	return &certificateManager{
		sm: secretsManager,
	}
}

type certificateManager struct {
	sm secretsmanager.Interface
}

func (m *certificateManager) KeyPair(ctx context.Context, component string) (certificatemanagement.KeyPairInterface, error) {
	if _, err := m.getCA(caName); err != nil {
		return nil, fmt.Errorf("getting ca: %w", err)
	}
	compCert, err := m.generateClientServerCert(ctx, component, caName)
	if err != nil {
		return nil, fmt.Errorf("generating cert %w", err)
	}
	return certificatemanagement.NewKeyPair(compCert, []string{component}, "cluster.local"), nil
}

func (m *certificateManager) TrustBundle(ctx context.Context) (certificatemanagement.TrustedBundle, error) {
	ca, err := m.getCA(caName)
	if err != nil {
		if !errors.Is(err, errNotFound) {
			return nil, err
		} else {
			ca, err = m.generateCA(ctx, caName)
			if err != nil {
				return nil, err
			}
		}
	}
	return certificatemanagement.CreateTrustedBundle(ca), nil
}

func (m *certificateManager) generateCA(ctx context.Context, name string) (*certificate, error) {
	certSecret, err := m.sm.Generate(ctx, &secrets.CertificateSecretConfig{
		Name:       name,
		CommonName: name + "-ca",
		CertType:   secrets.CACert,
	})
	if err != nil {
		return nil, err
	}
	return &certificate{
		isCA:   true,
		secret: certSecret,
	}, nil
}

var errNotFound = errors.New("not found")

func (m *certificateManager) getCA(name string) (*certificate, error) {
	certSecret, found := m.sm.Get(name)
	if !found {
		return nil, errNotFound
	}
	return &certificate{
		isCA:   true,
		secret: certSecret,
	}, nil
}

func (m *certificateManager) generateClientServerCert(ctx context.Context, name, caName string) (*corev1.Secret, error) {
	return m.sm.Generate(ctx, &secrets.CertificateSecretConfig{
		Name:       name,
		CommonName: name + "-client",
		DNSNames: []string{
			name,
			fmt.Sprintf("%s.kube-system", name),
			fmt.Sprintf("%s.kube-system.svc", name),
			fmt.Sprintf("%s.kube-system.svc.cluster.local", name),
		},
		CertType: secrets.ServerClientCert,
	}, secretsmanager.SignedByCA(caName))
}

type certificate struct {
	isCA   bool
	secret *corev1.Secret
	issuer *corev1.Secret
}

// GetCertificatePEM implements certificatemanagement.CertificateInterface.
func (c *certificate) GetCertificatePEM() []byte {
	if c.isCA {
		return c.secret.Data[secrets.DataKeyCertificateCA]
	}
	return c.secret.Data[secrets.DataKeyCertificateBundle]
}

// GetIssuer implements certificatemanagement.CertificateInterface.
func (c *certificate) GetIssuer() certificatemanagement.CertificateInterface {
	if c.issuer == nil {
		return nil
	}
	return &certificate{
		secret: c.issuer,
		isCA:   true,
		issuer: nil,
	}
}

// GetName implements certificatemanagement.CertificateInterface.
func (c *certificate) GetName() string {
	return c.secret.Name
}

// GetNamespace implements certificatemanagement.CertificateInterface.
func (c *certificate) GetNamespace() string {
	return c.secret.Namespace
}

var _ certificatemanagement.CertificateInterface = (*certificate)(nil)
