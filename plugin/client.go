package quay

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	qc "github.com/redhat-cop/vault-plugin-secrets-quay/client"
)

type client struct {
	*qc.QuayClient
}

func newClient(config *quayConfig) (*client, error) {

	tlsConfig := tls.Config{}

	// Skip SSL Verification
	if config.DisableSslVerification {
		tlsConfig.InsecureSkipVerify = true
	}

	// Load TLS Certificate
	if len(config.CaCertificate) > 0 {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(config.CaCertificate))

		tlsConfig.RootCAs = certPool
	}

	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
		},
	}

	quayClient, err := qc.NewClient(&httpClient, config.URL, config.Token)

	if err != nil {
		return nil, err
	}

	return &client{quayClient}, nil

}
