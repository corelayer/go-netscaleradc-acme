/*
 * Copyright 2024 CoreLayer BV
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package netscalerdns

import (
	"fmt"
	"log/slog"

	"github.com/corelayer/go-netscaleradc-nitro/pkg/nitro"
	"github.com/corelayer/go-netscaleradc-nitro/pkg/nitro/resource/config"
	"github.com/corelayer/go-netscaleradc-nitro/pkg/nitro/resource/controllers"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
)

const (
	envNamespace = "NETSCALERADC_DNS_"

	envName                      = envNamespace + "NAME"
	envAddress                   = envNamespace + "ADDRESS"
	envUsername                  = envNamespace + "USER"
	envPassword                  = envNamespace + "PASS"
	envUseSsl                    = envNamespace + "USE_SSL"
	envValidateServerCertificate = envNamespace + "VALIDATE_SERVER_CERTIFICATE"
	envTimeout                   = envNamespace + "TIMEOUT"

	ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS = "netscalerdns"
)

func newProviderConfig() (*providerConfig, error) {
	var (
		err    error
		values map[string]string
	)

	values, err = env.Get(envName, envAddress, envUsername, envPassword)
	if err != nil {
		return nil, err
	}

	return &providerConfig{
		Name:                      values[envName],
		Address:                   values[envAddress],
		Username:                  values[envUsername],
		Password:                  values[envPassword],
		UseSsl:                    env.GetOrDefaultBool(envUseSsl, true),
		ValidateServerCertificate: env.GetOrDefaultBool(envValidateServerCertificate, true),
		Timeout:                   env.GetOrDefaultInt(envTimeout, 5000),
	}, nil
}

type providerConfig struct {
	Name                      string
	Address                   string
	Username                  string
	Password                  string
	UseSsl                    bool
	ValidateServerCertificate bool
	Timeout                   int
}

func (c providerConfig) GetClient() (*nitro.Client, error) {
	return nitro.NewClient(c.Name, c.Address, c.getCredentials(), c.getConnectionSettings())
}

func (c providerConfig) getCredentials() nitro.Credentials {
	return nitro.Credentials{
		Username: c.Username,
		Password: c.Password,
	}
}

func (c providerConfig) getConnectionSettings() nitro.ConnectionSettings {
	return nitro.ConnectionSettings{
		UseSsl:                    c.UseSsl,
		Timeout:                   c.Timeout,
		UserAgent:                 "",
		ValidateServerCertificate: c.ValidateServerCertificate,
		LogTlsSecrets:             false,
		LogTlsSecretsDestination:  "",
		AutoLogin:                 false,
	}
}

func NewNetScalerDnsProvider(maxRetries int) (*DNSProvider, error) {
	var (
		err error
		c   *providerConfig
		n   *nitro.Client
		p   *DNSProvider
	)
	c, err = newProviderConfig()
	if err != nil {
		slog.Error("failed to initialize client configuration from environment", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "error", err)
		return nil, err
	}

	n, err = c.GetClient()
	if err != nil {
		slog.Error("failed to initialize nitro client", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "error", err)
		return nil, err
	}

	p = &DNSProvider{
		nitroClient: n,
		maxRetries:  maxRetries,
	}
	p.initialize()
	return &DNSProvider{
		maxRetries: maxRetries,
	}, nil
}

// DNSProvider manages ACME requests for NetScaler ADC Authoritative DNS service
type DNSProvider struct {
	nitroClient *nitro.Client
	dnsTxtRec   *controllers.DnsTxtRecController
	maxRetries  int
}

// Present the ACME challenge to the provider.
// domain is the fqdn for which the challenge will be provided
// Parameter endpoint is the path to which ACME will look  for the challenge (/.well-known/acme-challenge/<token>)
// Parameter keyAuth is the value which must be returned for a successful challenge
func (p *DNSProvider) Present(domain string, token string, keyAuth string) error {
	var err error
	slog.Info("present acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)

	// Get challenge information to
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// Add DNS record to ADNS zone on NetScaler ADC
	slog.Debug("create dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)
	if _, err = p.dnsTxtRec.Add(info.FQDN, []string{info.Value}, 30); err != nil {
		slog.Error("failed to create dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain, "error", err)
		return fmt.Errorf("failed to create dns record %s: %w", domain, err)
	}

	slog.Debug("finished presenting acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)
	return nil
}

func (p *DNSProvider) CleanUp(domain string, token string, keyAuth string) error {
	var err error
	slog.Info("cleanup acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)

	// Get DNS01 Challenge info
	info := dns01.GetChallengeInfo(domain, keyAuth)

	slog.Debug("delete dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)
	var res *nitro.Response[config.DnsTxtRec]
	// Limit data transfer by limiting returned fields
	if res, err = p.dnsTxtRec.Get(info.FQDN, []string{"string", "recordid"}); err != nil {
		slog.Error("failed to get record id", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain, "error", err)
		return fmt.Errorf("failed to get record id %s: %w", domain, err)

	}

	for _, rec := range res.Data {
		slog.Debug("processing dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain, "recordid", rec.RecordId)
		// Loop over array of returned records
		for _, data := range rec.Data {
			// Only remove record if keyAuth matches the current acme request
			if data != info.Value {
				slog.Debug("skipping dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)
				continue
			}

			if _, err = p.dnsTxtRec.Delete(info.FQDN, rec.RecordId); err != nil {
				slog.Error("failed to delete dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain, "error", err)
				return fmt.Errorf("failed to delete dns record %s: %w", domain, err)
			}
			slog.Debug("deleted dns record", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)
		}
	}

	slog.Debug("finished cleaning up acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_ADNS, "domain", domain)
	return nil
}

func (p *DNSProvider) initialize() {
	p.dnsTxtRec = controllers.NewDnsTxtRecController(p.nitroClient)
}
