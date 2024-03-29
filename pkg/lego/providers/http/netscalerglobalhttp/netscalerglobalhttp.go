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

package netscalerglobalhttp

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/corelayer/go-netscaleradc-nitro/pkg/nitro"
	"github.com/corelayer/go-netscaleradc-nitro/pkg/nitro/resource/config"
	"github.com/corelayer/go-netscaleradc-nitro/pkg/nitro/resource/controllers"
	"github.com/go-acme/lego/v4/platform/config/env"
)

const (
	envNamespace = "NETSCALERADC_HTTP_"

	EnvName                      = envNamespace + "NAME"
	EnvAddress                   = envNamespace + "ADDRESS"
	EnvUsername                  = envNamespace + "USER"
	EnvPassword                  = envNamespace + "PASS"
	EnvUseSsl                    = envNamespace + "USE_SSL"
	EnvValidateServerCertificate = envNamespace + "VALIDATE_SERVER_CERTIFICATE"
	EnvTimeout                   = envNamespace + "TIMEOUT"

	ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL = "netscaler-http-global"
)

func newProviderConfig() (*providerConfig, error) {
	var (
		err    error
		values map[string]string
	)

	values, err = env.Get(EnvName, EnvAddress, EnvUsername, EnvPassword)
	if err != nil {
		return nil, err
	}

	return &providerConfig{
		Name:                      values[EnvName],
		Address:                   values[EnvAddress],
		Username:                  values[EnvUsername],
		Password:                  values[EnvPassword],
		UseSsl:                    env.GetOrDefaultBool(EnvUseSsl, true),
		ValidateServerCertificate: env.GetOrDefaultBool(EnvValidateServerCertificate, true),
		Timeout:                   env.GetOrDefaultInt(EnvTimeout, 5000),
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

func (c providerConfig) getClient() (*nitro.Client, error) {
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

// NewGlobalHttpProvider returns an HTTPProvider instance from environment variable settings
func NewNetScalerGlobalHttpProvider(prefix string, maxRetries int, timestamp string) (*HttpProvider, error) {
	var (
		err error
		c   *providerConfig
		n   *nitro.Client
		p   *HttpProvider
	)

	c, err = newProviderConfig()
	if err != nil {
		slog.Error("failed to initialize client configuration from environment", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "error", err)
		return nil, err
	}

	n, err = c.getClient()
	if err != nil {
		slog.Error("failed to initialize nitro client", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "error", err)
		return nil, err
	}

	p = &HttpProvider{
		client:     n,
		maxRetries: maxRetries,
		timestamp:  timestamp,
	}
	p.initialize(prefix)

	return p, nil
}

type HttpProvider struct {
	client         *nitro.Client
	rsaController  *controllers.ResponderActionController
	rspController  *controllers.ResponderPolicyController
	rspbController *controllers.ResponderGlobalResponderPolicyBindingController

	rspbBindType string
	rsaPrefix    string
	rspPrefix    string
	timestamp    string

	maxRetries int
}

// Present the ACME challenge to the provider before validation
//
//	domain is the fqdn for which the challenge will be provided
//	token is the path to which ACME will look  for the challenge (/.well-known/acme-challenge/<token>)
//	keyAuth is the value which must be returned for a successful challenge
func (p *HttpProvider) Present(domain string, token string, keyAuth string) error {
	var err error
	slog.Info("present acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain)

	rsaActionName := p.getResponderActionName(domain)
	rspPolicyName := p.getResponderPolicyName(domain)
	rsaAction := "\"HTTP/1.1 200 OK\\r\\n\\r\\n" + keyAuth + "\""
	rspRule := "HTTP.REQ.HOSTNAME.EQ(\"" + domain + "\") && HTTP.REQ.URL.EQ(\"/.well-known/acme-challenge/" + token + "\")"

	// Create responder action
	slog.Debug("create responder action", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rsaActionName)
	if _, err = p.rsaController.Add(rsaActionName, "respondwith", rsaAction); err != nil {
		slog.Error("failed to create responder action", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rsaActionName)
		return fmt.Errorf("failed to create responder action %s for %s: %w", rsaActionName, domain, err)
	}

	// Create responder policy
	slog.Debug("create responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
	if _, err = p.rspController.Add(rspPolicyName, rspRule, rsaActionName, ""); err != nil {
		slog.Error("failed to create responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
		return fmt.Errorf("failed to create responder policy %s for %s: %w", rspPolicyName, domain, err)
	}

	// Bind responder policy to REQ_OVERRIDE
	// We need REQ_OVERRIDE, otherwise responder policies bound to a csvserver/lbvserver get a higher priority
	slog.Debug("globally bind responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
	if err = p.bindResponderPolicy(domain); err != nil {
		slog.Error("failed to globally bind responder policy globally", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
		return fmt.Errorf("failed to globally bind responder policy %s for %s: %w", rspPolicyName, domain, err)
	}

	slog.Debug("finished presenting acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain)
	return nil
}

// CleanUp the ACME challenge on the provider after validation
//
//	domain is the fqdn for which the challenge will be provided
//	token is the path to which ACME will look  for the challenge (/.well-known/acme-challenge/<token>)
//	keyAuth is the value which must be returned for a successful challenge
func (p *HttpProvider) CleanUp(domain string, token string, keyAuth string) error {
	var err error
	slog.Info("cleanup acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain)

	rspPolicyName := p.getResponderPolicyName(domain)
	rsaActionName := p.getResponderActionName(domain)

	// Unbind responder policy from globalconfig REQ_OVERRIDE
	slog.Debug("globally unbind responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
	if _, err = p.rspbController.Delete(rspPolicyName, p.rspbBindType); err != nil {
		slog.Error("failed to globally unbind responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
		return fmt.Errorf("failed to globally unbind responder policy %s for %s: %w", rspPolicyName, domain, err)
	}

	slog.Debug("remove responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
	if _, err = p.rspController.Delete(rspPolicyName); err != nil {
		slog.Error("failed to remove responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
		return fmt.Errorf("failed to remove responder policy %s for %s: %w", rspPolicyName, domain, err)
	}

	slog.Debug("remove responder action", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rsaActionName)
	if _, err = p.rsaController.Delete(rsaActionName); err != nil {
		slog.Error("failed to remove responder action", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rsaActionName)
		return fmt.Errorf("failed to remove responder action %s for %s: %w", rsaActionName, domain, err)
	}

	slog.Debug("finished cleaning up acme challenge", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain)
	return nil
}

// bindResponderPolicy will bind the responder policy globally on NetScaler
func (p *HttpProvider) bindResponderPolicy(domain string) error {
	var (
		successfullyBoundPolicy = false
		retries                 = 0
		err                     error
		priority                string
		rspPolicyName           = p.getResponderPolicyName(domain)
	)

	for !successfullyBoundPolicy {
		slog.Debug("search for valid binding priority", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)

		retries += 1
		priority, err = p.getPriority()
		if err != nil {
			slog.Error("failed to find valid policy binding priority", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "error", err)
			return fmt.Errorf("failed to find valid policy binding priority for %s: %w", domain, err)
		}

		if _, err = p.rspbController.Add(rspPolicyName, p.rspbBindType, priority, "END"); err != nil {
			if retries >= p.maxRetries {
				slog.Error("exceeded max retries to globally bind responder policy", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "domain", domain, "resource", rspPolicyName)
				return fmt.Errorf("exceeded max retries to globally bind responder policy %s for %s: %w", rspPolicyName, domain, err)
			}
			// If the attempt to bind the policy at the current priority fails, continue to the next iteration to increase the priority
			continue
		}
		// The binding completed successfully, exit the loop
		successfullyBoundPolicy = true
	}
	return nil
}

// getPolicyBindingPriorities will get all global responder binding priorities currently in use on NetScaler
func (p *HttpProvider) getPolicyBindingPriorities() ([]string, error) {
	var (
		err      error
		output   []string
		bindings *nitro.Response[config.ResponderGlobalResponderPolicyBinding]
	)
	slog.Debug("retrieve existing binding priorities", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL)

	// Create custom Nitro Request
	// Limit data transfer by limiting returned fields
	nitroRequest := &nitro.Request[config.ResponderGlobalResponderPolicyBinding]{
		Arguments: map[string]string{
			"type": p.rspbBindType,
		},
		Attributes: []string{"priority"},
	}

	// Execute Nitro Request
	bindings, err = nitro.ExecuteNitroRequest[config.ResponderGlobalResponderPolicyBinding](p.client, nitroRequest)
	if err != nil {
		slog.Error("failed to retrieve existing binding priorities", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL)
		return nil, fmt.Errorf("failed to retrieve existing binding priorities: %w", err)
	}

	// If no priorities are found, the nitro request will return an empty slice, so we can return immediately
	if len(bindings.Data) == 0 {
		slog.Debug("no globally bound responder policies found", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL)
		return output, nil
	}

	// If there are policies bound, add existing priorities to the list
	for _, binding := range bindings.Data {
		output = append(output, binding.Priority)
	}
	return output, nil
}

// getPriority finds an available priority for binding the responder policy
func (p *HttpProvider) getPriority() (string, error) {
	var (
		err                error
		priority           float64 = 33500
		usedPriorities     []string
		validPriorityFound bool = false
	)
	slog.Debug("find valid priority for binding", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL)

	usedPriorities, err = p.getPolicyBindingPriorities()
	if err != nil {
		return "", err
	}

	// If there are no existing priorities, use the deault value + 1
	if len(usedPriorities) == 0 {
		priority = priority + 1
		slog.Debug("using default priority", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "priority", priority)
		return fmt.Sprintf("%g", priority), nil
	}

	// Existing priorities are found, find available priority
	for !validPriorityFound {
		priority = priority + 1
		validPriorityFound = !p.priorityExists(priority, usedPriorities)
	}
	slog.Debug("found available priority", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "priority", priority)
	return fmt.Sprintf("%g", priority), nil
}

// priorityExists checks if a priority is present in a slice or priorities
//
//	priority is the desired priority
//	usedPriorities is the current list of priorities in use
func (p *HttpProvider) priorityExists(priority float64, usedPriorities []string) bool {
	if len(usedPriorities) == 0 {
		return false
	}

	for _, usedPriority := range usedPriorities {
		// Convert priority to string --> exponent as needed, necessary digits only
		if fmt.Sprintf("%g", priority) == usedPriority {
			slog.Debug("priority is in use", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "priority", priority)
			return true
		}
	}
	slog.Debug("priority is available", "provider", ACME_CHALLENGE_PROVIDER_NETSCALER_HTTP_GLOBAL, "priority", priority)
	return false
}

// getResponderActionName generates the name for the responder action
func (p *HttpProvider) getResponderActionName(domain string) string {
	return p.rsaPrefix + domain + "_" + p.timestamp
}

// getResponderPolicyName generates the name for the responder policy
func (p *HttpProvider) getResponderPolicyName(domain string) string {
	return p.rspPrefix + domain + "_" + p.timestamp
}

func (p *HttpProvider) initialize(prefix string) {
	p.rsaController = controllers.NewResponderActionController(p.client)
	p.rspController = controllers.NewResponderPolicyController(p.client)
	p.rspbController = controllers.NewResponderGlobalResponderPolicyBindingController(p.client)

	if p.timestamp == "" {
		p.timestamp = time.Now().Format("20060102150405")
	}
	p.rspbBindType = "REQ_OVERRIDE"
	p.rsaPrefix = "RSA_" + prefix + "_"
	p.rspPrefix = "RSP_" + prefix + "_"
}
