// Package kafkatls resolves the transport every Go Kafka client uses.
//
// kafka-go defaults to a nil Transport and a nil Dialer, both of which mean
// plaintext. Neither the publisher nor the graph reader set one, so the
// ingest service — the front door for every normalized event — spoke
// cleartext to the broker, carrying raw event bodies, usernames, hostnames
// and command lines.
//
// This mirrors services/fusion/app/core/kafka_security.py. The two cannot be
// one file across languages, so the rules are restated rather than shared
// and scripts/check_kafka_transport.py checks both ends:
//
//   - production refuses cleartext, as a startup error rather than a warning;
//   - development defaults to plaintext, because the compose broker has no
//     certificate and demanding one would break `make up` on a machine with
//     nothing to fix;
//   - an unrecognised protocol is an error, never a fallback, because the
//     fallback is plaintext.
package kafkatls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

const (
	protocolVar = "KAFKA_SECURITY_PROTOCOL"
	caVar       = "KAFKA_SSL_CAFILE"
	certVar     = "KAFKA_SSL_CERTFILE"
	keyVar      = "KAFKA_SSL_KEYFILE"
	mechVar     = "KAFKA_SASL_MECHANISM"
	userVar     = "KAFKA_SASL_USERNAME"
	passVar     = "KAFKA_SASL_PASSWORD"
	envVar      = "ENVIRONMENT"
	overrideVar = "AISOC_ALLOW_CLEARTEXT_KAFKA"
)

var (
	validProtocols     = map[string]bool{"PLAINTEXT": true, "SSL": true, "SASL_PLAINTEXT": true, "SASL_SSL": true}
	cleartextProtocols = map[string]bool{"PLAINTEXT": true, "SASL_PLAINTEXT": true}
	protectedEnvs      = map[string]bool{"production": true, "prod": true, "staging": true}
	truthy             = map[string]bool{"1": true, "true": true, "yes": true, "on": true}
)

// Transport carries the resolved settings for both client shapes.
type Transport struct {
	Protocol  string
	TLS       *tls.Config
	SASL      sasl.Mechanism
	Cleartext bool
}

func env(name string) string { return strings.TrimSpace(os.Getenv(name)) }

// Resolve reads the environment and returns the transport, or an error if it
// is wrong for this environment.
func Resolve() (*Transport, error) {
	environment := strings.ToLower(env(envVar))
	protocol := strings.ToUpper(env(protocolVar))
	if protocol == "" {
		protocol = "PLAINTEXT"
	}
	if !validProtocols[protocol] {
		return nil, fmt.Errorf("%s=%q is not a recognised protocol; refusing rather than "+
			"falling back, because the fallback is plaintext", protocolVar, protocol)
	}

	cleartext := cleartextProtocols[protocol]
	if cleartext && protectedEnvs[environment] && !truthy[strings.ToLower(env(overrideVar))] {
		return nil, fmt.Errorf("%s=%q with %s=%q would put normalized security telemetry on "+
			"the wire in the clear. Set %s=SSL or SASL_SSL, or set %s=1 if the broker is "+
			"reachable only over a network you already encrypt",
			envVar, environment, protocolVar, protocol, protocolVar, overrideVar)
	}

	transport := &Transport{Protocol: protocol, Cleartext: cleartext}

	if protocol == "SSL" || protocol == "SASL_SSL" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if path := env(caVar); path != "" {
			pem, err := os.ReadFile(path) // #nosec G304 - operator-supplied CA bundle path
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", caVar, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("%s=%q contains no usable certificate", caVar, path)
			}
			cfg.RootCAs = pool
		}
		if certPath := env(certVar); certPath != "" {
			pair, err := tls.LoadX509KeyPair(certPath, env(keyVar))
			if err != nil {
				return nil, fmt.Errorf("loading the client certificate: %w", err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		transport.TLS = cfg
	}

	if strings.HasPrefix(protocol, "SASL_") {
		mechanism, err := saslMechanism()
		if err != nil {
			return nil, err
		}
		transport.SASL = mechanism
	}
	return transport, nil
}

func saslMechanism() (sasl.Mechanism, error) {
	name := strings.ToUpper(env(mechVar))
	user, password := env(userVar), env(passVar)
	switch name {
	case "":
		return nil, fmt.Errorf("a SASL protocol requires %s (for example PLAIN or SCRAM-SHA-512)", mechVar)
	case "PLAIN":
		return plain.Mechanism{Username: user, Password: password}, nil
	case "SCRAM-SHA-256":
		return scram.Mechanism(scram.SHA256, user, password)
	case "SCRAM-SHA-512":
		return scram.Mechanism(scram.SHA512, user, password)
	default:
		return nil, fmt.Errorf("%s=%q is not supported", mechVar, name)
	}
}

// WriterTransport returns what kafka.Writer.Transport expects.
func (t *Transport) WriterTransport() *kafka.Transport {
	return &kafka.Transport{TLS: t.TLS, SASL: t.SASL, DialTimeout: 10 * time.Second}
}

// Dialer returns what kafka.ReaderConfig.Dialer expects.
func (t *Transport) Dialer() *kafka.Dialer {
	return &kafka.Dialer{Timeout: 10 * time.Second, DualStack: true, TLS: t.TLS, SASLMechanism: t.SASL}
}
