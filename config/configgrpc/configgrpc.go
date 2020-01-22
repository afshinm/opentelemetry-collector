// Copyright 2019, OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package configgrpc defines the gRPC configuration settings.
package configgrpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// GRPCSettings defines common settings for a gRPC configuration.
type GRPCSettings struct {
	// The headers associated with gRPC requests.
	Headers map[string]string `mapstructure:"headers"`

	// The target to which the exporter is going to send traces or metrics,
	// using the gRPC protocol. The valid syntax is described at
	// https://github.com/grpc/grpc/blob/master/doc/naming.md.
	Endpoint string `mapstructure:"endpoint"`

	// The compression key for supported compression types within
	// collector. Currently the only supported mode is `gzip`.
	Compression string `mapstructure:"compression"`

	// Certificate file for TLS credentials of gRPC client. Should
	// only be used if `secure` is set to true.
	CertPemFile string `mapstructure:"cert_pem_file"`

	// Whether to enable client transport security for the exporter's gRPC
	// connection. See https://godoc.org/google.golang.org/grpc#WithInsecure.
	UseSecure bool `mapstructure:"secure"`

	// Authority to check against when doing TLS verification
	ServerNameOverride string `mapstructure:"server_name_override"`

	// The keepalive parameters for client gRPC. See grpc.WithKeepaliveParams
	// (https://godoc.org/google.golang.org/grpc#WithKeepaliveParams).
	KeepaliveParameters *KeepaliveConfig `mapstructure:"keepalive"`

	// File to use for storing TLS master secrets is NNS key log format to
	// allow external programs such as Wireshark to decrypt TLS connections.
	KeyLogFile string `mapstructure:"key_log_file"`
}

// KeepaliveConfig exposes the keepalive.ClientParameters to be used by the exporter.
// Refer to the original data-structure for the meaning of each parameter.
type KeepaliveConfig struct {
	Time                time.Duration `mapstructure:"time,omitempty"`
	Timeout             time.Duration `mapstructure:"timeout,omitempty"`
	PermitWithoutStream bool          `mapstructure:"permit_without_stream,omitempty"`
}

// GrpcSettingsToDialOptions maps configgrpc.GRPCSettings to a slice of dial options for gRPC
func GrpcSettingsToDialOptions(settings GRPCSettings) ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{}
	if settings.CertPemFile != "" {
		creds, err := NewClientTLSFromFile(settings.CertPemFile, settings.ServerNameOverride, settings.KeyLogFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else if settings.UseSecure {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		creds, err := NewClientTLSFromCert(certPool, settings.ServerNameOverride, settings.KeyLogFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	if settings.KeepaliveParameters != nil {
		keepAliveOption := grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                settings.KeepaliveParameters.Time,
			Timeout:             settings.KeepaliveParameters.Timeout,
			PermitWithoutStream: settings.KeepaliveParameters.PermitWithoutStream,
		})
		opts = append(opts, keepAliveOption)
	}

	return opts, nil
}

func NewClientTLSFromFile(certFile, serverNameOverride, keyLogFile string) (credentials.TransportCredentials, error) {
	b, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("credentials: failed to append certificates")
	}
	kl, err := NewKeyLogWriter(keyLogFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{ServerName: serverNameOverride, RootCAs: cp, KeyLogWriter: kl}), nil
}

func NewClientTLSFromCert(cp *x509.CertPool, serverNameOverride, keyLogFile string) (credentials.TransportCredentials, error) {
	kl, err := NewKeyLogWriter(keyLogFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{ServerName: serverNameOverride, RootCAs: cp, KeyLogWriter: kl}), nil
}

func NewKeyLogWriter(keyLogFile string) (kl *os.File, err error) {
	if keyLogFile != "" {
		kl, err = os.OpenFile(keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
	}
	return
}
