// Package tlscfg provides an option-driven way to easily setup a well
// configured *tls.Config.
//
// Initializing a *tls.Config is a rote task, and often good, secure defaults
// are not so obvious. This package aims to eliminate the chore of initializing
// a *tls.Config correctly and securely.
//
// New returns a valid config with system certificates and tls v1.2+ ciphers.
// The With functions can be used to further add certificates or override
// settings as appropriate.
//
// Usage:
//
//     cfg, err := tlscfg.New(
//             tlscfg.MaybeWithDiskCA( // optional CA
//                     *flagCA,
//                     tlscfg.ForClient,
//             ),
//             tlscfg.WithDiskKeyPair( // required client cert+key pair
//                     "cert.pem",
//                     "key.pem",
//             ),
//     )
//     if err != nil {
//             // handle
//     }
//
package tlscfg

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// Opt is a function to configure a *tls.Config.
type Opt interface {
	apply(FS, *tls.Config) error
}

type opt struct {
	fn func(FS, *tls.Config) error
}

func (o *opt) apply(fs FS, c *tls.Config) error { return o.fn(fs, c) }

// ForKind is used in some options to specify whether the option is meant to be
// applied for server configurations or client configurations.
type ForKind uint8

const (
	// ForServer specifies that an option should work on server portions
	// of a *tls.Config (adding a CA).
	ForServer ForKind = iota
	// ForClient specifies that an option should work on client portions
	// of a *tls.Config (adding a CA).
	ForClient
)

// CipherSuites returns this package's recommended ciphers that tls
// configurations should use.
//
// Currently, this returns tls ciphers that are only compatible with tls v1.2.
// Ciphers for tls v1.3 are not include because if a connection negotiates tls
// v1.3, Go internally uses v1.3 ciphers.
func CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// CurvePreferences returns this package's recommended curve preferences that
// tls configurations should use.
//
// Currently, this returns only x25519. This may cause problems with old
// versions of openssl, if so, be sure to add P256.
func CurvePreferences() []tls.CurveID {
	return []tls.CurveID{tls.X25519}
}

// MaybeWithDiskKeyPair optionally loads a PEM encoded cert and key from
// certPath and keyPath and adds the pair to the *tls.Config's Certificates.
//
// If both certPath and keyPath are empty, this option does nothing. This
// option is useful if accepting flags to optionally setup a cert.
func MaybeWithDiskKeyPair(certPath, keyPath string) Opt {
	return &opt{func(fs FS, cfg *tls.Config) error {
		if certPath == "" && keyPath == "" {
			return nil
		}
		return WithDiskKeyPair(certPath, keyPath).apply(fs, cfg)
	}}
}

// WithDiskKeyPair loads a PEM encoded cert and key from certPath and keyPath
// and adds the pair to the *tls.Config's Certificates.
func WithDiskKeyPair(certPath, keyPath string) Opt {
	return &opt{func(fs FS, cfg *tls.Config) error {
		if certPath == "" || keyPath == "" {
			return errors.New("both cert and key paths must be specified")
		}
		cert, err := fs.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("unable to read cert at %q: %w", certPath, err)
		}
		pem, err := fs.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("unable to read key at %q: %w", keyPath, err)
		}
		return WithKeyPair(cert, pem).apply(fs, cfg)
	}}
}

// WithKeyPair parses a PEM encoded cert and key and adds the pair to the
// *tls.Config's Certificates.
func WithKeyPair(cert, key []byte) Opt {
	return &opt{func(_ FS, cfg *tls.Config) error {
		cert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("unable to load keypair: %w", err)
		}
		cfg.Certificates = append(cfg.Certificates, cert)
		return nil
	}}
}

// MaybeWithDiskCA optionally loads a PEM encoded CA cert from disk and adds it
// to the proper CA pool based off of forKind.
//
// If the path is empty, this option does nothing. This option is useful if
// accepting flags to optionally setup a cert.
//
// NOTE: If this option loads a CA, then system certs are not used. If you wish
// to use system certs in addition to this CA, use the WithSystemCertPool option.
func MaybeWithDiskCA(path string, forKind ForKind) Opt {
	return &opt{func(fs FS, cfg *tls.Config) error {
		if path == "" {
			return nil
		}
		return WithDiskCA(path, forKind).apply(fs, cfg)
	}}
}

// WithDiskCA loads a PEM encoded CA cert from disk and adds it to the proper
// CA pool based off of forKind.
//
// If for servers, this option sets RequireAndVerifyClientCert.
//
// NOTE: This option ensures system certs are not used. If you wish to use
// system certs in addition to this CA, use the WithSystemCertPool option.
func WithDiskCA(path string, forKind ForKind) Opt {
	return &opt{func(fs FS, cfg *tls.Config) error {
		if path == "" {
			return errors.New("ca path must be specified")
		}
		ca, err := fs.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to read ca at %q: %w", path, err)
		}
		return WithCA(ca, forKind).apply(fs, cfg)
	}}
}

// WithCA parses a PEM encoded CA cert and adds it to the proper CA pool based
// off of forKind.
//
// If for servers, this option sets RequireAndVerifyClientCert.
//
// NOTE: This option ensures system certs are not used. If you wish to use
// system certs in addition to this CA, use the WithSystemCertPool option.
func WithCA(ca []byte, forKind ForKind) Opt {
	return &opt{func(_ FS, cfg *tls.Config) error {
		pool := &cfg.RootCAs
		if forKind == ForServer {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			pool = &cfg.ClientCAs
		}

		// If the special systemCASentinel is set, then system certs
		// were requested in addition to the custom CA. We initialize
		// the pool with system certs and add.
		switch *pool {
		case nil:
			*pool = x509.NewCertPool()

		case systemCASentinel:
			var err error
			if *pool, err = x509.SystemCertPool(); err != nil {
				return fmt.Errorf("unable to load system cert pool: %w", err)
			}
		}

		if ok := (*pool).AppendCertsFromPEM(ca); !ok {
			return errors.New("no cert could be found in the ca bytes")
		}
		return nil
	}}
}

var (
	systemCA         = &opt{func(FS, *tls.Config) error { return nil }}
	systemCASentinel = new(x509.CertPool)
)

// WithSystemCertPool ensures that the system cert pool is used in addition to
// any CA you manually set.
//
// This option is necessary if you want to talk to both servers that have
// public CA issued certs as well as servers that have your own manually issued
// certs, or, as a server, if you want to verify certs from clients with public
// CA issued certs as well as clients that use custom certs.
//
// This option is likely only to be used when migrating from mTLS custom certs
// to public CA certs.
//
// Only cert pools that have additional CAs to add are initialized. If no extra
// CAs are added, the pool is left nil, which by default uses system certs.
func WithSystemCertPool() Opt {
	return systemCA
}

// WithServerName sets the *tls.Config's ServerName, which is important for
// clients to verify servers. This option is required if all of the following
// are true:
//
//   - the config is not used in an http.Transport (http.Transport clones the
//     config and sets ServerName)
//   - you do not set InsecureSkipVerify to true
//   - you do not want to set ServerName on the config manually
//
func WithServerName(name string) Opt {
	return &opt{func(_ FS, cfg *tls.Config) error {
		cfg.ServerName = name
		return nil
	}}
}

// WithAdditionalCipherSuites adds additional cipher suites to the default set
// used by this package. This option is important if talking to legacy systems
// that do not support newer cipher suites.
func WithAdditionalCipherSuites(cipherSuites ...uint16) Opt {
	return &opt{func(_ FS, cfg *tls.Config) error {
		cfg.CipherSuites = append(cfg.CipherSuites, cipherSuites...)
		return nil
	}}
}

type override struct {
	fn func(*tls.Config) error
}

func (o *override) apply(_ FS, c *tls.Config) error { return o.fn(c) }

// WithOverride returns an option to override fields on a *tls.Config. All
// overrides are run last, in order.
func WithOverride(fn func(*tls.Config) error) Opt {
	return &override{fn}
}

type filesystem struct{ fs FS }

func (*filesystem) apply(FS, *tls.Config) error { panic("unused") }

// WithFS sets the filesystem used to read files, overriding the default of
// simply using the host OS.
func WithFS(fs FS) Opt {
	return &filesystem{fs}
}

// FS represents a filesystem.
//
// This is different from fs.FS, because fs.FS only reads unrooted paths.
type FS interface {
	// ReadFile opens the file at path and reads it.
	ReadFile(path string) ([]byte, error)
}

type hostFS struct{}

func (*hostFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

var osFS FS = new(hostFS)

// New creates and returns a *tls.Config with any options applied.
//
// This function will not error if no options are specified.
func New(opts ...Opt) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     CipherSuites(),
		CurvePreferences: CurvePreferences(),
	}

	var (
		fs    = osFS
		first []Opt
		last  []Opt
	)

	for _, o := range opts {
		switch t := o.(type) {
		case *filesystem:
			fs = t.fs

		case *opt:
			if t == systemCA {
				cfg.ClientCAs = systemCASentinel
				cfg.RootCAs = systemCASentinel
				continue
			}
			first = append(first, t)

		case *override:
			last = append(last, t)
		}
	}

	// Before we apply overrides, strip our sentinel pointer.
	first = append(first, &opt{func(_ FS, c *tls.Config) error {
		if c.ClientCAs == systemCASentinel {
			c.ClientCAs = nil
		}
		if c.RootCAs == systemCASentinel {
			c.RootCAs = nil
		}
		return nil
	}})

	for _, opt := range append(first, last...) {
		if err := opt.apply(fs, cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}
