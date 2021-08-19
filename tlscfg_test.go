package tlscfg

import (
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"testing"
)

// Our two test CAs were generated identically, but due to time their serial
// number is different. The subject is identical minus the trailing bytes (the
// serial). We encode the identical hex here, and then expect our suffixes to
// be different.
var (
	subjectBase = []byte{
		0x30, 0x65, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
		0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06,
		0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x43, 0x41, 0x31, 0x16,
		0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d, 0x53,
		0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73,
		0x63, 0x6f, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
		0x0a, 0x13, 0x03, 0x64, 0x65, 0x76, 0x31, 0x0f, 0x30, 0x0d,
		0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x06, 0x64, 0x65, 0x76,
		0x20, 0x43, 0x41, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
		0x04, 0x05, 0x13, 0x09,
	}
	subject1 = append(subjectBase, "196629234"...)
	subject2 = append(subjectBase, "885211544"...)
)

func TestMaybe(t *testing.T) {
	{
		cfg, err := New(
			MaybeWithDiskCA("", ForClient),
		)
		if err != nil {
			t.Errorf("unable to initialize cfg maybe with empty CA: %v", err)
		}
		if cfg.RootCAs != nil {
			t.Error("unexpectedly non-nil root CAs when no CA used")
		}

		cfg, err = New(
			MaybeWithDiskCA("testdata/ca1.pem", ForClient),
		)
		if err != nil {
			t.Errorf("unable to initialize cfg maybe with non-empty CA: %v", err)
		}
		if cfg.RootCAs == nil {
			t.Error("unexpectedly nil root CAs when CA used")
		}
	}

	{
		cfg, err := New(
			MaybeWithDiskKeyPair("", ""),
		)
		if err != nil {
			t.Errorf("unable to initialize cfg maybe with empty keypair: %v", err)
		}
		if cfg.Certificates != nil {
			t.Error("unexpectedly non-nil certificates when no keypair used")
		}

		cfg, err = New(
			MaybeWithDiskKeyPair(
				"testdata/client-cert.pem",
				"testdata/client-key.pem",
			),
		)
		if err != nil {
			t.Errorf("unable to initialize cfg maybe with non-empty keypair: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Errorf("unexpectedly %d certificates when expecting 1 when non-empty keypair", len(cfg.Certificates))
		}
	}
}

func TestSystemCertOnly(t *testing.T) {
	cfg, err := New(WithSystemCertPool())
	if err != nil {
		t.Fatalf("unable to initialize system-cert-pool-only config: %v", err)
	}

	if cfg.RootCAs != cfg.ClientCAs {
		t.Fatal("expected system-cert-pool-only server and client pools to be equal, they were not")
	}
	if cfg.RootCAs != nil {
		t.Fatal("system CA only config unexpectedly has non-nil RootCAs")
	}
}

func TestSystemCertWithOverrideAndCA(t *testing.T) {
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("unable to load system certs: %v", err)
	}

	cfg, err := New(
		WithOverride(func(cfg *tls.Config) error {
			cfg.ServerName = "foo"
			return nil
		}),
		WithDiskCA("testdata/ca1.pem", ForClient),
		WithSystemCertPool(),
	)
	if err != nil {
		t.Fatalf("unable to initialize system+1 config: %v", err)
	}

	if cfg.ClientCAs != nil {
		t.Errorf("system+1 ClientCAs is unexpectedly non-nil: %v", err)
	}

	sysSubj := sysPool.Subjects()
	sysPlusSubj := cfg.RootCAs.Subjects()
	l := len(cfg.RootCAs.Subjects())
	r := len(sysSubj)
	if l != r+1 {
		t.Fatalf("got %d CAs != expected %d system+1", l, r+1)
	}
	sysSubj = append(sysSubj, subject1)
	if !reflect.DeepEqual(sysSubj, sysPlusSubj) {
		t.Error("system+1 client-side subjects != system subjects with subject1")
	}

	if cfg.ServerName != "foo" {
		t.Errorf("got server name %s != expected foo", cfg.ServerName)
	}
}

// TestMultiRootCA ensures that appending multiple CAs works correctly, and
// validates a few other things about initializing the config.
func TestMultiRootCA(t *testing.T) {
	expSubjects := [][]byte{subject1, subject2}

	for _, test := range []struct {
		name    string
		forKind ForKind
	}{
		{"client", ForClient},
		{"server", ForServer},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := New(
				WithDiskCA("testdata/ca1.pem", test.forKind),
				WithDiskCA("testdata/ca2.pem", test.forKind),
				WithFS(osFS), // we can test our internal impl
			)
			if err != nil {
				t.Fatalf("unable to create cfg: %v", err)
			}

			var (
				setPool   *x509.CertPool
				unsetPool *x509.CertPool
				expAuth   tls.ClientAuthType
			)

			switch test.forKind {
			case ForClient:
				setPool = cfg.RootCAs
				unsetPool = cfg.ClientCAs
				expAuth = tls.NoClientCert

			case ForServer:
				setPool = cfg.ClientCAs
				unsetPool = cfg.RootCAs
				expAuth = tls.RequireAndVerifyClientCert
			}

			if cfg.ClientAuth != expAuth {
				t.Errorf("got client auth %d != exp %d", cfg.ClientAuth, expAuth)
			}
			if unsetPool != nil {
				t.Errorf("expected-unset pool is unexpectedly set")
			}
			if setPool == nil {
				t.Fatalf("expected-set pool is unexpectedly unset")
			}
			subjects := setPool.Subjects()

			if !reflect.DeepEqual(subjects, expSubjects) {
				t.Errorf("got subjects != exp subjects")
			}
		})
	}
}
