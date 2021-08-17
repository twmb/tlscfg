tlscfg
=====

This repo provides an option-driven Go package that simplifies initializing a
well configured `*tls.Config`.

Initializing a `*tls.Config` is a rote task, and often good, secure defaults
are not so obvious. This package aims to eliminate the chore of initializing a
`*tls.Config` correctly and securely.

New returns a valid config with system certificates and tls v1.2+ ciphers. The
With functions can be used to further add certificates or override settings as
appropriate.

Usage:

```go
cfg, err := tlscfg.New(
        tlscfg.MaybeWithDiskCA( // optional CA
                *flagCA,
                tlscfg.ForClient,
        ),
        tlscfg.WithDiskKeyPair( // required client cert+key pair
                "cert.pem",
                "key.pem",
        ),
)
if err != nil {
        // handle
}
```
