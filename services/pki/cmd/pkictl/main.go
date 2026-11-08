// Command pkictl performs the IronMesh PKI ceremonies and operator tasks:
//
//	init-root          offline root ceremony (optionally Shamir quorum over the root KEK)
//	recover-root       rebuild the root KEK from shares and re-wrap the root key
//	init-intermediate  create the Factory, Device or Services CA
//	init-bundle-key    create the Ed25519 trust-bundle signing key
//	issue-bootstrap    factory flow: bootstrap cert (+ key, or sign a secure-element CSR)
//	issue-server       90-day server certificate from the Services CA
//	revoke             revoke a serial through the management API
//	crl                download and print the Device CA CRL
//	ocsp-check         query the OCSP responder for a certificate
//
// Run `pkictl <command> -h` for flags. Secrets (PKI_FILE_KMS_PASSPHRASE,
// PKI_PKCS11_PIN) are read from the environment, never from flags.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ceremony"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/awskms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/file"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/pkcs11"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

const usage = `usage: pkictl <command> [flags]

commands:
  init-root          offline root ceremony (P-384); --quorum-shares/--quorum-threshold split the root KEK
  recover-root       reconstruct the root KEK from shares and re-wrap the root key under a passphrase
  init-intermediate  create the factory|device|services CA signed by the root
  init-bundle-key    create the Ed25519 bundle signing key
  issue-bootstrap    issue a 10-year bootstrap certificate (software key or --csr for secure elements)
  issue-server       issue a 90-day server certificate from the Services CA
  revoke             revoke a certificate via the management API
  crl                download and print the Device CA CRL
  ocsp-check         query the OCSP responder for a certificate
`

type env struct {
	getenv func(string) string
	stdout io.Writer
	stderr io.Writer
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	e := &env{getenv: getenv, stdout: stdout, stderr: stderr}
	cmds := map[string]func(context.Context, *env, []string) error{
		"init-root":         cmdInitRoot,
		"recover-root":      cmdRecoverRoot,
		"init-intermediate": cmdInitIntermediate,
		"init-bundle-key":   cmdInitBundleKey,
		"issue-bootstrap":   cmdIssueBootstrap,
		"issue-server":      cmdIssueServer,
		"revoke":            cmdRevoke,
		"crl":               cmdCRL,
		"ocsp-check":        cmdOCSPCheck,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err := cmd(ctx, e, args[1:]); err != nil {
		var ue usageError
		if errors.Is(err, flag.ErrHelp) || errors.As(err, &ue) {
			return 2
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// usageError marks flag parsing failures so run exits with status 2.
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err: err}
	}
	return nil
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// kdfFor lets tests speed up Argon2id via PKI_FILE_KMS_FAST_KDF=1.
func kdfFor(e *env) file.KDFParams {
	if e.getenv("PKI_FILE_KMS_FAST_KDF") == "1" {
		return file.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	}
	return file.DefaultKDFParams
}

func (e *env) provider(ctx context.Context, backend string) (kms.Provider, error) {
	switch strings.ToLower(backend) {
	case "file":
		pass := e.getenv("PKI_FILE_KMS_PASSPHRASE")
		if pass == "" {
			return nil, errors.New("PKI_FILE_KMS_PASSPHRASE must be set for the file backend")
		}
		return &file.Provider{Passphrase: []byte(pass), KDF: kdfFor(e)}, nil
	case "awskms":
		return awskms.NewProvider(ctx)
	case "softhsm", "pkcs11":
		return pkcs11.New(pkcs11.Config{
			ModulePath: firstNonEmpty(e.getenv("PKI_PKCS11_MODULE"), "/usr/lib/softhsm/libsofthsm2.so"),
			TokenLabel: firstNonEmpty(e.getenv("PKI_PKCS11_TOKEN"), "ironmesh"),
			PIN:        e.getenv("PKI_PKCS11_PIN"),
		})
	}
	return nil, fmt.Errorf("unknown KMS backend %q (file, awskms, softhsm)", backend)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func cmdInitRoot(ctx context.Context, e *env, args []string) error {
	fs := newFlags("init-root", e.stderr)
	dir := fs.String("dir", "./pki-data", "CA directory")
	backend := fs.String("kms", "file", "KMS backend: file|awskms|softhsm")
	keyRef := fs.String("key-ref", "", "key reference (file path, KMS alias, PKCS#11 label)")
	shares := fs.Int("quorum-shares", 0, "split the root KEK into N Shamir shares (file backend)")
	threshold := fs.Int("quorum-threshold", 0, "shares required to reconstruct the KEK")
	if err := parse(fs, args); err != nil {
		return err
	}
	opts := ceremony.RootOptions{Dir: *dir, KeyRef: *keyRef, QuorumShares: *shares, QuorumThreshold: *threshold, FileKDF: kdfFor(e)}
	if *shares == 0 && *threshold == 0 {
		prov, err := e.provider(ctx, *backend)
		if err != nil {
			return err
		}
		opts.Provider = prov
	} else if strings.ToLower(*backend) != "file" {
		return errors.New("--quorum-* applies to the file backend only; HSM/KMS backends enforce quorum through their own key policies")
	}
	res, err := ceremony.InitRoot(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "root certificate: %s\nkey: %s (%s)\nserial: %s\nnot after: %s\n",
		res.CertPath, res.KeyRef, res.KeyID, ca.FormatSerial(res.Certificate.SerialNumber), res.Certificate.NotAfter.Format(time.RFC3339))
	for _, p := range res.SharePaths {
		fmt.Fprintf(e.stdout, "share: %s\n", p)
	}
	if len(res.SharePaths) > 0 {
		fmt.Fprintln(e.stdout, "Distribute each share to a different custodian and delete them from this machine.")
	}
	return nil
}

func cmdRecoverRoot(ctx context.Context, e *env, args []string) error {
	fs := newFlags("recover-root", e.stderr)
	dir := fs.String("dir", "./pki-data", "CA directory")
	keyPath := fs.String("key", "", "root key file (default <dir>/root-ca.key.json)")
	shares := fs.String("shares", "", "comma-separated share files")
	out := fs.String("out", "", "write the recovered key re-wrapped under PKI_FILE_KMS_PASSPHRASE to this path")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *keyPath == "" {
		*keyPath = ca.Layout{Dir: *dir}.KeyPath(ca.KindRoot)
	}
	var paths []string
	for _, p := range strings.Split(*shares, ",") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	signer, err := ceremony.RecoverRoot(ctx, *keyPath, paths, []byte(e.getenv("PKI_FILE_KMS_PASSPHRASE")), *out, kdfFor(e))
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "root key recovered: %s\n", signer.KeyID())
	if *out != "" {
		fmt.Fprintf(e.stdout, "re-wrapped key written to %s\n", *out)
	}
	return nil
}

func cmdInitIntermediate(ctx context.Context, e *env, args []string) error {
	fs := newFlags("init-intermediate", e.stderr)
	dir := fs.String("dir", "./pki-data", "CA directory")
	kindFlag := fs.String("kind", "", "factory|device|services")
	backend := fs.String("kms", "file", "KMS backend for the new CA key")
	keyRef := fs.String("key-ref", "", "key reference for the new CA key")
	rootBackend := fs.String("root-kms", "file", "KMS backend holding the root key")
	rootKey := fs.String("root-key", "", "root key reference (default <dir>/root-ca.key.json)")
	if err := parse(fs, args); err != nil {
		return err
	}
	kind, err := ca.ParseKind(*kindFlag)
	if err != nil {
		return err
	}
	rootProv, err := e.provider(ctx, *rootBackend)
	if err != nil {
		return err
	}
	if *rootKey == "" {
		*rootKey = ca.Layout{Dir: *dir}.KeyPath(ca.KindRoot)
	}
	rootSigner, err := rootProv.Open(ctx, *rootKey)
	if err != nil {
		return fmt.Errorf("open root key: %w", err)
	}
	prov, err := e.provider(ctx, *backend)
	if err != nil {
		return err
	}
	cert, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: *dir, Kind: kind, RootSigner: rootSigner, Provider: prov, KeyRef: *keyRef})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "%s CA certificate: %s\nserial: %s\nnot after: %s\n", kind, ca.Layout{Dir: *dir}.CertPath(kind), ca.FormatSerial(cert.SerialNumber), cert.NotAfter.Format(time.RFC3339))
	return nil
}

func cmdInitBundleKey(ctx context.Context, e *env, args []string) error {
	fs := newFlags("init-bundle-key", e.stderr)
	dir := fs.String("dir", "./pki-data", "CA directory")
	if err := parse(fs, args); err != nil {
		return err
	}
	pass := e.getenv("PKI_FILE_KMS_PASSPHRASE")
	if pass == "" {
		return errors.New("PKI_FILE_KMS_PASSPHRASE must be set")
	}
	pub, err := ceremony.InitBundleKey(ctx, *dir, []byte(pass), kdfFor(e))
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "bundle key: %s\npublic key (hex, bake into firmware): %x\n", ca.Layout{Dir: *dir}.BundleKeyPath(), []byte(pub))
	return nil
}

func cmdIssueBootstrap(ctx context.Context, e *env, args []string) error {
	fs := newFlags("issue-bootstrap", e.stderr)
	dir := fs.String("dir", "./pki-data", "CA directory")
	backend := fs.String("kms", "file", "KMS backend holding the Factory CA key")
	keyRef := fs.String("key-ref", "", "Factory CA key reference (default <dir>/factory-ca.key.json)")
	tenant := fs.String("tenant", "", "tenant id (UUIDv4)")
	device := fs.String("device", "", "device id (dev-<16 hex>)")
	csrPath := fs.String("csr", "", "CSR file from a secure element (PEM or DER); omit to generate a software key")
	out := fs.String("out", "", "output directory (default <dir>/devices)")
	baseURL := fs.String("public-url", "https://pki.ironmesh.local", "public PKI base URL for CRL/OCSP pointers")
	if err := parse(fs, args); err != nil {
		return err
	}
	prov, err := e.provider(ctx, *backend)
	if err != nil {
		return err
	}
	if *keyRef == "" {
		*keyRef = ca.Layout{Dir: *dir}.KeyPath(ca.KindFactory)
	}
	signer, err := prov.Open(ctx, *keyRef)
	if err != nil {
		return fmt.Errorf("open factory key: %w", err)
	}
	opts := ceremony.BootstrapOptions{
		Dir: *dir, FactorySigner: signer, TenantID: *tenant, DeviceID: *device, OutDir: *out,
		CRLDistributionPoint: strings.TrimRight(*baseURL, "/") + "/crl/device-ca.crl",
		OCSPServer:           strings.TrimRight(*baseURL, "/") + "/ocsp",
	}
	if *csrPath != "" {
		if opts.CSR, err = os.ReadFile(*csrPath); err != nil {
			return err
		}
	}
	res, err := ceremony.IssueBootstrap(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "bootstrap certificate: %s\nserial: %s\nnot after: %s\nrecord: %s\n", res.CertPath, res.Record.Serial, res.Certificate.NotAfter.Format(time.RFC3339), res.RecordPath)
	if res.KeyPath != "" {
		fmt.Fprintf(e.stdout, "private key (software device, assurance=software): %s\n", res.KeyPath)
	}
	return nil
}

func cmdIssueServer(ctx context.Context, e *env, args []string) error {
	fs := newFlags("issue-server", e.stderr)
	dir := fs.String("dir", "./pki-data", "CA directory")
	backend := fs.String("kms", "file", "KMS backend holding the Services CA key")
	keyRef := fs.String("key-ref", "", "Services CA key reference (default <dir>/services-ca.key.json)")
	cn := fs.String("cn", "", "common name (e.g. svc-registry, pki)")
	san := fs.String("san", "", "comma-separated DNS names / IPs")
	out := fs.String("out", "", "output directory (default <dir>/services)")
	if err := parse(fs, args); err != nil {
		return err
	}
	prov, err := e.provider(ctx, *backend)
	if err != nil {
		return err
	}
	if *keyRef == "" {
		*keyRef = ca.Layout{Dir: *dir}.KeyPath(ca.KindServices)
	}
	signer, err := prov.Open(ctx, *keyRef)
	if err != nil {
		return fmt.Errorf("open services key: %w", err)
	}
	var sans []string
	for _, s := range strings.Split(*san, ",") {
		if s = strings.TrimSpace(s); s != "" {
			sans = append(sans, s)
		}
	}
	res, err := ceremony.IssueServer(ctx, ceremony.ServerOptions{Dir: *dir, ServicesSigner: signer, CN: *cn, SANs: sans, OutDir: *out})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "server certificate: %s\nprivate key: %s\nserial: %s\nnot after: %s\n", res.CertPath, res.KeyPath, ca.FormatSerial(res.Certificate.SerialNumber), res.Certificate.NotAfter.Format(time.RFC3339))
	return nil
}

func clientFlags(fs *flag.FlagSet) *ceremony.ClientOptions {
	opts := &ceremony.ClientOptions{}
	fs.StringVar(&opts.CAFile, "ca", "", "PEM bundle to verify the PKI server (chain.pem)")
	fs.StringVar(&opts.CertFile, "cert", "", "client certificate (Services CA) for mTLS")
	fs.StringVar(&opts.KeyFile, "key", "", "client private key")
	fs.StringVar(&opts.Token, "token", "", "bearer JWT (ES256, aud=pki) instead of a client certificate")
	fs.BoolVar(&opts.Insecure, "insecure", false, "skip server certificate verification (development only)")
	return opts
}

func cmdRevoke(ctx context.Context, e *env, args []string) error {
	fs := newFlags("revoke", e.stderr)
	url := fs.String("url", "https://localhost:8443", "management API base URL")
	serial := fs.String("serial", "", "certificate serial (hex)")
	reason := fs.String("reason", "unspecified", "RFC 5280 reason: "+strings.Join(ca.ReasonNames(), ", "))
	copts := clientFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if *serial == "" {
		return errors.New("--serial is required")
	}
	client, err := ceremony.NewHTTPClient(*copts)
	if err != nil {
		return err
	}
	res, err := ceremony.Revoke(ctx, client, *url, copts.Token, *serial, *reason)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "revoked serial %v (reason %v) at %v; published=%v\n", res["serial"], res["reason"], res["revoked_at"], res["published"])
	return nil
}

func cmdCRL(ctx context.Context, e *env, args []string) error {
	fs := newFlags("crl", e.stderr)
	url := fs.String("url", "http://localhost:8444/crl/device-ca.crl", "CRL URL")
	copts := clientFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	client, err := ceremony.NewHTTPClient(*copts)
	if err != nil {
		return err
	}
	crl, err := ceremony.FetchCRL(ctx, client, *url)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "issuer: %s\nnumber: %s\nthis update: %s\nnext update: %s\nentries: %d\n",
		crl.Issuer.CommonName, crl.Number, crl.ThisUpdate.Format(time.RFC3339), crl.NextUpdate.Format(time.RFC3339), len(crl.RevokedCertificateEntries))
	for _, en := range crl.RevokedCertificateEntries {
		fmt.Fprintf(e.stdout, "  %s  %s  %s\n", ca.FormatSerial(en.SerialNumber), en.RevocationTime.Format(time.RFC3339), ca.ReasonString(en.ReasonCode))
	}
	return nil
}

func cmdOCSPCheck(ctx context.Context, e *env, args []string) error {
	fs := newFlags("ocsp-check", e.stderr)
	url := fs.String("url", "https://localhost:8443/ocsp", "OCSP responder URL")
	certPath := fs.String("cert-file", "", "certificate to check (PEM)")
	issuerPath := fs.String("issuer", "", "issuer certificate (PEM, default <dir>/device-ca.crt)")
	dir := fs.String("dir", "./pki-data", "CA directory")
	copts := clientFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if *certPath == "" {
		return errors.New("--cert-file is required")
	}
	cert, err := ca.LoadCertPEM(*certPath)
	if err != nil {
		return err
	}
	if *issuerPath == "" {
		*issuerPath = ca.Layout{Dir: *dir}.CertPath(ca.KindDevice)
	}
	issuer, err := ca.LoadCertPEM(*issuerPath)
	if err != nil {
		return err
	}
	client, err := ceremony.NewHTTPClient(*copts)
	if err != nil {
		return err
	}
	res, err := ceremony.OCSPCheck(ctx, client, *url, cert, issuer)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "status: %s\nresponder: %s\nproduced at: %s\nnext update: %s\nnonce echoed: %v\n",
		res.Status, res.Responder, res.ProducedAt.Format(time.RFC3339), res.NextUpdate.Format(time.RFC3339), res.NonceEchoed)
	if res.Status == "revoked" {
		fmt.Fprintf(e.stdout, "revoked at: %s\nreason: %s\n", res.RevokedAt.Format(time.RFC3339), res.Reason)
	}
	return nil
}
