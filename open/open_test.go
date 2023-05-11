package open

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_UnmarshalCborCdiCert(t *testing.T) {
	data, err := os.ReadFile("test/_CBOR_Ed25519_cert_full_cert_chain_0.cert")
	require.Nil(t, err)

	var cert CborCdiCert
	err = cert.UnmarshalCBOR(data)
	assert.Nil(t, err)
}

func Test_UnmarshalX509CdiCert(t *testing.T) {
	type DeltaFunc func(cert *x509.Certificate)

	type TestVector struct {
		Name          string
		Delta         DeltaFunc
		ExpectedError string
	}
	tvs := []TestVector{
		{
			Name: "ok",
			Delta: func(cert *x509.Certificate) {
				// No-op: use the template as is
			},
			ExpectedError: "",
		},
		{
			Name: "no CDI ext",
			Delta: func(cert *x509.Certificate) {
				cert.ExtraExtensions = []pkix.Extension{}
			},
			ExpectedError: "x509 cert does not contain CDI custom extension",
		},
		{
			Name: "KeyUsage Extra",
			Delta: func(cert *x509.Certificate) {
				cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			},
			ExpectedError: "unexpected KeyUsage: 96",
		},
		{
			Name: "KeyUsage None",
			Delta: func(cert *x509.Certificate) {
				cert.KeyUsage = 0
			},
			ExpectedError: "unexpected KeyUsage: 0",
		},
		{
			Name: "Subject mismatch",
			Delta: func(cert *x509.Certificate) {
				cert.SerialNumber = big.NewInt(0xdeadbeef)
			},
			ExpectedError: "SerialNumber(00000000000000000000000000000000deadbeef), Subject SERIALNUMBER(229795c1584dfea60b82d349970647263f884ffc), and subjectKeyIdentifer(229795c1584dfea60b82d349970647263f884ffc) do not match",
		},
		{
			Name: "SubjectKeyId mismatch",
			Delta: func(cert *x509.Certificate) {
				cert.SubjectKeyId = []byte{0xde, 0xad, 0xbe, 0xef}
			},
			ExpectedError: "SerialNumber(229795c1584dfea60b82d349970647263f884ffc), Subject SERIALNUMBER(229795c1584dfea60b82d349970647263f884ffc), and subjectKeyIdentifer(00000000000000000000000000000000deadbeef) do not match",
		},
		{
			Name: "AuthorityKeyId mismatch",
			Delta: func(cert *x509.Certificate) {
				cert.AuthorityKeyId = []byte{0xde, 0xad, 0xbe, 0xef}
			},
			ExpectedError: "Issuer SERIALNUMBER(7a06eee41b789f4863d86b8778b1a201a6fedd56), and authorityKeyIdentifer(00000000000000000000000000000000deadbeef) do not match",
		},
		{
			Name: "IsCA false",
			Delta: func(cert *x509.Certificate) {
				cert.IsCA = false
			},
			ExpectedError: "cA basic contraint is not set to TRUE",
		},
		{
			Name: "MaxPathLen > 0",
			Delta: func(cert *x509.Certificate) {
				cert.MaxPathLen = 42
			},
			ExpectedError: "pathLenConstraint is greater than zero",
		},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	udsRaw, err := os.ReadFile("test/_X509_Ed25519_uds_cert.cert")
	require.Nil(t, err)
	udsCert, err := x509.ParseCertificate(udsRaw)
	require.Nil(t, err)

	templateRaw, err := os.ReadFile("test/_X509_Ed25519_cert_full_cert_chain_0.cert")
	require.Nil(t, err)
	templateCert, err := x509.ParseCertificate(templateRaw)
	require.Nil(t, err)

	udsCert.PublicKey = pub
	// If the parent SubjectKeyId is set, x509.CreateCertificate() will
	// ignore the AuthorityKeyId in the template and use it instead.
	udsCert.SubjectKeyId = nil

	applyDelta := func(delta DeltaFunc) []byte {
		cert := *templateCert
		cert.ExtraExtensions = []pkix.Extension{cert.Extensions[4]} // custom CDI ext
		delta(&cert)

		bytes, err := x509.CreateCertificate(rand.Reader, &cert, udsCert, pub, priv) // nolint:govet
		require.NoError(t, err)

		return bytes
	}

	for _, tv := range tvs {
		t.Run(tv.Name, func(t *testing.T) {
			data := applyDelta(tv.Delta)

			var cert X509CdiCert
			err = cert.Unmarshal(data)
			if tv.ExpectedError == "" {
				assert.Nil(t, err)
			} else {
				assert.EqualError(t, err, tv.ExpectedError)
			}
		})
	}
}

func Test_X509CdiCert_getters(t *testing.T) {
	data, err := os.ReadFile("test/_X509_Ed25519_cert_full_cert_chain_0.cert")
	require.Nil(t, err)

	x509Cert, err := x509.ParseCertificate(data)
	require.Nil(t, err)

	var cert X509CdiCert
	err = cert.PopulateFromX509Cert(x509Cert)
	require.Nil(t, err)

	assert.Equal(t, x509Cert.SubjectKeyId, cert.GetCdiID())
	assert.Equal(t, x509Cert.AuthorityKeyId, cert.GetUdsID())
}

func Test_Config(t *testing.T) {
	tvs := []struct {
		Name          string
		Value         []byte
		Test          func(config *Config)
		ExpectedError string
	}{
		{
			Name: "ok",
			Value: []byte{
				0x96,       // verified boot
				0x06,       // debug ports
				0x10,       // boot source
				0x00, 0x01, // version

				// reserved
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00,

				// implementation specific
				0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef,
			},
			Test: func(config *Config) {
				assert.True(t, config.VerifiedBootEnabled)
				assert.EqualValues(t,
					[]int{3, 5, 6},
					config.EnabledVerifiedBootAuthorities,
				)
				assert.EqualValues(t, config.BootSource, 16)
				assert.EqualValues(t, config.Version, 1)
				assert.EqualValues(t,
					[]byte{0xde, 0xad},
					config.ImplementationSpecific[:2],
				)
				assert.EqualValues(t,
					[]byte{0xbe, 0xef},
					config.ImplementationSpecific[30:],
				)
			},
			ExpectedError: "",
		},
		{
			Name:          "too short",
			Value:         []byte{0xde, 0xad, 0xbe, 0xef},
			Test:          nil,
			ExpectedError: "configurationDescriptor must be exactly 64 bytes (found 4)",
		},
		{
			Name:          "too long",
			Value:         bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 20),
			Test:          nil,
			ExpectedError: "configurationDescriptor must be exactly 64 bytes (found 80)",
		},
		{
			Name:          "verified boot disabled",
			Value:         append([]byte{0x16}, bytes.Repeat([]byte{0x00}, 63)...),
			Test:          nil,
			ExpectedError: "VerifiedBootEnabled bit is unset, expecting the remaining verified boot bits to be unset (found 0x16)",
		},
	}

	for _, tv := range tvs {
		t.Run(tv.Name, func(t *testing.T) {
			entry := Entry{ConfigurationDescriptor: tv.Value}
			config, err := entry.GetConfigDetails()

			if tv.ExpectedError == "" {
				tv.Test(config)
			} else {
				assert.EqualError(t, err, tv.ExpectedError)
			}

		})
	}
}

func Test_ExtractChainFromX509(t *testing.T) {
	rawRoot, err := os.ReadFile("test/_X509_Ed25519_uds_cert.cert")
	require.Nil(t, err)
	root, err := x509.ParseCertificate(rawRoot)
	require.Nil(t, err)

	var chain []byte
	for i := 0; i < 7; i++ {
		path := fmt.Sprintf("test/_X509_Ed25519_cert_full_cert_chain_%d.cert", i)
		rawCert, err := os.ReadFile(path) // nolint:govet
		require.NoError(t, err)

		chain = append(chain, rawCert...)
	}

	entries, err := ExtractChainFromX509(chain, []*x509.Certificate{root}, true)

	assert.NoError(t, err)
	assert.Len(t, entries, 7)
	assert.Equal(t, root.Subject.SerialNumber, fmt.Sprintf("%040x", entries[0].UdsID))

	_, err = ExtractChainFromX509(chain, nil, true)
	assert.EqualError(t, err, "unexpected roots type (<nil>); must be []byte or []*x509.Certificate")
	_, err = ExtractChainFromX509(chain, nil, false)
	assert.NoError(t, err)

	_, err = ExtractChainFromX509(nil, []*x509.Certificate{root}, true)
	assert.EqualError(t, err, "unexpected data type (<nil>); must be []byte or []*x509.Certificate")

	var emptyRoots []*x509.Certificate
	_, err = ExtractChainFromX509(chain, emptyRoots, true)
	assert.EqualError(t, err, "failed to verify cert: x509: certificate signed by unknown authority")
}

func Test_ExtractChainFromCbor(t *testing.T) {
	rawRoot, err := os.ReadFile("test/_CBOR_Ed25519_uds_cert.cert")
	require.Nil(t, err)
	var root CborUdsCert
	err = root.UnmarshalCBOR(rawRoot)
	require.Nil(t, err)

	var chain []byte
	for i := 0; i < 7; i++ {
		path := fmt.Sprintf("test/_CBOR_Ed25519_cert_full_cert_chain_%d.cert", i)
		rawCert, err := os.ReadFile(path) // nolint:govet
		require.NoError(t, err)

		chain = append(chain, rawCert...)
	}

	entries, err := ExtractChainFromCbor(chain, []*CborUdsCert{&root}, true)
	assert.NoError(t, err)
	assert.Len(t, entries, 7)
}

func Test__SignatureVerify(t *testing.T) {
	var cert0, cert1 CborCdiCert

	rawCert, err := os.ReadFile("test/_CBOR_Ed25519_cert_full_cert_chain_0.cert")
	require.NoError(t, err)

	err = cert0.UnmarshalCBOR(rawCert)
	require.NoError(t, err)

	rawCert, err = os.ReadFile("test/_CBOR_Ed25519_cert_full_cert_chain_1.cert")
	require.NoError(t, err)

	err = cert1.UnmarshalCBOR(rawCert)
	require.NoError(t, err)

	verifier, err := cert0.SubjectPublicKey.Verifier()
	require.NoError(t, err)

	err = cert1.Cose.Verify(nil, verifier)
	assert.NoError(t, err)
}
