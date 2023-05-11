package open

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
	"golang.org/x/exp/slices"
)

// X509CdiExtOid encodes the Open-DICE custom x509 extension OID
var X509CdiExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 24}

// Mode represents the value of the Mode field inside the Open DICE
// custom extension. See:
// https://pigweed.googlesource.com/open-dice/+/refs/heads/master/docs/specification.md#Mode-Value-Details
type Mode uint8

const (
	// OdmNotConfigured indicates that at least one security mechanism has
	// not been configured. This mode also acts as a catch-all for
	// configurations which do not fit the other modes. Invalid mode values
	// -- values not defined here -- should be treated like this mode.
	OdmNotConfigured Mode = iota
	// OdmNormal indicates the device is operating normally under secure
	// configuration. This may mean, for example: Verified boot is enabled,
	// verified boot authorities used for development or debug have been
	// disabled, debug ports or other debug facilities have been disabled,
	// and the device booted software from the normal primary source, for
	// example, eMMC, not USB, network, or removable storage.
	OdmNormal
	// OdmDebug indicates at least one criteria for Normal mode is not met
	// and the device is not in a secure state.
	OdmDebug
	// OdmRecovery indicates a recovery or maintenance mode of some kind.
	// This may mean software is being loaded from an alternate source, or
	// the device is configured to trigger recovery logic instead of a
	// normal boot flow.
	OdmRecovery

	OdmInvalid // must be last
)

// IsValid returns a boolean indicating whether the the mode value is valid.
func (o Mode) IsValid() bool {
	return o < OdmInvalid
}

// Config represents the configurationDescriptor decoded according to
// the convention specified in the Open DICE profile. See:
// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#configuration-input-value-details-optional
type Config struct {
	// EnabledVerifiedBootAuthorities is indicates which verified boot
	// authorities have been enabled (empty if VerifiedBootEnabled is
	// false).
	EnabledVerifiedBootAuthorities []int
	// Version encodes target software version information.
	Version uint16
	// ImplementationSpecific may be used by an implementation for any
	// other security-relevant configuration.
	ImplementationSpecific [32]byte
	// VerifiedBootEnabled indicates whether a verified boot feature is enabled.
	VerifiedBootEnabled bool
	// DebugPortsEnabled is a bit map indicating which debug ports and
	// features have been enabled.
	DebugPortsEnabled byte
	// BootSource indicates where the target software was loaded from.
	BootSource byte
}

// Entry represents Open DICE-relevant claims extracted from a
// certificate (either CBOR or X.509).
type Entry struct {
	// UdsID is an identifier derived from the UDS (or, in case of multiple
	// layers, previous layer's CDI) public key.
	UdsID []byte `json:"UDS_ID"`

	// CdiID  is an identifier derived from the (this layer's) CDI public
	// key.
	CdiID []byte `json:"CDI_ID"`

	// Fields below correspond to the Open DICE custom extension entries
	// described here:
	// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#custom-extension-format

	// CodeHash is the exact 64-byte code input value used to compute CDI values.
	CodeHash []byte `json:"codeHash"`
	// CodeDescriptor contains additional information about CodeHash.
	CodeDescriptor []byte `json:"codeDescriptor,omitempty"`
	// ConfigurationHash is the exact 64-byte configuration input value
	// used to compute CDI values.
	ConfigurationHash []byte `json:"configurationHash,omitempty"`
	// ConfigurationDescriptor contains the original configuration data, if
	// ConfigurationHash is present. Otherwise, it contains the exact
	// 64-byte configuration input data used to compute CDI values.
	ConfigurationDescriptor []byte `json:"configurationDescriptor"`
	// AuthorityHash is the exact 64-byte authority input value used to
	// compute CDI values.
	AuthorityHash []byte `json:"authorityHash"`
	// AuthorityDescriptor contains additional information about the
	// authority input value.
	AuthorityDescriptor []byte `json:"authorityDescriptor,omitempty"`
	// Mode is the mode input value.
	Mode Mode `json:"mode"`
}

// GetConfigDetails parses the Entry's ConfigurationDescriptor into an
// Config entry.
func (o *Entry) GetConfigDetails() (*Config, error) {
	if len(o.ConfigurationDescriptor) != 64 {
		return nil, fmt.Errorf(
			"configurationDescriptor must be exactly 64 bytes (found %d)",
			len(o.ConfigurationDescriptor),
		)
	}

	var config Config

	config.VerifiedBootEnabled = (o.ConfigurationDescriptor[0] & 0x80) != 0
	// If the MSb of the verified boot byte is set, the remaining bits, in
	// big endian order, indicate the authorities that have been enabled
	// (i.e. LSb indicates whether the authority 7 has been enabled). See:
	// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#configuration-input-value-details-optional
	if config.VerifiedBootEnabled {
		for i := 1; i < 8; i++ {
			if (o.ConfigurationDescriptor[0] & (1 << (7 - i))) != 0 {
				config.EnabledVerifiedBootAuthorities =
					append(config.EnabledVerifiedBootAuthorities, i)
			}
		}
	} else if o.ConfigurationDescriptor[0] != 0x00 { // If a verified boot system is disabled or not supported, all bits are clear.
		return nil, fmt.Errorf(
			"VerifiedBootEnabled bit is unset, expecting the remaining verified boot bits to be unset (found 0x%x)", // nolint:golint
			o.ConfigurationDescriptor[0],
		)
	}

	config.DebugPortsEnabled = o.ConfigurationDescriptor[1]
	config.BootSource = o.ConfigurationDescriptor[2]
	config.Version = binary.BigEndian.Uint16(o.ConfigurationDescriptor[3:5])
	copy(config.ImplementationSpecific[:], o.ConfigurationDescriptor[32:])

	return &config, nil
}

// ExtractChainFromCbor extracts Open DICE claim entries from a
// concatenated chain of CBOR CDI certificates. If verify is true, the
// signatures on the certificates are verified, and chained back to the
// provided UDS certificate.
func ExtractChainFromCbor(
	data []byte,
	roots []*CborUdsCert,
	verify bool,
) ([]*Entry, error) {
	var certs []*CborCdiCert

	buf := bytes.NewBuffer(data)
	decoder := cbor.NewDecoder(buf)

	i := 0
	for decoder.NumBytesRead() < len(data) {
		var cert CborCdiCert
		if err := decoder.Decode(&cert); err != nil {
			return nil, fmt.Errorf("could not parse cert %d: %w", i, err)
		}

		certs = append(certs, &cert)
		i++
	}

	// nolint:prealloc
	var entries []*Entry

	for _, cert := range certs {
		entries = append(entries, cert.GetEntry())
	}

	if verify {
		// We're accepting a slice of roots to be consistent with the X509 interface,
		// however, for simplicity of the initial implementation, we're expecting to match
		// against a single trust anchor.
		if len(roots) != 1 {
			return nil, fmt.Errorf(
				"could not verify: exactly one root cert must be provided",
			)
		}

		issuer := roots[0].Subject
		verifier, err := roots[0].SubjectPublicKey.Verifier()
		if err != nil {
			return nil, fmt.Errorf("could get root cert key: %w", err)
		}

		for i, cert := range certs {
			if err = cert.Cose.Verify(nil, verifier); err != nil {
				return nil, fmt.Errorf("could not verify cert %d: %w", i, err)
			}

			if issuer != cert.Issuer {
				return nil, fmt.Errorf("issuer mismatch for cert %d", i)
			}

			issuer = cert.Subject
			verifier, err = cert.SubjectPublicKey.Verifier()
			if err != nil {
				return nil, fmt.Errorf("could get cert %d key: %w", i, err)
			}
		}
	}

	return entries, nil
}

// CborCdiCertClaims represents the claims extracted from a CBOR UDS certificate.
type CborUdsCertClaims struct {
	// Standard CWT fields. See:
	//	https://www.rfc-editor.org/rfc/rfc8392

	// Issuer identifies the principal that issued the certificate. The
	// value is implementation-dependant.
	Issuer string `cbor:"1,keyasint" json:"iss"`
	// Subject identifies the principal that is the subject of the
	// certificate. This must set to the UDS_ID.
	Subject string `cbor:"2,keyasint" json:"sub"`

	// RawSubjectPublicKey is the bstr-encoded COSE_Key containing UDS_Public
	RawSubjectPublicKey []byte `cbor:"-4670552,keyasint" json:"subjectPublicKey"`
	// KeyUsage bits are set according to X.509 key usage. See:
	// https://www.rfc-editor.org/rfc/rfc8392#section-3.1.2
	KeyUsage []byte `cbor:"-4670553,keyasint" json:"keyUsage"`
}

// CborUdsCert represents an Open DICE UDS certificate.
type CborUdsCert struct {
	CborUdsCertClaims

	// SubjectPublicKey is the decoded COSE_Key containing UDS_Public
	SubjectPublicKey *cose.Key
}

// UnmarshalCBOR decodes a CBOR UDS certificate.
func (o *CborUdsCert) UnmarshalCBOR(data []byte) error {
	var msg cose.UntaggedSign1Message

	if err := msg.UnmarshalCBOR(data); err != nil {
		return err
	}

	if err := cbor.Unmarshal(msg.Payload, &o.CborUdsCertClaims); err != nil {
		return err
	}

	if err := cbor.Unmarshal(o.RawSubjectPublicKey, &o.SubjectPublicKey); err != nil {
		return err
	}

	return nil
}

// CborCdiCertClaims represents the claims extracted from a CBOR CDI certificate.
type CborCdiCertClaims struct {
	// Standard CWT fields. See:
	//	https://www.rfc-editor.org/rfc/rfc8392
	Issuer         string `cbor:"1,keyasint" json:"iss"`
	Subject        string `cbor:"2,keyasint" json:"sub"`
	ExpirationTime int    `cbor:"4,keyasint,omitempty" json:"exp,omitempty"`
	NotBefore      int    `cbor:"5,keyasint,omitempty" json:"nbf,omitempty"`
	IssuedAt       int    `cbor:"6,keyasint,omitempty" json:"iat,omitempty"`

	// Additional, OpenDICE-defined fields. See:
	//	https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md#profile-design-certificate-details-cbor-cdi-certificates-additional-fields
	CodeHash                []byte  `cbor:"-4670545,keyasint" json:"codeHash"`
	CodeDescriptor          []byte  `cbor:"-4670546,keyasint,omitempty" json:"codeDescriptor,omitempty"`
	ConfigurationHash       []byte  `cbor:"-4670547,keyasint,omitempty" json:"configurationHash,omitempty"`
	ConfigurationDescriptor []byte  `cbor:"-4670548,keyasint,omitempty" json:"configurationDescriptor,omitempty"`
	AuthorityHash           []byte  `cbor:"-4670549,keyasint" json:"authorityHash"`
	AuthorityDescriptor     []byte  `cbor:"-4670550,keyasint,omitempty" json:"authorityDescriptor,omitempty"`
	Mode                    [1]byte `cbor:"-4670551,keyasint" json:"mode"`

	RawSubjectPublicKey []byte `cbor:"-4670552,keyasint" json:"subjectPublicKey"`
	KeyUsage            []byte `cbor:"-4670553,keyasint" json:"keyUsage"`
}

// CborCdiCert rersents a CBOR CDI certificate.
type CborCdiCert struct {
	CborCdiCertClaims
	// Raw bytes of the certificate
	Raw []byte
	// SubjectPublicKey is the cose.Key parsed from subjectPublicKey field.
	SubjectPublicKey *cose.Key
	// Cose is the parsed COSE_Sign1 structure form the certificate.
	Cose *cose.UntaggedSign1Message
}

// UnmarshalCBOR decodes an untagged COSE_Sign1 structure into an
// CborCdiCert.
func (o *CborCdiCert) UnmarshalCBOR(data []byte) error {
	var msg cose.UntaggedSign1Message

	if err := msg.UnmarshalCBOR(data); err != nil {
		return err
	}

	o.Raw = data
	o.Cose = &msg

	if err := cbor.Unmarshal(msg.Payload, &o.CborCdiCertClaims); err != nil {
		return err
	}

	if err := cbor.Unmarshal(o.RawSubjectPublicKey, &o.SubjectPublicKey); err != nil {
		return err
	}

	return nil
}

// GetEntry extracts an Entry from the cert.
func (o *CborCdiCert) GetEntry() *Entry {
	return &Entry{
		CodeHash:                o.CodeHash,
		CodeDescriptor:          o.CodeDescriptor,
		ConfigurationHash:       o.ConfigurationHash,
		ConfigurationDescriptor: o.ConfigurationDescriptor,
		AuthorityHash:           o.AuthorityHash,
		AuthorityDescriptor:     o.AuthorityDescriptor,
		Mode:                    Mode(o.Mode[0]),
	}
}

// ExtractChainFromX509 processes a chain of x509 certificates,
// extracting the Open DICE data from each, retruning a slice of
// *Entry, where the order matches the order of x509 certs in the
// input. If verify is true, each certificate in the chain is also verified by
// chaining it back to the root. The certs in the input are assumed to be in
// order, starting with DICE Layer 0.
// See:
// https://trustedcomputinggroup.org/wp-content/uploads/DICE-Layering-Architecture-r19_pub.pdf
// Input certificates and roots must be either []byte containing
// concatenated DER-encoded certs, or []*x509.Certificate (the types of othe
// two parameters do not need to match).
func ExtractChainFromX509(
	data any,
	roots any,
	verify bool,
) ([]*Entry, error) {
	var certs, rootCerts []*x509.Certificate
	var err error

	switch t := data.(type) {
	case []byte:
		certs, err = x509.ParseCertificates(t)
		if err != nil {
			return nil, fmt.Errorf("could not parse certs: %w", err)
		}
	case []*x509.Certificate:
		certs = t
	default:
		return nil, fmt.Errorf(
			"unexpected data type (%T); must be []byte or []*x509.Certificate",
			data,
		)
	}

	var verifOpts x509.VerifyOptions

	if verify {
		switch t := roots.(type) {
		case []byte:
			rootCerts, err = x509.ParseCertificates(t)
			if err != nil {
				return nil, fmt.Errorf("could not parse certs: %w", err)
			}
		case []*x509.Certificate:
			rootCerts = t
		default:
			return nil, fmt.Errorf(
				"unexpected roots type (%T); must be []byte or []*x509.Certificate",
				roots,
			)
		}

		verifOpts.Roots = x509.NewCertPool()
		verifOpts.Intermediates = x509.NewCertPool()

		for _, root := range rootCerts {
			verifOpts.Roots.AddCert(root)
		}

	}

	// nolint:prealloc
	var result []*Entry
	var leaf *x509.Certificate

	for i, cert := range certs {
		var odCert X509CdiCert

		if err = odCert.PopulateFromX509Cert(cert); err != nil {
			return nil, fmt.Errorf(
				"cert at index %d does appear to match Open DICE profile: %w",
				i, err,
			)
		}

		if verify {
			if i == (len(certs) - 1) {
				leaf = &odCert.Certificate
			} else {
				verifOpts.Intermediates.AddCert(&odCert.Certificate)
			}
		}

		result = append(result, odCert.GetEntry())

	}

	if verify {
		if _, err = leaf.Verify(verifOpts); err != nil {
			return nil, fmt.Errorf("failed to verify cert: %w", err)
		}
	}

	return result, nil
}

// X509CdiExt is the custom X.509 cert extension for CDI. See:
// https://pigweed.googlesource.com/open-dice/+/refs/heads/master/docs/specification.md#custom-extension-format
type X509CdiExt struct {
	CodeHash                []byte          `asn1:"tag:0,explicit"`
	CodeDescriptor          []byte          `asn1:"tag:1,explicit,optional"`
	ConfigurationHash       []byte          `asn1:"tag:2,explicit,optional"`
	ConfigurationDescriptor []byte          `asn1:"tag:3,explicit"`
	AuthorityHash           []byte          `asn1:"tag:4,explicit,optional"`
	AuthorityDescriptor     []byte          `asn1:"tag:5,explicit,optional"`
	Mode                    asn1.Enumerated `asn1:"tag:6,explicit"`
}

// X509CdiCert represents the decoded X.509 CID certificate.
type X509CdiCert struct {
	x509.Certificate
	X509CdiExt
}

// GetUdsID returns the cert's UDS_ID.
func (o *X509CdiCert) GetUdsID() []byte {
	return o.AuthorityKeyId
}

// GetCdiID returns the cert's CDI_ID.
func (o *X509CdiCert) GetCdiID() []byte {
	return o.SubjectKeyId
}

// Unmarshal decodes the der-encoded X.509 data into the X509CdiCert.
func (o *X509CdiCert) Unmarshal(data []byte) error {
	x509Cert, err := x509.ParseCertificate(data)
	if err != nil {
		return err
	}

	return o.PopulateFromX509Cert(x509Cert)
}

// PopulateFromX509Cert populatess the X509CdiCert from the provided
// x509.Certificate (which must contain the custom CDI extension).
func (o *X509CdiCert) PopulateFromX509Cert(x509Cert *x509.Certificate) error {
	if x509Cert.KeyUsage != x509.KeyUsageCertSign {
		return fmt.Errorf("unexpected KeyUsage: %v", x509Cert.KeyUsage)
	}

	// All must be set to CDI_ID
	if x509Cert.Subject.SerialNumber != fmt.Sprintf("%040x", x509Cert.SubjectKeyId) ||
		x509Cert.Subject.SerialNumber != fmt.Sprintf("%040x", x509Cert.SerialNumber) {
		return fmt.Errorf(
			"SerialNumber(%040x), Subject SERIALNUMBER(%s), and subjectKeyIdentifer(%040x) do not match", // nolint:golint
			x509Cert.SerialNumber,
			x509Cert.Subject.SerialNumber,
			x509Cert.SubjectKeyId,
		)
	}

	// Both must be set to UDS_ID
	if x509Cert.Issuer.SerialNumber != fmt.Sprintf("%040x", x509Cert.AuthorityKeyId) {
		return fmt.Errorf(
			"Issuer SERIALNUMBER(%s), and authorityKeyIdentifer(%040x) do not match", // nolint:golint
			x509Cert.Issuer.SerialNumber,
			x509Cert.AuthorityKeyId,
		)
	}

	if !x509Cert.IsCA {
		return fmt.Errorf("cA basic contraint is not set to TRUE")
	}

	if x509Cert.MaxPathLen > 0 {
		return fmt.Errorf("pathLenConstraint is greater than zero")
	}

	isCdiExt := func(id asn1.ObjectIdentifier) bool {
		return id.Equal(X509CdiExtOid)
	}
	cdiExtIndex := slices.IndexFunc(x509Cert.UnhandledCriticalExtensions, isCdiExt)
	if cdiExtIndex == -1 {
		return errors.New("x509 cert does not contain CDI custom extension")
	}

	o.Certificate = *x509Cert

	for _, ext := range o.Certificate.Extensions {
		if ext.Id.Equal(X509CdiExtOid) {
			rest, err := asn1.Unmarshal(ext.Value, &o.X509CdiExt)
			if err != nil {
				return fmt.Errorf("CDI ext error: %w", err)
			}
			if len(rest) != 0 {
				return fmt.Errorf("CDI ext error: trailing bytes")
			}

			o.Certificate.UnhandledCriticalExtensions = slices.Delete(
				o.Certificate.UnhandledCriticalExtensions,
				cdiExtIndex, cdiExtIndex+1,
			)
		}
	}

	return nil
}

// GetEntry returns an Entry popluated from the X509CdiCert.
func (o *X509CdiCert) GetEntry() *Entry {
	return &Entry{
		UdsID:                   o.GetUdsID(),
		CdiID:                   o.GetCdiID(),
		CodeHash:                o.CodeHash,
		CodeDescriptor:          o.CodeDescriptor,
		ConfigurationHash:       o.ConfigurationHash,
		ConfigurationDescriptor: o.ConfigurationDescriptor,
		AuthorityHash:           o.AuthorityHash,
		AuthorityDescriptor:     o.AuthorityDescriptor,
		Mode:                    Mode(o.Mode),
	}
}
