// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tcg

// This package implements the DICE attestation structure as defined by
//    https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// DiceOID is the standard object identifier for the DICE extension
var DiceOID = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

// DiceTcbInfoOid encodes the TCBInfo extension OID
var DiceTcbInfoOid = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2}

type FwID struct {
	// HashAlg is an algorithm identifier for the hash algorithm used to
	// produce the Digest value.
	HashAlg asn1.ObjectIdentifier
	// Digest is a digest of firmware, initialization values or other
	// settings of the target TCB.
	Digest []byte
}

type TcbInfo struct {
	// Vender is the entity that created the target TCB (e.g., a TCI
	// value).
	Vendor string `asn1:"tag:0,implicit,optional,utf8"`
	// Model is the product name associated with the target TCB.
	Model string `asn1:"tag:1,implicit,optional,utf8"`
	// Version is the revision string associated with the target TCB.
	Version string `asn1:"tag:2,implicit,optional,utf8"`
	// Svn is the security version number associated with the target TCB.
	Svn int `asn1:"tag:3,implicit,optional"`
	// Layer is the DICE layer associated with the target TCB.
	Layer int `asn1:"tag:4,implicit,optional"`
	// Index enumerates assests or keys within the target TCB and DICE
	// layer.
	Index int `asn1:"tag:5,implicit,optional"`
	// FwIDList is a list of FWID valuees resulting from applying the
	// HashAlg function over the target TCB values used to compute TCI and
	// CDI values. It is computed by the DICE layer that is the Attesting
	// Environment and certificate Issues.
	FwIDList []FwID `asn1:"tag:6,implicit,optional,omitempty"`
	// Flags enumerates possible TCB states. A TCB MAY operate according to
	// combinations of these operational states (in bit order, starting
	// with bit 0): notConfigured, notSecure, recover, debug.
	Flags asn1.BitString `asn1:"tag:7,implicit,optional"`
	// VendorInfo contains vendor-supplied values that encode vendor-,
	// model-, or device-specific state.
	VendorInfo []byte `asn1:"tag:8,implicit,optional,omitempty"`
}

func (o TcbInfo) IsNotConfigured() bool {
	return o.Flags.At(0) == 1
}

func (o TcbInfo) IsNotSecure() bool {
	return o.Flags.At(1) == 1
}

func (o TcbInfo) IsRecovery() bool {
	return o.Flags.At(2) == 1
}

func (o TcbInfo) IsDebug() bool {
	return o.Flags.At(3) == 1
}

// This structure is defined in pkix package but is not exported, so
// re-definding here.
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// FirmwareID contains the digest that is result of applying the specified
// hash algorithm over the object being measured.
type FirmwareID struct {
	HashAlg asn1.ObjectIdentifier
	Fwid    []byte
}

// CompositeDeviceID combines the firmware id with
type CompositeDeviceID struct {
	Version  int
	DeviceID SubjectPublicKeyInfo
	Fwid     FirmwareID
}

// DiceData is the attestation data encapsulated in the DiceExtension
// nolint: golint
type DiceData struct {
	Oid               asn1.ObjectIdentifier
	CompositeDeviceID CompositeDeviceID
}

// DiceExtension is the x509 v3 extension for DICE attestation.
// nolint: golint
type DiceExtension struct {
	DiceData `asn1:"tag:0,implicit,optional"`
}

// UnmarshalDER populates the DiceExtension from the provided DER-encoded data
// extracted from the certificate extension.
func (re *DiceExtension) UnmarshalDER(data []byte) ([]byte, error) {
	rest, err := asn1.Unmarshal(data, re)

	if err == nil && !re.Oid.Equal(DiceOID) {
		err = errors.New("decoded value does not have the Dice Exteision OID")
	}

	return rest, err
}
