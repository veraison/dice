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
