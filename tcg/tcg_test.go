// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tcg

import (
	"encoding/asn1"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DiceExtension_Unmarshal(t *testing.T) {
	data, err := os.ReadFile("test/riot-ext.der")
	assert.Nil(t, err)

	var dice DiceExtension
	rest, err := dice.UnmarshalDER(data)
	assert.Empty(t, rest)
	assert.Nil(t, err)
}

func Test_TCBInfo_flags(t *testing.T) {
	var tv TcbInfo

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x80},
		BitLength: 8,
	}

	assert.True(t, tv.IsNotConfigured())
	assert.False(t, tv.IsNotSecure())
	assert.False(t, tv.IsRecovery())
	assert.False(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x40},
		BitLength: 8,
	}

	assert.False(t, tv.IsNotConfigured())
	assert.True(t, tv.IsNotSecure())
	assert.False(t, tv.IsRecovery())
	assert.False(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x20},
		BitLength: 8,
	}

	assert.False(t, tv.IsNotConfigured())
	assert.False(t, tv.IsNotSecure())
	assert.True(t, tv.IsRecovery())
	assert.False(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x10},
		BitLength: 8,
	}

	assert.False(t, tv.IsNotConfigured())
	assert.False(t, tv.IsNotSecure())
	assert.False(t, tv.IsRecovery())
	assert.True(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0xf0},
		BitLength: 8,
	}

	assert.True(t, tv.IsNotConfigured())
	assert.True(t, tv.IsNotSecure())
	assert.True(t, tv.IsRecovery())
	assert.True(t, tv.IsDebug())
}
