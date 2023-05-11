// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tcg

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DiceExtension_Unmarshal(t *testing.T) {
	assert := assert.New(t)

	data, err := ioutil.ReadFile("test/riot-ext.der")
	assert.Nil(err)

	var dice DiceExtension
	rest, err := dice.UnmarshalDER(data)
	assert.Empty(rest)
	assert.Nil(err)
}
