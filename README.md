# Features

- Implementation of the attestation extension defined in [TCG DICE Attestation Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf).
- Implementation of TCG DICE TCB Info evidence extension.
- Implementation of [Open
  DICE](https://pigweed.googlesource.com/open-dice/+/refs/heads/master/docs/specification.md) certificate (CBOR and X.509) chain validation and claim extraction.


# Make targets

* `make test` (or just `make`) to run the unit tests;
* `make coverage` to get code coverage stats;
* `make lint` to run the code linter (requires [golangci-lint](https://golangci-lint.run/usage/install/)).
