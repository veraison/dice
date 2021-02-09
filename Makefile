.DEFAULT_GOAL := test

export GO111MODULE := on
export SHELL := /bin/bash

.PHONY: test
test: ; @go test -v

.PHONY: coverage
coverage:
	@go test -v -cover -race -coverprofile=coverage.out && \
                go tool cover -html=coverage.out
CLEANFILES += coverage.out

.PHONY: lint
lint: ; @golangci-lint run

.PHONY: clean
clean: ; $(RM) -r $(CLEANFILES)

.PHONY: help
help:
	@echo "Available targets:"
	@echo
	@echo "    test: run the package tests (default)"
	@echo "coverage: run the package tests and show coverage profile"
	@echo "    lint: run golangci-lint using configuration from .golangci.yml"
	@echo "   clean: remove garbage"
	@echo
