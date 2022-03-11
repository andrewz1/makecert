#!/usr/bin/env bash

[ -r .env ] && source .env
rm -f go.mod go.sum
go mod init
go mod tidy
go generate ./...
