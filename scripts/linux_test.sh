#!/bin/bash

cd /root/go/src/github.com/chasinglogic/redalert
go get ./...
go test -v ./...
