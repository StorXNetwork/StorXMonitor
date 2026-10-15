// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

//go:generate protoc --gogo_out=paths=source_relative:. --go-drpc_out=protolib=github.com/gogo/protobuf,paths=source_relative:. -I=. nodeconfig.proto

// Package nodeconfigpb contains proto definitions for satellite-managed storage node configuration.
package nodeconfigpb
