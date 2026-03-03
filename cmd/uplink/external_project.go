// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/rpc/rpcpool"
	"github.com/StorXNetwork/StorXMonitor/cmd/uplink/ulext"
	"github.com/StorXNetwork/StorXMonitor/cmd/uplink/ulfs"
	"github.com/StorXNetwork/uplink"
	privateAccess "github.com/StorXNetwork/uplink/private/access"
	privateProject "github.com/StorXNetwork/uplink/private/project"
	"github.com/StorXNetwork/uplink/private/testuplink"
	"github.com/StorXNetwork/uplink/private/transport"
)

const uplinkCLIUserAgent = "uplink-cli"

func (ex *external) OpenFilesystem(ctx context.Context, accessName string, options ...ulext.Option) (_ ulfs.Filesystem, err error) {
	defer mon.Task()(&ctx)(&err)

	project, err := ex.OpenProject(ctx, accessName, options...)
	if err != nil {
		return nil, err
	}
	return ulfs.NewMixed(ulfs.NewLocal(ulfs.NewLocalBackendOS()), ulfs.NewRemote(project)), nil
}

func (ex *external) OpenProject(ctx context.Context, accessName string, options ...ulext.Option) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	opts := ulext.LoadOptions(options...)

	access, err := ex.OpenAccess(accessName)
	if err != nil {
		return nil, err
	}

	if opts.EncryptionBypass {
		if err := privateAccess.EnablePathEncryptionBypass(access); err != nil {
			return nil, err
		}
	}

	config := uplink.Config{
		UserAgent: uplinkCLIUserAgent,
	}

	userAgents, err := ex.Dynamic("client.user-agent")
	if err != nil {
		return nil, err
	}
	if len(userAgents) > 0 {
		if ua := userAgents[len(userAgents)-1]; ua != "" {
			config.UserAgent = ua
		}
	}

	if opts.ConnectionPoolOptions != (rpcpool.Options{}) {
		if err := transport.SetConnectionPool(ctx, &config, rpcpool.New(opts.ConnectionPoolOptions)); err != nil {
			return nil, err
		}
	}

	if opts.ConcurrentSegmentUploadsConfig != (testuplink.ConcurrentSegmentUploadsConfig{}) {
		ctx = testuplink.WithConcurrentSegmentUploadsConfig(ctx, opts.ConcurrentSegmentUploadsConfig)
	}

	return config.OpenProject(ctx, access)
}

func (ex *external) GetEdgeUrlOverrides(ctx context.Context, access *uplink.Access) (overrides ulext.EdgeURLOverrides, err error) {
	defer mon.Task()(&ctx)(&err)

	info, err := privateProject.GetProjectInfo(ctx, uplink.Config{UserAgent: uplinkCLIUserAgent}, access)
	if err != nil {
		return overrides, errs.New("could not get project info: %w", err)
	}
	if info.EdgeUrlOverrides != nil {
		overrides.AuthService = info.EdgeUrlOverrides.AuthService
		overrides.PublicLinksharing = info.EdgeUrlOverrides.PublicLinksharing
		overrides.InternalLinksharing = info.EdgeUrlOverrides.InternalLinksharing
	}
	return overrides, nil
}
