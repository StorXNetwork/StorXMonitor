// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"

	"storj.io/storj/private/api"
)

// Settings contains relevant settings for the consumers of this service. It may contain settings
// of:
//
// - this service.
//
// - the server that exposes the service.
//
// - related Storj services (e.g. Satellite).
type Settings struct {
	Admin SettingsAdmin `json:"admin"`
}

// SettingsAdmin are the settings of this service and the server that exposes it.
type SettingsAdmin struct {
	Features FeatureFlags `json:"features"`
}

// FeatureFlags indicates what Admin service features are enabled or disabled. The features are
// usually disabled when they are not fully implemented.
type FeatureFlags struct {
	Account         AccountFlags `json:"account"`
	Project         ProjectFlags `json:"project"`
	Bucket          BucketFlags  `json:"bucket"`
	Nodes           NodeFlags    `json:"nodes"`
	Dashboard       bool         `json:"dashboard"`
	Operator        bool         `json:"operator"` // This is the information about the logged operator
	SignOut         bool         `json:"signOut"`
	SwitchSatellite bool         `json:"switchSatellite"`
}

// AccountFlags are the feature flags related to user's accounts.
type AccountFlags struct {
	Create                 bool `json:"create"`
	Delete                 bool `json:"delete"`
	History                bool `json:"history"`
	List                   bool `json:"list"`
	Projects               bool `json:"projects"`
	Search                 bool `json:"search"`
	Suspend                bool `json:"suspend"`
	Unsuspend              bool `json:"unsuspend"`
	ResetMFA               bool `json:"resetMFA"`
	UpdateInfo             bool `json:"updateInfo"`
	UpdateLimits           bool `json:"updateLimits"`
	UpdatePlacement        bool `json:"updatePlacement"`
	UpdateStatus           bool `json:"updateStatus"`
	UpdateValueAttribution bool `json:"updateValueAttribution"`
	View                   bool `json:"view"`
}

// ProjectFlags are the feature flags related to projects.
type ProjectFlags struct {
	Create                 bool `json:"create"`
	Delete                 bool `json:"delete"`
	History                bool `json:"history"`
	List                   bool `json:"list"`
	UpdateInfo             bool `json:"updateInfo"`
	UpdateLimits           bool `json:"updateLimits"`
	UpdatePlacement        bool `json:"updatePlacement"`
	UpdateValueAttribution bool `json:"updateValueAttribution"`
	View                   bool `json:"view"`
	MemberList             bool `json:"memberList"`
	MemberAdd              bool `json:"memberAdd"`
	MemberRemove           bool `json:"memberRemove"`
}

// BucketFlags are the feature flags related to buckets.
type BucketFlags struct {
	Create                 bool `json:"create"`
	Delete                 bool `json:"delete"`
	History                bool `json:"history"`
	List                   bool `json:"list"`
	UpdateInfo             bool `json:"updateInfo"`
	UpdatePlacement        bool `json:"updatePlacement"`
	UpdateValueAttribution bool `json:"updateValueAttribution"`
	View                   bool `json:"view"`
}

// NodeFlags are the feature flags related to storage nodes.
type NodeFlags struct {
	List   bool `json:"list"`
	View   bool `json:"view"`
	Manage bool `json:"manage"`
}

// GetSettings returns the service settings.
func (server *Server) GetSettings(ctx context.Context) (*Settings, api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	return &Settings{
		Admin: SettingsAdmin{
			Features: FeatureFlags{
				Account: AccountFlags{
					Create:                 true,
					Delete:                 true,
					History:                true,
					List:                   true,
					Projects:               true,
					Search:                 true,
					Suspend:                true,
					Unsuspend:              true,
					ResetMFA:               true,
					UpdateInfo:             true,
					UpdateLimits:           true,
					UpdatePlacement:        true,
					UpdateStatus:           true,
					UpdateValueAttribution: true,
					View:                   true,
				},
				Project: ProjectFlags{
					Create:                 true,
					Delete:                 true,
					History:                true,
					List:                   true,
					UpdateInfo:             true,
					UpdateLimits:           true,
					UpdatePlacement:        true,
					UpdateValueAttribution: true,
					View:                   true,
					MemberList:             true,
					MemberAdd:              true,
					MemberRemove:           true,
				},
				Bucket: BucketFlags{
					Create:                 true,
					Delete:                 true,
					History:                true,
					List:                   true,
					UpdateInfo:             true,
					UpdatePlacement:        true,
					UpdateValueAttribution: true,
					View:                   true,
				},
				Nodes: NodeFlags{
					List:   true,
					View:   true,
					Manage: true,
				},
				Dashboard:       true,
				Operator:        true,
				SignOut:         true,
				SwitchSatellite: true,
			},
		},
	}, api.HTTPError{}
}
