// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package staticapi

// Swagger models for static content APIs (used by swag only).

// StaticResourceItemSwagger is one entry in GET /resources-list responses.
type StaticResourceItemSwagger struct {
	Name string `json:"name" example:"Google Backup Guide"`
	Desc string `json:"desc" example:"Step-by-step guide to backup Google Workspace data"`
	Type string `json:"type" example:"url" enums:"url,contact"`
	Link string `json:"link" example:"/guides?type=google-backup"`
}

// StaticBlogItemSwagger is one entry in GET /blog-list responses.
type StaticBlogItemSwagger struct {
	Image       string `json:"image" example:"https://miro.medium.com/v2/resize:fit:1400/format:webp/0*j5KNMeLGxLjo4vNW"`
	Title       string `json:"title" example:"Cloud Storage Reimagined with StorX Network"`
	Description string `json:"description" example:"Cloud storage has become an integral part of our digital lives."`
	By          string `json:"by" example:"admin"`
	Date        string `json:"date" example:"JANUARY 1, 2022"`
	Link        string `json:"link" example:"https://medium.com/storx-network/cloud-storage-reimagined-with-storx-network-5c28296ac25f"`
}
