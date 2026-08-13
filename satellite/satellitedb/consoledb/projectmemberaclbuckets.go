// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ console.ProjectMemberACLBuckets = (*projectMemberACLBuckets)(nil)

type projectMemberACLBuckets struct {
	db dbx.DriverMethods
}

func (r *projectMemberACLBuckets) List(ctx context.Context, projectID uuid.UUID) (rows []console.ProjectMemberACLBucket, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxRows, err := r.db.All_ProjectMemberAclBucket_By_ProjectId(ctx, dbx.ProjectMemberAclBucket_ProjectId(projectID[:]))
	if err != nil {
		return nil, err
	}

	rows = make([]console.ProjectMemberACLBucket, 0, len(dbxRows))
	for _, row := range dbxRows {
		converted, err := projectMemberACLBucketFromDBX(row)
		if err != nil {
			return nil, err
		}
		rows = append(rows, *converted)
	}
	return rows, nil
}

func (r *projectMemberACLBuckets) Get(ctx context.Context, projectID uuid.UUID, bucketName string) (_ *console.ProjectMemberACLBucket, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := r.db.Get_ProjectMemberAclBucket_By_ProjectId_And_BucketName(ctx,
		dbx.ProjectMemberAclBucket_ProjectId(projectID[:]),
		dbx.ProjectMemberAclBucket_BucketName(bucketName),
	)
	if err != nil {
		return nil, err
	}
	return projectMemberACLBucketFromDBX(row)
}

func (r *projectMemberACLBuckets) Add(ctx context.Context, projectID uuid.UUID, bucketName string) (_ *console.ProjectMemberACLBucket, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := r.db.Create_ProjectMemberAclBucket(ctx,
		dbx.ProjectMemberAclBucket_ProjectId(projectID[:]),
		dbx.ProjectMemberAclBucket_BucketName(bucketName),
	)
	if err != nil {
		return nil, err
	}
	return projectMemberACLBucketFromDBX(row)
}

func (r *projectMemberACLBuckets) Remove(ctx context.Context, projectID uuid.UUID, bucketName string) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = r.db.Delete_ProjectMemberAclBucket_By_ProjectId_And_BucketName(ctx,
		dbx.ProjectMemberAclBucket_ProjectId(projectID[:]),
		dbx.ProjectMemberAclBucket_BucketName(bucketName),
	)
	return err
}

func projectMemberACLBucketFromDBX(row *dbx.ProjectMemberAclBucket) (*console.ProjectMemberACLBucket, error) {
	if row == nil {
		return nil, Error.New("dbx project member acl bucket is nil")
	}
	projectID, err := uuid.FromBytes(row.ProjectId)
	if err != nil {
		return nil, err
	}
	return &console.ProjectMemberACLBucket{
		ProjectID:  projectID,
		BucketName: row.BucketName,
		CreatedAt:  row.CreatedAt,
	}, nil
}
