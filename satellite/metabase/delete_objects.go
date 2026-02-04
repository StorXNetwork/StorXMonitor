// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package metabase

import (
	"context"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/storj"
	"storj.io/common/uuid"
)

// DeleteObjectsMaxItems is the maximum amount of items that are allowed
// in a DeleteObjects request.
const DeleteObjectsMaxItems = 1000

// DeleteObjects contains options for deleting multiple committed objects from a bucket.
type DeleteObjects struct {
	ProjectID  uuid.UUID
	BucketName BucketName
	Items      []DeleteObjectsItem

	Versioned bool
	Suspended bool

	ObjectLock ObjectLockDeleteOptions

	// supported only by Spanner.
	TransmitEvent bool
}

// DeleteObjectsItem describes the location of an object in a bucket to be deleted.
type DeleteObjectsItem struct {
	ObjectKey       ObjectKey
	StreamVersionID StreamVersionID
}

// DeleteZombieObjects contains all the information necessary to delete zombie objects and segments.
type DeleteZombieObjects struct {
	DeadlineBefore     time.Time
	InactiveDeadline   time.Time
	AsOfSystemInterval time.Duration
	BatchSize          int
}

// DeleteZombieObjects deletes all objects that zombie deletion deadline passed.
// TODO will be removed when objects table will be free from pending objects.
func (db *DB) DeleteZombieObjects(ctx context.Context, opts DeleteZombieObjects) (err error) {
	defer mon.Task()(&ctx)(&err)

	return db.deleteObjectsAndSegmentsBatch(ctx, opts.BatchSize, func(startAfter ObjectStream, batchsize int) (last ObjectStream, err error) {
		// pending objects migrated to metabase didn't have zombie_deletion_deadline column set, because
		// of that we need to get into account also object with zombie_deletion_deadline set to NULL
		query := `
			SELECT
				project_id, bucket_name, object_key, version, stream_id
			FROM objects
			` + db.impl.AsOfSystemInterval(opts.AsOfSystemInterval) + `
			WHERE
				(project_id, bucket_name, object_key, version) > ($1, $2, $3, $4)
				AND status = ` + statusPending + `
				AND (zombie_deletion_deadline IS NULL OR zombie_deletion_deadline < $5)
				ORDER BY project_id, bucket_name, object_key, version
			LIMIT $6;`

		objects := make([]ObjectStream, 0, batchsize)

		scanErrClass := errs.Class("DB rows scan has failed")
		err = withRows(db.db.QueryContext(ctx, query,
			startAfter.ProjectID, []byte(startAfter.BucketName), []byte(startAfter.ObjectKey), startAfter.Version,
			opts.DeadlineBefore,
			batchsize),
		)(func(rows tagsql.Rows) error {
			for rows.Next() {
				err = rows.Scan(&last.ProjectID, &last.BucketName, &last.ObjectKey, &last.Version, &last.StreamID)
				if err != nil {
					return scanErrClass.Wrap(err)
				}

				objects = append(objects, last)
			}

			return nil
		})
		if err != nil {
			if scanErrClass.Has(err) {
				return ObjectStream{}, Error.New("unable to select zombie objects for deletion: %w", err)
			}

			db.log.Warn("unable to select zombie objects for deletion", zap.Error(Error.Wrap(err)))
			return ObjectStream{}, nil
		}

		err = db.deleteInactiveObjectsAndSegments(ctx, objects, opts)
		if err != nil {
			db.log.Warn("delete from DB zombie objects", zap.Error(err))
			return ObjectStream{}, nil
		}

		return last, nil
	})
}

func (db *DB) deleteObjectsAndSegmentsBatch(ctx context.Context, batchsize int, deleteBatch func(startAfter ObjectStream, batchsize int) (last ObjectStream, err error)) (err error) {
	defer mon.Task()(&ctx)(&err)

	deleteBatchsizeLimit.Ensure(&batchsize)

	var startAfter ObjectStream
	for {
		lastDeleted, err := deleteBatch(startAfter, batchsize)
		if err != nil {
			return err
		}
		if lastDeleted.StreamID.IsZero() {
			return nil
		}
		startAfter = lastDeleted
	}
	for i, item := range opts.Items {
		if item.ObjectKey == "" {
			return ErrInvalidRequest.New("Items[%d].ObjectKey missing", i)
		}
		version := item.StreamVersionID.Version()
		if !item.StreamVersionID.IsZero() && version == 0 {
			return ErrInvalidRequest.New("Items[%d].StreamVersionID invalid: version is %v", i, version)
		}
	}
	return nil
}

// DeleteObjectsResult contains the results of an attempt to delete specific objects from a bucket.
type DeleteObjectsResult struct {
	Items               []DeleteObjectsResultItem
	DeletedSegmentCount int64
}

// DeleteObjectsResultItem contains the result of an attempt to delete a specific object from a bucket.
type DeleteObjectsResultItem struct {
	ObjectKey                ObjectKey
	RequestedStreamVersionID StreamVersionID

	Removed *DeleteObjectsInfo
	Marker  *DeleteObjectsInfo

	Status storj.DeleteObjectsStatus
}

// DeleteObjectsInfo contains information about an object that was deleted or a delete marker that was inserted
// as a result of processing a DeleteObjects request item.
type DeleteObjectsInfo struct {
	StreamVersionID    StreamVersionID
	Status             ObjectStatus
	CreatedAt          time.Time
	TotalEncryptedSize int64
}

// DeleteObjects deletes specific objects from a bucket.
func (db *DB) DeleteObjects(ctx context.Context, opts DeleteObjects) (result DeleteObjectsResult, err error) {
	defer mon.Task()(&ctx)(&err)

	if err := opts.Verify(); err != nil {
		return DeleteObjectsResult{}, errs.Wrap(err)
	}

	deletedObjectOffset, deletedSegmentOffset := 0, 0

	defer func() {
		var deletedObjects int
		for _, item := range result.Items {
			if item.Status == storj.DeleteObjectsStatusOK && item.Removed != nil {
				deletedObjects++
			}
		}
		mon.Meter("object_delete").Mark(deletedObjects - deletedObjectOffset)
		mon.Meter("segment_delete").Mark64(result.DeletedSegmentCount - int64(deletedSegmentOffset))
	}()

	adapter := db.ChooseAdapter(opts.ProjectID)
	processedOpts := opts.processResults()
	result.Items = processedOpts.results

	for i := 0; i < processedOpts.lastCommittedCount; i++ {
		resultItem := &processedOpts.results[i]

		deleteOpts := DeleteObjectLastCommitted{
			ObjectLocation: ObjectLocation{
				ProjectID:  opts.ProjectID,
				BucketName: opts.BucketName,
				ObjectKey:  resultItem.ObjectKey,
			},
			ObjectLock:    opts.ObjectLock,
			TransmitEvent: opts.TransmitEvent,
		}

		var deleteObjectResult DeleteObjectResult
		if opts.Versioned {
			var deleteMarkerStreamID uuid.UUID
			deleteMarkerStreamID, err = generateDeleteMarkerStreamID()
			if err != nil {
				return result, err
			}
			deleteObjectResult, err = adapter.DeleteObjectLastCommittedVersioned(ctx, deleteOpts, deleteMarkerStreamID)
		} else if opts.Suspended {
			var deleteMarkerStreamID uuid.UUID
			deleteMarkerStreamID, err = generateDeleteMarkerStreamID()
			if err != nil {
				return result, err
			}
			deleteObjectResult, err = db.DeleteObjectLastCommittedSuspended(ctx, deleteOpts, deleteMarkerStreamID)
			if ErrObjectNotFound.Has(err) {
				err = nil
			}
			// HACKFIX: `DeleteObjectLastCommittedSuspended` internally already submits metrics and we don't want
			// to send them twice. Ideally the whole switch should be replaced by `db.DeleteObjectLastCommitted`.
			deletedObjectOffset += len(deleteObjectResult.Removed)
			deletedSegmentOffset += deleteObjectResult.DeletedSegmentCount
		} else {
			deleteObjectResult, err = adapter.DeleteObjectLastCommittedPlain(ctx, deleteOpts)
		}

		result.DeletedSegmentCount += int64(deleteObjectResult.DeletedSegmentCount)

		if len(deleteObjectResult.Removed) > 0 {
			removed := deleteObjectResult.Removed[0]
			sv := removed.StreamVersionID()
			deleteInfo := &DeleteObjectsInfo{
				StreamVersionID:    sv,
				Status:             CommittedUnversioned,
				CreatedAt:          removed.CreatedAt,
				TotalEncryptedSize: removed.TotalEncryptedSize,
			}
			resultItem.Removed = deleteInfo
			resultItem.Status = storj.DeleteObjectsStatusOK

			if !opts.Versioned {
				// Handle the case where an object was specified twice in the deletion request:
				// once with a version omitted and once with a version set. We must ensure that
				// when the object is deleted, both result items that reference it are updated.
				if i, ok := processedOpts.resultsIndices[DeleteObjectsItem{
					ObjectKey:       resultItem.ObjectKey,
					StreamVersionID: sv,
				}]; ok {
					processedOpts.results[i].Removed = deleteInfo
					processedOpts.results[i].Status = storj.DeleteObjectsStatusOK
				}
			}
		}

		if len(deleteObjectResult.Markers) > 0 {
			marker := deleteObjectResult.Markers[0]
			resultItem.Marker = &DeleteObjectsInfo{
				StreamVersionID:    marker.StreamVersionID(),
				Status:             marker.Status,
				CreatedAt:          marker.CreatedAt,
				TotalEncryptedSize: marker.TotalEncryptedSize,
			}
			resultItem.Status = storj.DeleteObjectsStatusOK
		}

		if err != nil {
			if ErrObjectLock.Has(err) {
				resultItem.Status = storj.DeleteObjectsStatusLocked
				err = nil
			} else {
				return result, err
			}
		}

		if resultItem.Status == storj.DeleteObjectsStatusInternalError {
			resultItem.Status = storj.DeleteObjectsStatusNotFound
		}
	}

	for i := processedOpts.lastCommittedCount; i < len(processedOpts.results); i++ {
		resultItem := &processedOpts.results[i]
		if resultItem.Status == storj.DeleteObjectsStatusOK {
			continue
		}

		if opts.Versioned || opts.Suspended {
			// Prevent the removal of a delete marker that was added in a previous iteration.
			if linkedItemIdx, ok := processedOpts.resultsIndices[DeleteObjectsItem{
				ObjectKey: resultItem.ObjectKey,
			}]; ok {
				marker := processedOpts.results[linkedItemIdx].Marker
				if marker != nil && marker.StreamVersionID == resultItem.RequestedStreamVersionID {
					resultItem.Status = storj.DeleteObjectsStatusNotFound
					continue
				}
			}
		}

		var deleteObjectResult DeleteObjectResult
		deleteObjectResult, err = adapter.DeleteObjectExactVersion(ctx, DeleteObjectExactVersion{
			ObjectLocation: ObjectLocation{
				ProjectID:  opts.ProjectID,
				BucketName: opts.BucketName,
				ObjectKey:  resultItem.ObjectKey,
			},
			Version:        resultItem.RequestedStreamVersionID.Version(),
			StreamIDSuffix: resultItem.RequestedStreamVersionID.StreamIDSuffix(),
			ObjectLock:     opts.ObjectLock,
			TransmitEvent:  opts.TransmitEvent,
		})

		result.DeletedSegmentCount += int64(deleteObjectResult.DeletedSegmentCount)

		if len(deleteObjectResult.Removed) > 0 {
			resultItem.Status = storj.DeleteObjectsStatusOK
			resultItem.Removed = &DeleteObjectsInfo{
				StreamVersionID:    resultItem.RequestedStreamVersionID,
				Status:             deleteObjectResult.Removed[0].Status,
				CreatedAt:          deleteObjectResult.Removed[0].CreatedAt,
				TotalEncryptedSize: deleteObjectResult.Removed[0].TotalEncryptedSize,
			}
		}

		if err != nil {
			if ErrObjectLock.Has(err) {
				resultItem.Status = storj.DeleteObjectsStatusLocked
				err = nil
			} else {
				return result, err
			}
		}

		if resultItem.Status == storj.DeleteObjectsStatusInternalError {
			resultItem.Status = storj.DeleteObjectsStatusNotFound
		}
	}

	return result, err
}

type deleteObjectsSetupInfo struct {
	results            []DeleteObjectsResultItem
	resultsIndices     map[DeleteObjectsItem]int
	lastCommittedCount int
}

// processResults returns data that (*Adapter).DeleteObjects implementations require for executing database queries.
func (opts DeleteObjects) processResults() (info deleteObjectsSetupInfo) {
	info.resultsIndices = make(map[DeleteObjectsItem]int, len(opts.Items))
	for _, item := range opts.Items {
		if _, exists := info.resultsIndices[item]; !exists {
			info.resultsIndices[item] = -1
			if item.StreamVersionID.IsZero() {
				info.lastCommittedCount++
			}
		}
	}

	info.results = make([]DeleteObjectsResultItem, len(info.resultsIndices))

	// We process last committed items first to allow for a simpler implementation
	// than what would otherwise be possible. This shouldn't result in any difference
	// in the result items' contents or the overall effect on the database.
	// If an object is requested for deletion both by last committed and exact version
	// request items, each result item should reflect the effects of processing its
	// respective request item in isolation, so the order in which the request items
	// are processed isn't significant.

	lastCommittedCounter := 0
	versionedCounter := info.lastCommittedCount
	for _, item := range opts.Items {
		if info.resultsIndices[item] == -1 {
			counter := &lastCommittedCounter
			if !item.StreamVersionID.IsZero() {
				counter = &versionedCounter
			}
			info.results[*counter] = DeleteObjectsResultItem{
				ObjectKey:                item.ObjectKey,
				RequestedStreamVersionID: item.StreamVersionID,
			}
			info.resultsIndices[item] = *counter
			*counter++
		}
	}

	return info
}
