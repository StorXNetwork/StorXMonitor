// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package compensation

import (
	"time"

	"github.com/StorXNetwork/common/storxnetwork"
)

// NodeID is a wrapper type around storxnetwork.NodeID that implements CSV helpers.
type NodeID storxnetwork.NodeID

// Bytes calls the underlying type's Bytes function.
func (nodeID NodeID) Bytes() []byte {
	return storxnetwork.NodeID(nodeID).Bytes()
}

// String calls the underlying type's String function.
func (nodeID NodeID) String() string {
	return storxnetwork.NodeID(nodeID).String()
}

// UnmarshalCSV reads the csv entry into a storxnetwork.NodeID.
func (nodeID *NodeID) UnmarshalCSV(s string) error {
	v, err := storxnetwork.NodeIDFromString(s)
	if err != nil {
		return err
	}
	*nodeID = NodeID(v)
	return nil
}

// MarshalCSV writes the storxnetwork.NodeID into a CSV entry.
func (nodeID NodeID) MarshalCSV() (string, error) {
	return nodeID.String(), nil
}

// UTCDate is a wrapper type around time.Time that implements CSV helpers.
type UTCDate time.Time

// String formats the date into YYYY-MM-DD.
func (date UTCDate) String() string {
	return time.Time(date).In(time.UTC).Format("2006-01-02")
}

// UnmarshalCSV reads the YYYY-MM-DD date into the date.
func (date *UTCDate) UnmarshalCSV(s string) error {
	v, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	*date = UTCDate(v)
	return nil
}

// MarshalCSV writes out a CSV row containing the YYYY-MM-DD of the time.
func (date UTCDate) MarshalCSV() (string, error) {
	return date.String(), nil
}
