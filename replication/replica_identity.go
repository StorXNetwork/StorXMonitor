// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	replicaIdentityDefault = "default"
	replicaIdentityFull    = "full"
	replicaIdentityNothing = "nothing"
	replicaIdentityIndexed = "indexed"
)

type replicaIdentityAlter struct {
	Table string
	Mode  string
	SQL   string
}

func mergeReplicaIdentityTableLists(c *Config) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(raw string) {
		t := strings.TrimSpace(raw)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range c.ReplicaIdentityTables {
		add(t)
	}
	for _, t := range c.ReplicaIdentityFullTables {
		add(t)
	}
	return out
}

func parseReplicaIdentityMode(s string) (string, error) {
	m := strings.ToLower(strings.TrimSpace(s))
	if m == "" {
		return "", Error.New("empty replica identity mode")
	}
	switch m {
	case replicaIdentityDefault, replicaIdentityFull, replicaIdentityNothing, replicaIdentityIndexed:
		return m, nil
	default:
		return "", Error.New("invalid replica identity %q: want default, full, nothing, or indexed", s)
	}
}

func qualifiedNameToIdentifier(name string) (pgx.Identifier, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, Error.New("empty qualified name")
	}
	var id pgx.Identifier
	for _, p := range strings.Split(name, ".") {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, Error.New("invalid qualified name %q", name)
		}
		id = append(id, p)
	}
	return id, nil
}

func buildReplicaIdentityAlterSQL(table string, mode, indexName string) (string, error) {
	tid, err := qualifiedNameToIdentifier(table)
	if err != nil {
		return "", err
	}
	m, err := parseReplicaIdentityMode(mode)
	if err != nil {
		return "", err
	}
	switch m {
	case replicaIdentityDefault:
		return fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY DEFAULT", tid.Sanitize()), nil
	case replicaIdentityFull:
		return fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY FULL", tid.Sanitize()), nil
	case replicaIdentityNothing:
		return fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY NOTHING", tid.Sanitize()), nil
	case replicaIdentityIndexed:
		iid, err := qualifiedNameToIdentifier(indexName)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY USING INDEX %s", tid.Sanitize(), iid.Sanitize()), nil
	default:
		return "", Error.New("unsupported replica identity mode %q", mode)
	}
}

func collectReplicaIdentityAlters(c *Config) ([]replicaIdentityAlter, error) {
	defaultMode, err := parseReplicaIdentityMode(c.DefaultReplicaIdentity)
	if err != nil {
		return nil, err
	}
	if defaultMode == replicaIdentityIndexed {
		return nil, Error.New("default-replica-identity cannot be indexed; use per-table replica_identity and replica_identity_index")
	}

	type row struct {
		table string
		mode  string
		index string
	}
	specs := make(map[string]row)

	set := func(table string, mode string, index string) error {
		table = strings.TrimSpace(table)
		if table == "" {
			return nil
		}
		m, err := parseReplicaIdentityMode(mode)
		if err != nil {
			return err
		}
		if m == replicaIdentityIndexed && strings.TrimSpace(index) == "" {
			return Error.New("replica_identity_index required for indexed mode on table %q", table)
		}
		specs[table] = row{table: table, mode: m, index: strings.TrimSpace(index)}
		return nil
	}

	for _, t := range mergeReplicaIdentityTableLists(c) {
		tc := c.LookupTableConfigForReplica(t)
		mode := defaultMode
		index := ""
		if tc != nil && strings.TrimSpace(tc.ReplicaIdentity) != "" {
			m, err := parseReplicaIdentityMode(tc.ReplicaIdentity)
			if err != nil {
				return nil, err
			}
			mode = m
			index = tc.ReplicaIdentityIndex
		}
		if err := set(t, mode, index); err != nil {
			return nil, err
		}
	}

	for i := range c.Tables {
		tc := &c.Tables[i]
		if strings.TrimSpace(tc.ReplicaIdentity) == "" {
			continue
		}
		m, err := parseReplicaIdentityMode(tc.ReplicaIdentity)
		if err != nil {
			return nil, err
		}
		if err := set(tc.Table, m, tc.ReplicaIdentityIndex); err != nil {
			return nil, err
		}
	}

	var out []replicaIdentityAlter
	for _, r := range specs {
		sql, err := buildReplicaIdentityAlterSQL(r.table, r.mode, r.index)
		if err != nil {
			return nil, err
		}
		out = append(out, replicaIdentityAlter{Table: r.table, Mode: r.mode, SQL: sql})
	}
	return out, nil
}
