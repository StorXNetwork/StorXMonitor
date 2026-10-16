// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"encoding/json"
)

const invoiceBillingJSONKey = "invoiceBilling"

// InvoiceBillingSettings is stored on reseller_configs.config under "invoiceBilling".
// Admin selects this; manual generate and auto cron both use it per seller.
type InvoiceBillingSettings struct {
	Day    int `json:"day"`
	Hour   int `json:"hour"`
	Minute int `json:"minute"`
}

func (s InvoiceBillingSettings) Clock() BillingClock {
	return BillingClock{Day: s.Day, Hour: s.Hour, Minute: s.Minute}
}

func defaultInvoiceBillingSettings() InvoiceBillingSettings {
	return InvoiceBillingSettings{Day: 1, Hour: 0, Minute: 0}
}

// ExtractInvoiceBillingSettings reads invoiceBilling from reseller config JSON (or defaults).
func ExtractInvoiceBillingSettings(configJSON []byte) InvoiceBillingSettings {
	settings := defaultInvoiceBillingSettings()
	if len(configJSON) == 0 {
		return settings
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(configJSON, &root); err != nil {
		return settings
	}
	raw, ok := root[invoiceBillingJSONKey]
	if !ok || len(raw) == 0 {
		return settings
	}
	var parsed InvoiceBillingSettings
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return settings
	}
	if parsed.Day < InvoiceBillingDayMin || parsed.Day > InvoiceBillingDayMax {
		parsed.Day = 1
	}
	if parsed.Hour < 0 || parsed.Hour > 23 {
		parsed.Hour = 0
	}
	if parsed.Minute < 0 || parsed.Minute > 59 {
		parsed.Minute = 0
	}
	return parsed
}

// MergeInvoiceBillingSettings writes invoiceBilling into config JSON, preserving other keys.
func MergeInvoiceBillingSettings(configJSON []byte, settings InvoiceBillingSettings) ([]byte, error) {
	root := map[string]json.RawMessage{}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &root); err != nil {
			// Branding may be invalid; start fresh map but keep nothing — still set billing.
			root = map[string]json.RawMessage{}
		}
	}
	if settings.Day < InvoiceBillingDayMin || settings.Day > InvoiceBillingDayMax {
		settings.Day = 1
	}
	if settings.Hour < 0 || settings.Hour > 23 {
		settings.Hour = 0
	}
	if settings.Minute < 0 || settings.Minute > 59 {
		settings.Minute = 0
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	root[invoiceBillingJSONKey] = raw
	return json.Marshal(root)
}

// MergePreserveInvoiceBilling copies invoiceBilling from oldConfig into newConfig JSON.
func MergePreserveInvoiceBilling(oldConfig, newConfig []byte) ([]byte, error) {
	if len(oldConfig) == 0 {
		return newConfig, nil
	}
	var oldRoot map[string]json.RawMessage
	if err := json.Unmarshal(oldConfig, &oldRoot); err != nil {
		return newConfig, nil
	}
	billing, ok := oldRoot[invoiceBillingJSONKey]
	if !ok || len(billing) == 0 {
		return newConfig, nil
	}
	var newRoot map[string]json.RawMessage
	if len(newConfig) == 0 {
		newRoot = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(newConfig, &newRoot); err != nil {
		return newConfig, nil
	}
	newRoot[invoiceBillingJSONKey] = billing
	return json.Marshal(newRoot)
}
