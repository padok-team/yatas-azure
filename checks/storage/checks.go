package storage

import (
	"strings"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	SoftDeleteID   = "AZURE_STO_002"
	GeoReplID      = "AZURE_STO_003"
	LifecycleID    = "AZURE_STO_004"
	ImmutabilityID = "AZURE_STO_005"
	PublicAccessID = "AZURE_STO_006"
	TransportID    = "AZURE_STO_007"
)

type accounts = internal.Fetched[Account]

// AZURE_STO_002 (≈ AWS "S3 buckets have versioning enabled"): blob soft delete or
// versioning lets deleted or overwritten blobs be recovered.
func checkIfSoftDelete(cfg commons.CheckConfig, in accounts, id string) {
	check := internal.NewCheck("Storage accounts have soft delete or versioning", "Check that blob soft delete or versioning is enabled on storage accounts", id)
	internal.Evaluate(cfg, check, in, "storage accounts", func(a Account) *internal.Verdict {
		switch {
		case !a.BlobProps:
			return nil
		case a.SoftDelete || a.Versioning:
			return internal.Yes(a.ID, "Blob soft delete or versioning is enabled on "+a.Name)
		}
		return internal.No(a.ID, "Neither blob soft delete nor versioning is enabled on "+a.Name)
	})
}

// AZURE_STO_003 (≈ AWS "S3 buckets have replication enabled"): geo-redundant SKU.
func checkIfGeoReplicated(cfg commons.CheckConfig, in accounts, id string) {
	check := internal.NewCheck("Storage accounts are geo-replicated", "Check that storage accounts use a geo-redundant SKU (GRS, GZRS, RA-GRS, RA-GZRS)", id, "Reliability", "Good Practice")
	internal.Evaluate(cfg, check, in, "storage accounts", func(a Account) *internal.Verdict {
		if strings.Contains(strings.ToUpper(a.SKU), "GRS") || strings.Contains(strings.ToUpper(a.SKU), "GZRS") {
			return internal.Yes(a.ID, a.Name+" is geo-replicated ("+a.SKU+")")
		}
		return internal.No(a.ID, a.Name+" is not geo-replicated ("+a.SKU+")")
	})
}

// AZURE_STO_004 (≈ AWS "S3 buckets have lifecycle policy").
func checkIfLifecyclePolicy(cfg commons.CheckConfig, in accounts, id string) {
	check := internal.NewCheck("Storage accounts have a lifecycle management policy", "Check that blob storage accounts define a lifecycle management policy", id, "Cost", "Good Practice")
	internal.Evaluate(cfg, check, in, "storage accounts", func(a Account) *internal.Verdict {
		switch {
		case !a.BlobProps:
			return nil
		case a.LifecyclePolicy:
			return internal.Yes(a.ID, a.Name+" has a lifecycle management policy")
		}
		return internal.No(a.ID, a.Name+" has no lifecycle management policy")
	})
}

// AZURE_STO_005 (≈ AWS "S3 buckets have object lock enabled").
func checkIfImmutability(cfg commons.CheckConfig, in accounts, id string) {
	check := internal.NewCheck("Storage accounts have immutable storage", "Check that account-level immutable storage with versioning is enabled", id)
	internal.Evaluate(cfg, check, in, "storage accounts", func(a Account) *internal.Verdict {
		switch {
		case !a.BlobProps:
			return nil
		case a.Immutability:
			return internal.Yes(a.ID, "Immutable storage with versioning is enabled on "+a.Name)
		}
		return internal.No(a.ID, "Immutable storage with versioning is not enabled on "+a.Name)
	})
}

// AZURE_STO_006 (≈ AWS "S3 buckets block public access").
func checkIfNoPublicAccess(cfg commons.CheckConfig, in accounts, id string) {
	check := internal.NewCheck("Storage accounts disallow public blob access", "Check that anonymous public access to blobs is disabled", id)
	internal.Evaluate(cfg, check, in, "storage accounts", func(a Account) *internal.Verdict {
		if a.PublicBlobAccess {
			return internal.No(a.ID, "Public blob access is allowed on "+a.Name)
		}
		return internal.Yes(a.ID, "Public blob access is disabled on "+a.Name)
	})
}

// AZURE_STO_007: encryption in transit.
func checkIfSecureTransport(cfg commons.CheckConfig, in accounts, id string) {
	check := internal.NewCheck("Storage accounts require secure transport", "Check that storage accounts require HTTPS and TLS 1.2 minimum", id)
	internal.Evaluate(cfg, check, in, "storage accounts", func(a Account) *internal.Verdict {
		switch {
		case !a.HTTPSOnly:
			return internal.No(a.ID, "HTTPS is not required on "+a.Name)
		case !a.MinTLS12:
			return internal.No(a.ID, "Minimum TLS version of "+a.Name+" is below 1.2")
		}
		return internal.Yes(a.ID, a.Name+" requires HTTPS and TLS 1.2")
	})
}
