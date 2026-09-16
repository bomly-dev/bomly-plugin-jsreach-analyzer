package plugin

import (
	"testing"

	sdkmodel "github.com/bomly-dev/bomly-sdk/model"
)

// TestEvidenceFromASecondRootIsNotDiscarded pins the loss phase 2.8 removes.
//
// This analyzer annotated a vulnerability once and skipped it on every later
// project pass. In a workspace that is wrong in the unsafe direction: the
// first project can leave a package unimported while the second imports it,
// and the first answer stood. Each root now contributes evidence and the
// annotation is the derived summary.
func TestEvidenceFromASecondRootIsNotDiscarded(t *testing.T) {
	const stamp = "2026-08-31T00:00:00Z"

	first := withEvidence(nil, sdkmodel.ReachabilityEvidence{
		ModuleRoot: "apps/api", Analyzer: Name,
		Status: sdkmodel.ReachabilityUnreachable, Tier: sdkmodel.TierPackage, Reason: "package-not-imported",
	}, stamp)
	if first.Status != sdkmodel.ReachabilityUnreachable {
		t.Fatalf("first pass = %q, want unreachable", first.Status)
	}

	second := withEvidence(first, sdkmodel.ReachabilityEvidence{
		ModuleRoot: "apps/web", Analyzer: Name,
		Status: sdkmodel.ReachabilityReachable, Tier: sdkmodel.TierPackage,
	}, stamp)
	if second.Status != sdkmodel.ReachabilityReachable {
		t.Errorf("summary = %q, want a reachable second root to win", second.Status)
	}
	if len(second.Evidence) != 2 {
		t.Errorf("evidence = %d entries, want both roots kept", len(second.Evidence))
	}
}

// TestUnanalyzedRootDoesNotReadAsUnreachable pins the safety half: a root that
// could not be analyzed must stop the pair reading as unreachable, rather than
// turning "we did not look there" into "it is not reachable there".
func TestUnanalyzedRootDoesNotReadAsUnreachable(t *testing.T) {
	const stamp = "2026-08-31T00:00:00Z"
	r := withEvidence(nil, sdkmodel.ReachabilityEvidence{
		ModuleRoot: "apps/api", Analyzer: Name,
		Status: sdkmodel.ReachabilityUnreachable, Reason: "package-not-imported",
	}, stamp)
	r = withEvidence(r, sdkmodel.ReachabilityEvidence{
		ModuleRoot: "apps/web", Analyzer: Name, Status: sdkmodel.ReachabilityUnknown, Reason: "runner-error",
	}, stamp)
	if r.Status != sdkmodel.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown when a root could not be analyzed", r.Status)
	}
}
