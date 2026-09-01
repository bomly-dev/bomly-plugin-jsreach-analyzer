package plugin

import (
	"testing"

	model "github.com/bomly-dev/bomly-sdk"
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

	first := withEvidence(nil, model.ReachabilityEvidence{
		ModuleRoot: "apps/api", Analyzer: Name,
		Status: model.ReachabilityUnreachable, Tier: model.TierPackage, Reason: "package-not-imported",
	}, stamp)
	if first.Status != model.ReachabilityUnreachable {
		t.Fatalf("first pass = %q, want unreachable", first.Status)
	}

	second := withEvidence(first, model.ReachabilityEvidence{
		ModuleRoot: "apps/web", Analyzer: Name,
		Status: model.ReachabilityReachable, Tier: model.TierPackage,
	}, stamp)
	if second.Status != model.ReachabilityReachable {
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
	r := withEvidence(nil, model.ReachabilityEvidence{
		ModuleRoot: "apps/api", Analyzer: Name,
		Status: model.ReachabilityUnreachable, Reason: "package-not-imported",
	}, stamp)
	r = withEvidence(r, model.ReachabilityEvidence{
		ModuleRoot: "apps/web", Analyzer: Name, Status: model.ReachabilityUnknown, Reason: "runner-error",
	}, stamp)
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown when a root could not be analyzed", r.Status)
	}
}
