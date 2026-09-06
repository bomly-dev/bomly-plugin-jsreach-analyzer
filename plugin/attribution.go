package plugin

import (
	"path/filepath"
	"strings"

	model "github.com/bomly-dev/bomly-sdk"
)

// rootAttribution is how firmly a dependency node's declaration sites tie it
// to the module root currently being analyzed.
//
// ADR-0037 makes the module root the mandatory attribution floor for
// reachability evidence and node references the optional ceiling — refs exist
// for "analyzers that can attribute to a specific occurrence", and a consumer
// must read their absence as "not stated", never as "no occurrence". Naming
// whichever node the annotation loop happens to be visiting states a precision
// the analysis does not have: it pins an occurrence to a root nothing tied it
// to, which is a false claim rather than a vague one.
//
// This rule reads SDK types to produce SDK types and its proper home is the
// SDK, next to ReachabilityEvidence; it lives here in four copies only because
// the analyzers are four modules with no shared internal package. Tracked as
// https://github.com/bomly-dev/bomly-sdk/issues/68.
type rootAttribution int

const (
	// attributedElsewhere: every site this node records names some other
	// module root. The node is not part of the root under analysis and
	// contributes no evidence to it — a finding about a root a package is
	// absent from is noise at best and, when it reads "unreachable", a claim
	// about code that was never in that build.
	attributedElsewhere rootAttribution = iota
	// attributedToRootOnly: nothing ties the node to a particular root. The
	// analysis still covers it — the analyzer ran over this root's build — so
	// the evidence carries the module root, but no node reference, because
	// the occurrence was not established.
	attributedToRootOnly
	// attributedToSite: a site names this root, or lies under it. The
	// occurrence is established and the evidence may name the node.
	//
	// This is jsreach's own attribution source, per row 2.8: an npm package
	// is installed inside the tree it belongs to, so a nested
	// node_modules copy and a hoisted top-level one are two sites under two
	// different roots, and their paths say which is which. The hop map is
	// keyed by node ID, so the two copies can and do receive different
	// statuses -- a nested copy is only reachable through its own parent's
	// edges.
	attributedToSite
)

// rootAttributor answers the question above for one analysis pass.
//
// It is built per Analyze call rather than per node because the honest answer
// depends on the whole run: a node whose sites declare module roots may only
// be judged "not in this root" when the producer's roots and the analyzer's
// roots are the same vocabulary. Detectors record the root they resolved
// from; this analyzer derives roots from the filesystem. When those two
// disagree — a relative workspace path against an absolute module directory,
// say — a non-match means the two are speaking past each other, not that the
// package is absent, and dropping the node's evidence on that basis would lose
// the finding entirely. So a non-match only means "not ours" once at least one
// declared root in the graph is a root this run analyzes.
type rootAttributor struct {
	// analyzed is every root this run covers, cleaned. A site that lies under
	// one of these but not under the root in hand is positive evidence of
	// absence -- the package is installed in a tree this run knows about, and
	// that tree is not this one.
	analyzed map[string]struct{}
	// trustDeclaredRoots is set when producer-recorded roots and analyzed
	// roots overlap, which is what licenses reading a non-match as absence.
	trustDeclaredRoots bool
}

// newRootAttributor calibrates attribution against the roots this run will
// analyze and the sites the graph actually records.
func newRootAttributor(graph *model.Graph, roots []string) rootAttributor {
	analyzed := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if cleaned := cleanRoot(root); cleaned != "" {
			analyzed[cleaned] = struct{}{}
		}
	}
	attributor := rootAttributor{analyzed: analyzed}
	if graph == nil || len(analyzed) == 0 {
		return attributor
	}
	for _, node := range graph.DependencyNodes() {
		if node == nil {
			continue
		}
		for _, location := range node.Locations {
			declared := cleanRoot(location.ModuleRoot)
			if declared == "" {
				continue
			}
			if _, ok := analyzed[declared]; ok {
				attributor.trustDeclaredRoots = true
				return attributor
			}
		}
	}
	return attributor
}

// attribute reports how firmly node's sites tie it to root.
func (a rootAttributor) attribute(node *model.DependencyNode, root string) rootAttribution {
	if node == nil {
		return attributedElsewhere
	}
	target := cleanRoot(root)
	declaredAnyRoot, sitedInAnotherRoot := false, false
	for _, location := range node.Locations {
		if declared := cleanRoot(location.ModuleRoot); declared != "" {
			declaredAnyRoot = true
			if target != "" && declared == target {
				return attributedToSite
			}
		}
		if location.RealPath == "" {
			continue
		}
		if target != "" && pathContainsRoot(location.RealPath, target) {
			return attributedToSite
		}
		if a.sitedInAnalyzedRoot(location.RealPath) {
			sitedInAnotherRoot = true
		}
	}
	// Two ways to know the node is not ours, and both need the run's own
	// roots to say so. A site under another root this run analyzes is
	// positive evidence of absence: the package is installed in a tree we
	// know about and it is not this one. A site whose path is under no
	// analyzed root at all -- a module cache, a global store -- says nothing
	// either way and must not be read as absence.
	if sitedInAnotherRoot || (declaredAnyRoot && a.trustDeclaredRoots) {
		return attributedElsewhere
	}
	return attributedToRootOnly
}

// sitedInAnalyzedRoot reports whether path lies under any root this run covers.
func (a rootAttributor) sitedInAnalyzedRoot(path string) bool {
	for root := range a.analyzed {
		if pathContainsRoot(path, root) {
			return true
		}
	}
	return false
}

// cleanRoot normalizes a module root for comparison. Empty in, empty out —
// an unset root is not a root that matches everything.
func cleanRoot(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	return filepath.Clean(root)
}
