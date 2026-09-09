package plugin

import (
	"path/filepath"
	"testing"
	"time"

	model "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// npmNodeAt builds one npm dependency node installed at installDir. The site's
// path is the whole point: a hoisted copy and a nested node_modules copy are
// the same name at two paths under two different project roots.
func npmNodeAt(t *testing.T, name, version, installDir string, declareRoot string) *model.DependencyNode {
	t.Helper()
	purl := "pkg:npm/" + name + "@" + version
	dep := testkit.MustDependencyCoords(t, model.Coordinates{
		Name: name, Version: version, Ecosystem: model.EcosystemNPM, PURL: purl,
	})
	dep.Locations = []model.PackageLocation{{
		RealPath:   filepath.Join(installDir, "package.json"),
		ModuleRoot: declareRoot,
	}}
	dep.PackageRef = purl
	return dep
}

func npmGraph(t *testing.T, nodes []*model.DependencyNode, ids []string) (*model.Graph, *model.PackageRegistry) {
	t.Helper()
	g := model.New()
	registry := model.NewPackageRegistry()
	for i, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s): %v", node.NodeID(), err)
		}
		pkg := registry.Ensure(node.PackageRef)
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{ID: ids[i], Source: "osv"})
	}
	return g, registry
}

func npmReachability(t *testing.T, registry *model.PackageRegistry, purl string) *model.Reachability {
	t.Helper()
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
		t.Fatalf("no vulnerability for %q", purl)
	}
	return pkg.Vulnerabilities[0].Reachability
}

func rootsOf(r *model.Reachability) []string {
	if r == nil {
		return nil
	}
	roots := make([]string, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		roots = append(roots, e.ModuleRoot)
	}
	return roots
}

// TestEvidenceIsKeyedByTheProjectRootThatEstablishedIt is the core of row 2.8.
//
// A package installed under apps/api must not collect apps/web's finding.
// Before attribution was real, packageBelongsToProjectRoot ended in an
// unconditional `return true`, so every npm package took every root's answer —
// including an "unreachable" from a project whose tree it was never in.
func TestEvidenceIsKeyedByTheProjectRootThatEstablishedIt(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "apps", "api")
	webRoot := filepath.Join(workspace, "apps", "web")

	apiDep := npmNodeAt(t, "lodash", "4.17.21", filepath.Join(apiRoot, "node_modules", "lodash"), "")
	webDep := npmNodeAt(t, "express", "4.18.2", filepath.Join(webRoot, "node_modules", "express"), "")
	g, registry := npmGraph(t, []*model.DependencyNode{apiDep, webDep}, []string{"GHSA-1", "GHSA-2"})

	attributor := model.NewRootAttributor([]string{apiRoot, webRoot}, g)
	for _, root := range []string{apiRoot, webRoot} {
		applyImportedPackageSeeds(model.AnalyzeRequest{Graph: g, Registry: registry}, attributor, root, nil, false, time.Time{})
	}

	for _, tc := range []struct {
		dep  *model.DependencyNode
		want string
	}{{apiDep, apiRoot}, {webDep, webRoot}} {
		roots := rootsOf(npmReachability(t, registry, tc.dep.PackageRef))
		if len(roots) != 1 || roots[0] != tc.want {
			t.Errorf("%s evidence roots = %v, want exactly [%s]", tc.dep.Name, roots, tc.want)
		}
	}
}

// TestNestedCopyIsDecidedByPathNotNamedAsAnOccurrence pins what the install
// paths do and do not establish.
//
// They do say which root each copy belongs to: npm installs a package inside
// the tree that uses it, so a hoisted copy and a nested one sit at two paths
// and only one of them is under the root being analyzed. That much is real,
// and it is why the nested copy must not collect the other root's finding.
//
// They do not say which of two same-name installations an import resolved to.
// Seeding matches on the bare specifier, so one `import "lodash"` seeds both
// copies; naming either as the occurrence would be a guess. The evidence
// carries the root and no refs.
func TestNestedCopyIsDecidedByPathNotNamedAsAnOccurrence(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "apps", "api")
	webRoot := filepath.Join(workspace, "apps", "web")

	// The same package name at two versions: one hoisted into api, one nested
	// under a dependency of web.
	hoisted := npmNodeAt(t, "lodash", "4.17.21", filepath.Join(apiRoot, "node_modules", "lodash"), "")
	nested := npmNodeAt(t, "lodash", "3.10.1", filepath.Join(webRoot, "node_modules", "legacy", "node_modules", "lodash"), "")
	g, registry := npmGraph(t, []*model.DependencyNode{hoisted, nested}, []string{"GHSA-1", "GHSA-1"})

	attributor := model.NewRootAttributor([]string{apiRoot, webRoot}, g)
	// api imports lodash; web's build is not analyzed in this call.
	applyImportedPackageSeeds(model.AnalyzeRequest{Graph: g, Registry: registry}, attributor, apiRoot,
		map[string]int{"lodash": 0}, false, time.Time{})

	hoistedEvidence := npmReachability(t, registry, hoisted.PackageRef).Evidence
	if len(hoistedEvidence) != 1 {
		t.Fatalf("hoisted evidence = %d entries, want 1", len(hoistedEvidence))
	}
	if hoistedEvidence[0].Status != model.ReachabilityReachable {
		t.Errorf("hoisted status = %q, want reachable", hoistedEvidence[0].Status)
	}
	if got := hoistedEvidence[0].DependencyRefs; len(got) != 0 {
		t.Errorf("hoisted refs = %v; a site says which root a copy is in, not which "+
			"same-name installation the import resolved to", got)
	}
	if hoistedEvidence[0].ModuleRoot != apiRoot {
		t.Errorf("module root = %q, want %q: the floor is the whole claim here",
			hoistedEvidence[0].ModuleRoot, apiRoot)
	}

	if r := npmReachability(t, registry, nested.PackageRef); r != nil {
		t.Errorf("the nested copy collected api's finding: %+v", r.Evidence)
	}
}

// TestUnattributedPackageKeepsTheRootFloorWithoutRefs covers the degradation
// direction. A package whose sites say nothing about where it is installed
// still gets the root's finding — the analyzer did run over that root — but
// naming an occurrence would state a precision nothing established.
func TestUnattributedPackageKeepsTheRootFloorWithoutRefs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	dep := npmNodeAt(t, "lodash", "4.17.21", "", "")
	dep.Locations = nil
	g, registry := npmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})

	applyImportedPackageSeeds(model.AnalyzeRequest{Graph: g, Registry: registry},
		model.NewRootAttributor([]string{root}, g), root, map[string]int{"lodash": 0}, false, time.Time{})

	evidence := npmReachability(t, registry, dep.PackageRef).Evidence
	if len(evidence) != 1 {
		t.Fatalf("evidence = %d entries, want 1", len(evidence))
	}
	if evidence[0].ModuleRoot != root {
		t.Errorf("module root = %q, want %q: the floor is mandatory", evidence[0].ModuleRoot, root)
	}
	if got := evidence[0].DependencyRefs; len(got) != 0 {
		t.Errorf("refs = %v, want none: no site established this occurrence", got)
	}
}

// TestSiteOutsideEveryAnalyzedRootIsNotAbsence separates the two ways a path
// can fail to match. A site under another root this run analyzes is evidence
// the package lives elsewhere; a site under no analyzed root at all -- a pnpm
// content store, a global cache -- says nothing about where it is used, and
// reading it as absence would silently drop the finding.
func TestSiteOutsideEveryAnalyzedRootIsNotAbsence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	store := filepath.Join(t.TempDir(), "pnpm-store")

	dep := npmNodeAt(t, "lodash", "4.17.21", filepath.Join(store, "lodash@4.17.21"), "")
	g, registry := npmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})

	applyImportedPackageSeeds(model.AnalyzeRequest{Graph: g, Registry: registry},
		model.NewRootAttributor([]string{root}, g), root, map[string]int{"lodash": 0}, false, time.Time{})

	r := npmReachability(t, registry, dep.PackageRef)
	if r == nil || len(r.Evidence) != 1 {
		t.Fatalf("evidence = %v; a site outside every analyzed root is not absence", rootsOf(r))
	}
	if r.Evidence[0].ModuleRoot != root {
		t.Errorf("module root = %q, want %q", r.Evidence[0].ModuleRoot, root)
	}
	if got := r.Evidence[0].DependencyRefs; len(got) != 0 {
		t.Errorf("refs = %v, want none: the store path does not say which root uses it", got)
	}
}

// TestFailedProjectRootStillContributesUnknownEvidence pins the safety half in
// the failure path: one root finding nothing must not speak for a workspace
// whose other root was never analyzed.
func TestFailedProjectRootStillContributesUnknownEvidence(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "apps", "api")
	webRoot := filepath.Join(workspace, "apps", "web")

	// One package installed in both trees, so both passes are about it.
	dep := npmNodeAt(t, "lodash", "4.17.21", filepath.Join(apiRoot, "node_modules", "lodash"), "")
	dep.Locations = append(dep.Locations, model.PackageLocation{
		RealPath: filepath.Join(webRoot, "node_modules", "lodash", "package.json"),
	})
	g, registry := npmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})
	req := model.AnalyzeRequest{Graph: g, Registry: registry}

	attributor := model.NewRootAttributor([]string{apiRoot, webRoot}, g)
	// api analyzed and found nothing; web's entry points could not be resolved.
	applyImportedPackageSeeds(req, attributor, apiRoot, nil, false, time.Time{})
	annotateProjectUnknown(req, attributor, webRoot, "no-entry-points", time.Time{})

	r := npmReachability(t, registry, dep.PackageRef)
	if len(r.Evidence) != 2 {
		t.Fatalf("evidence = %d entries (%v), want one per project root", len(r.Evidence), rootsOf(r))
	}
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown: one root was never analyzed", r.Status)
	}
}

// TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary guards the
// degradation path. Detectors record the root they resolved from and this
// analyzer derives roots from the filesystem; when the spellings never
// overlap, a non-match means they are speaking past each other, and dropping
// the node would lose the finding outright.
func TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	dep := npmNodeAt(t, "lodash", "4.17.21", "", "apps/api")
	dep.Locations = []model.PackageLocation{{ModuleRoot: "apps/api"}}
	g, registry := npmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})

	applyImportedPackageSeeds(model.AnalyzeRequest{Graph: g, Registry: registry},
		model.NewRootAttributor([]string{root}, g), root, nil, false, time.Time{})

	r := npmReachability(t, registry, dep.PackageRef)
	if r == nil || len(r.Evidence) == 0 {
		t.Fatal("evidence was dropped for a root vocabulary mismatch; the finding is lost")
	}
	if got := r.Evidence[0].DependencyRefs; len(got) != 0 {
		t.Errorf("refs = %v, want none: nothing established this occurrence", got)
	}
}

// TestAttributorCalibratesOnOverlap pins the calibration on its own, so both
// halves of the rule hold independently of a full analysis pass.
func TestAttributorCalibratesOnOverlap(t *testing.T) {
	node := npmNodeAt(t, "lodash", "4.17.21", "", "/ws/api")
	node.Locations = []model.PackageLocation{{ModuleRoot: "/ws/api"}}
	g := model.New()
	if err := g.AddNode(node); err != nil {
		t.Fatal(err)
	}

	shared := model.NewRootAttributor([]string{"/ws/api", "/ws/web"}, g)
	if got := shared.Attribute(node, "/ws/api"); got != model.AttributedToSite {
		t.Errorf("attribute(own root) = %v, want attributed-to-site", got)
	}
	if got := shared.Attribute(node, "/ws/web"); got != model.AttributedElsewhere {
		t.Errorf("attribute(other root) = %v, want attributed-elsewhere", got)
	}

	foreign := model.NewRootAttributor([]string{"/other/one"}, g)
	if got := foreign.Attribute(node, "/other/one"); got != model.AttributedToRootOnly {
		t.Errorf("attribute under a foreign vocabulary = %v, want attributed-to-root-only", got)
	}
}
