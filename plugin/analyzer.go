package plugin

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"

	model "github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// Name is the analyzer's stable identifier (used in selectors and output).
const Name = "jsreach"

// Analyzer is a Tier-3 (package-level) reachability analyzer for npm
// packages. It groups npm packages in the input graph by project root,
// runs the configured Runner once per project, and annotates each
// registry vulnerability on npm packages with a Reachability result.
//
// Tier-3 caveat: "unreachable" here means "the application source does
// not import this package, neither directly nor indirectly through app
// code". It does NOT mean "the vulnerability cannot be triggered".
// docs/REACHABILITY.md is the authoritative source on this distinction.
type Analyzer struct {
	// Runner is the underlying esbuild driver. Defaults to
	// NewRunner(Logger) when nil.
	Runner Runner
	Logger *zap.Logger
	// CacheDir overrides the default per-project result cache
	// location. Empty means "use the OS user cache directory under
	// bomly/analyzers/jsreach".
	CacheDir string
	// CacheTTL overrides the default 24h cache lifetime. Zero means
	// use the default.
	CacheTTL time.Duration
	// DisableCache turns off the on-disk result cache entirely.
	// Useful in CI smoke runs where freshness matters more than
	// speed.
	DisableCache bool
}

// Descriptor returns the registration metadata for the jsreach analyzer.
func (a Analyzer) Descriptor() model.AnalyzerDescriptor {
	return model.AnalyzerDescriptor{
		Name:                Name,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerNPM, model.PackageManagerPNPM, model.PackageManagerYarn},
		SupportedLanguages:  []model.Language{model.LanguageJavaScript, model.LanguageTypeScript},
		SupportedTiers:      []model.ReachabilityTier{model.TierPackage},
		Capabilities:        []string{model.CapabilityPackageUpdates},
	}
}

// Ready reports whether the analyzer is callable. Always true; the
// runner surfaces missing-toolchain or parser errors at Run time as
// Status=Unknown rather than blocking applicability.
func (a Analyzer) Ready(context.Context, model.AnalyzeRequest) error { return nil }

// Applicable reports whether the request graph contains at least one
// npm package with attached vulnerabilities. Without vulnerabilities
// to annotate, the analyzer would do work without producing output.
func (a Analyzer) Applicable(_ context.Context, req model.AnalyzeRequest) (bool, error) {
	if req.Graph == nil || req.Registry == nil {
		return false, nil
	}
	for _, pkg := range req.Graph.DependencyNodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		regPkg, ok := req.Registry.Get(dependencyPURL(pkg))
		if !ok || regPkg == nil || len(regPkg.Vulnerabilities) == 0 {
			continue
		}
		return true, nil
	}
	return false, nil
}

// dependencyPURL returns the registry key for a dependency node.
func dependencyPURL(dep *model.DependencyNode) string {
	if dep == nil {
		return ""
	}
	if dep.PackageRef != "" {
		return dep.PackageRef
	}
	return dep.NodeID()
}

// vulnerabilitiesForDep returns the registry slice for a dependency. The
// caller may mutate the returned slice in place; entries live on the
// shared backing array owned by the registry package.
func vulnerabilitiesForDep(req model.AnalyzeRequest, dep *model.DependencyNode) []model.Vulnerability {
	if req.Registry == nil || dep == nil {
		return nil
	}
	pkg, ok := req.Registry.Get(dependencyPURL(dep))
	if !ok || pkg == nil {
		return nil
	}
	return pkg.Vulnerabilities
}

// Analyze runs the configured Runner per discovered npm project root
// and writes Reachability onto every npm registry vulnerability in the
// graph. Errors degrade to Status=Unknown with a stable Reason — the
// engine relies on this to keep the pipeline running.
func (a Analyzer) Analyze(ctx context.Context, req model.AnalyzeRequest) (model.AnalyzeResult, error) {
	logger := a.logger()
	if req.Graph == nil {
		return model.AnalyzeResult{}, nil
	}
	runner := a.Runner
	if runner == nil {
		runner = NewRunner(logger)
	}

	overallStart := time.Now()
	hierarchies := discoverWorkspaceHierarchies(req)
	attributor := newRootAttributor(req.Graph, workspaceHierarchyRoots(hierarchies))
	if len(hierarchies) == 0 {
		logger.Info("jsreach: no npm project roots discovered; marking all npm vulnerabilities as unknown")
		annotateAllUnknown(req, "no-project-root-discovered", time.Now())
		return finishResult(req, resultFromRequest(req)), nil
	}

	logger.Info("jsreach: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.String("runner_version", runner.Version()),
		zap.Int("workspace_hierarchies", len(hierarchies)),
		zap.Bool("cache_enabled", !a.DisableCache),
	)
	logger.Debug("jsreach: discovered workspace hierarchies", zap.Strings("paths", workspaceHierarchyRoots(hierarchies)))

	cache := a.cache()
	stats := model.ReachabilityStats{}
	cacheHits, cacheMisses := 0, 0
	for _, hierarchy := range hierarchies {
		root := hierarchy.Root
		select {
		case <-ctx.Done():
			logger.Info("jsreach: context cancelled; skipping project",
				zap.String("project_root", root))
			annotateProjectUnknown(req, attributor, root, "cancelled", time.Now())
			continue
		default:
		}

		projectStart := time.Now()
		closure, hits, misses := a.analyzeWorkspaceHierarchy(ctx, runner, cache, hierarchy, logger)
		cacheHits += hits
		cacheMisses += misses
		var applied applyOutcome
		if closure.incomplete {
			added := annotateProjectUnknown(req, attributor, root, closure.reason, time.Now())
			applied.unknown += added
		} else {
			applied = applyImportedPackageSeeds(req, attributor, root, closure.importedPackages, closure.dynamicImports, time.Now())
		}
		stats.Reachable += applied.reachable
		stats.Unreachable += applied.unreachable
		stats.Unknown += applied.unknown
		logger.Info("jsreach: completed workspace hierarchy",
			zap.String("workspace_root", root),
			zap.String("runner", runner.Name()),
			zap.Int("members", len(hierarchy.Members)),
			zap.Int("cache_hits", hits),
			zap.Int("cache_misses", misses),
			zap.Int("imported_packages", len(closure.importedPackages)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Int("unknown", applied.unknown),
			zap.Duration("duration", time.Since(projectStart)),
		)
	}

	logger.Info("jsreach: completed reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("workspace_hierarchies", len(hierarchies)),
		zap.Int("cache_hits", cacheHits),
		zap.Int("cache_misses", cacheMisses),
		zap.Int("reachable", stats.Reachable),
		zap.Int("unreachable", stats.Unreachable),
		zap.Int("unknown", stats.Unknown),
		zap.Duration("duration", time.Since(overallStart)),
	)

	out := resultFromRequest(req)
	out.AnalyzerStats = map[string]model.ReachabilityStats{Name: stats}
	return finishResult(req, out), nil
}

type workspaceClosure struct {
	importedPackages map[string]int
	dynamicImports   bool
	incomplete       bool
	reason           string
}

func workspaceHierarchyRoots(hierarchies []workspaceHierarchy) []string {
	roots := make([]string, 0, len(hierarchies))
	for _, hierarchy := range hierarchies {
		roots = append(roots, hierarchy.Root)
	}
	return roots
}

func (a Analyzer) analyzeWorkspaceHierarchy(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	hierarchy workspaceHierarchy,
	logger *zap.Logger,
) (workspaceClosure, int, int) {
	results := make(map[string]RunnerResult, len(hierarchy.Members))
	failures := make(map[string]error)
	hits, misses := 0, 0
	for _, member := range hierarchy.Members {
		result, hit, err := a.runWithCache(ctx, runner, cache, member.Dir, logger)
		if err != nil {
			failures[member.Dir] = err
			logger.Warn("jsreach: workspace member runner failed",
				zap.String("workspace_root", hierarchy.Root),
				zap.String("member", member.Dir),
				zap.Error(err))
			continue
		}
		if hit {
			hits++
		} else {
			misses++
		}
		results[member.Dir] = result
	}
	if len(hierarchy.Members) == 1 {
		member := hierarchy.Members[0]
		if err := failures[member.Dir]; err != nil {
			return workspaceClosure{incomplete: true, reason: failureReason(err)}, hits, misses
		}
		result := results[member.Dir]
		return workspaceClosure{
			importedPackages: packageSeedDepths(result.ImportedPackages, 0),
			dynamicImports:   result.DynamicImportsDetected,
		}, hits, misses
	}

	byName := make(map[string]workspaceMember, len(hierarchy.Members))
	for _, member := range hierarchy.Members {
		if member.Name != "" {
			byName[member.Name] = member
		}
	}
	edges := make(map[string][]string)
	incoming := make(map[string]int)
	for _, member := range hierarchy.Members {
		for imported := range results[member.Dir].ImportedPackages {
			target, ok := byName[imported]
			if !ok || target.Dir == member.Dir {
				continue
			}
			edges[member.Dir] = append(edges[member.Dir], target.Dir)
			incoming[target.Dir]++
		}
		sort.Strings(edges[member.Dir])
	}
	var roots []string
	if result, ok := results[hierarchy.Root]; ok && result.hasResult() {
		roots = append(roots, hierarchy.Root)
	} else {
		for _, member := range hierarchy.Members {
			if incoming[member.Dir] == 0 && results[member.Dir].hasResult() {
				roots = append(roots, member.Dir)
			}
		}
	}
	if len(roots) == 0 {
		for _, member := range hierarchy.Members {
			if results[member.Dir].hasResult() {
				roots = append(roots, member.Dir)
			}
		}
	}
	sort.Strings(roots)
	closure := workspaceClosure{importedPackages: make(map[string]int)}
	depths := make(map[string]int)
	queue := append([]string(nil), roots...)
	for _, root := range roots {
		depths[root] = 0
	}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		depth := depths[dir]
		result := results[dir]
		closure.dynamicImports = closure.dynamicImports || result.DynamicImportsDetected
		for imported := range result.ImportedPackages {
			if _, internal := byName[imported]; internal {
				continue
			}
			setMinimumDepth(closure.importedPackages, imported, depth)
		}
		for _, target := range edges[dir] {
			if _, failed := failures[target]; failed {
				closure.incomplete = true
				closure.reason = "workspace-closure-incomplete"
				continue
			}
			if old, seen := depths[target]; seen && old <= depth+1 {
				continue
			}
			depths[target] = depth + 1
			queue = append(queue, target)
		}
	}
	return closure, hits, misses
}

func packageSeedDepths(imports map[string]struct{}, depth int) map[string]int {
	seeds := make(map[string]int, len(imports))
	for imported := range imports {
		seeds[imported] = depth
	}
	return seeds
}

func setMinimumDepth(depths map[string]int, key string, depth int) {
	if old, ok := depths[key]; !ok || depth < old {
		depths[key] = depth
	}
}

func (a Analyzer) logger() *zap.Logger { return ensureLogger(a.Logger) }

// runWithCache returns (result, fromCache, error) for one project.
// Cache failures are non-fatal — the runner still gets a chance to
// produce fresh output. Cache writes after successful runs are also
// non-fatal.
func (a Analyzer) runWithCache(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	projectDir string,
	logger *zap.Logger,
) (RunnerResult, bool, error) {
	if cache != nil {
		if cached, ok := cache.get(projectDir, runner.Name(), runner.Version()); ok {
			logger.Debug("jsreach: cache hit",
				zap.String("project_root", projectDir),
				zap.String("runner", runner.Name()),
				zap.Int("imported_packages", len(cached.ImportedPackages)))
			return cached, true, nil
		}
		logger.Debug("jsreach: cache miss",
			zap.String("project_root", projectDir),
			zap.String("runner", runner.Name()))
	}
	result, err := runner.Run(ctx, projectDir)
	if err != nil {
		return RunnerResult{}, false, err
	}
	if cache != nil {
		if err := cache.set(projectDir, runner.Name(), runner.Version(), result); err != nil {
			logger.Warn("jsreach: cache write failed (non-fatal)",
				zap.String("project_root", projectDir),
				zap.Error(err))
		}
	}
	return result, false, nil
}

// cache returns the configured result cache, or nil when caching is
// disabled. Cache construction errors are swallowed deliberately —
// they degrade to "no cache" rather than failing the analyzer.
func (a Analyzer) cache() *resultCache {
	if a.DisableCache {
		return nil
	}
	return newResultCache(a.CacheDir, a.CacheTTL, a.logger())
}

func resultFromRequest(req model.AnalyzeRequest) model.AnalyzeResult {
	return model.AnalyzeResult{Registry: req.Registry, AnalyzerRuns: []string{Name}}
}

// applyOutcome reports per-vuln Reachability outcomes for telemetry.
type applyOutcome struct {
	reachable, unreachable, unknown int
}

// applyRunnerResult annotates every npm vulnerability whose owning
// package is attributable to projectRoot. A package is "reachable" iff
// it is in the transitive closure of the runner's bare-specifier
// import set walked through the dep graph; otherwise it is marked
// Unreachable at TierPackage.
//
// The transitive closure is essential — esbuild stops at every bare
// specifier (PackagesExternal), so the runner's import set only
// captures packages directly imported from app source. A CVE in a
// transitive dep (e.g. body-parser pulled in by express) would be
// missed otherwise. The closure follows Graph.Dependencies edges, so
// it sees exactly the dep tree the npm detector resolved from the
// lockfile.
func applyRunnerResult(req model.AnalyzeRequest, attributor rootAttributor, projectRoot string, runRes RunnerResult, now time.Time) applyOutcome {
	return applyImportedPackageSeeds(req, attributor, projectRoot, packageSeedDepths(runRes.ImportedPackages, 0), runRes.DynamicImportsDetected, now)
}

func applyImportedPackageSeeds(req model.AnalyzeRequest, attributor rootAttributor, projectRoot string, imports map[string]int, dynamicImports bool, now time.Time) applyOutcome {
	var outcome applyOutcome
	if req.Graph == nil {
		return outcome
	}
	timestamp := now.UTC().Format(time.RFC3339)
	hopsByID := computeReachablePackageHopsFromSeeds(req.Graph, imports)
	for _, pkg := range req.Graph.DependencyNodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		attributed := attributor.attribute(pkg, projectRoot)
		if attributed == attributedElsewhere {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
		for i := range vulns {
			vuln := &vulns[i]
			// No skip on an earlier project pass. That skip was the loss
			// phase 2.8 removes: a workspace's second project can import a
			// package the first does not, and the first answer stood. Each
			// project root now contributes evidence and the annotation is
			// the derived summary over all of them.
			r := &model.ReachabilityEvidence{
				ModuleRoot:             projectRoot,
				Analyzer:               Name,
				AnalyzedAt:             timestamp,
				Tier:                   model.TierPackage,
				DynamicImportsDetected: dynamicImports,
			}
			if attributed == attributedToSite {
				// Named only when a site put this copy in this root. The hop
				// map is keyed by node ID, so a nested node_modules copy and
				// a hoisted one are separately decided -- but only a site can
				// say which root a copy is installed under, and without one
				// the module root is the whole claim.
				r.DependencyRefs = []string{pkg.NodeID()}
			}
			if hops, ok := hopsByID[pkg.NodeID()]; ok {
				r.Status = model.ReachabilityReachable
				h := hops
				r.Hops = &h
				r.Confidence = model.DeriveConfidence(&h, dynamicImports)
				outcome.reachable++
			} else {
				r.Status = model.ReachabilityUnreachable
				r.Reason = "package-not-imported"
				outcome.unreachable++
			}
			vuln.Reachability = withEvidence(vuln.Reachability, *r, timestamp)
		}
	}
	return outcome
}

// withEvidence appends one project root's finding to a vulnerability's
// reachability record and recomputes the summary.
//
// The summary is derived, never accumulated by hand: reachable anywhere wins,
// and unreachable requires every root to say so. Writing that rule at each
// call site is how the first-root-wins behaviour got there.
func withEvidence(current *model.Reachability, evidence model.ReachabilityEvidence, timestamp string) *model.Reachability {
	var all []model.ReachabilityEvidence
	if current != nil && current.Analyzer == Name {
		all = current.Evidence
	}
	all = append(all, evidence)
	summary := model.DeriveReachability(all)
	summary.Analyzer = Name
	summary.AnalyzedAt = timestamp
	summary.Evidence = all
	return &summary
}

// computeReachablePackageHops returns a map from graph package ID to
// the shortest dep-graph distance from any directly-imported package.
// The seed set (hop 0) is every npm package whose name (or qualified
// scoped name) matches a bare specifier in imports; the expansion
// walks Graph.Dependencies edges breadth-first.
//
// The result is keyed by package ID rather than name because npm
// allows multiple versions of the same package to coexist (a top-
// level lodash@4 and a nested lodash@3 inside some dep), and the
// lockfile-derived graph captures that. Working in IDs keeps the
// attribution honest.
func computeReachablePackageHops(g *model.Graph, imports map[string]struct{}) map[string]int {
	return computeReachablePackageHopsFromSeeds(g, packageSeedDepths(imports, 0))
}

func computeReachablePackageHopsFromSeeds(g *model.Graph, imports map[string]int) map[string]int {
	hops := make(map[string]int)
	if g == nil || len(imports) == 0 {
		return hops
	}
	queue := make([]string, 0)
	// Seed: every npm package whose name matches the import set.
	for _, pkg := range g.DependencyNodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		if !isPackageImported(pkg, imports) {
			continue
		}
		if _, ok := hops[pkg.NodeID()]; ok {
			continue
		}
		hops[pkg.NodeID()] = importedPackageDepth(pkg, imports)
		queue = append(queue, pkg.NodeID())
	}
	// BFS: every dep edge from a reachable package adds its target at
	// hop+1 if it has not been seen yet (shortest-distance wins).
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		current := hops[id]
		deps, err := g.DirectDependencies(id)
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			if _, ok := hops[dep.NodeID()]; ok {
				continue
			}
			hops[dep.NodeID()] = current + 1
			queue = append(queue, dep.NodeID())
		}
	}
	return hops
}

func importedPackageDepth(pkg *model.DependencyNode, imports map[string]int) int {
	if depth, ok := imports[importSpecifier(pkg)]; ok {
		return depth
	}
	return 0
}

// isPackageImported reports whether pkg's npm name appears in the runner's
// bare-specifier import set. Used as the seed predicate for the transitive
// walk.
func isPackageImported(pkg *model.DependencyNode, imports map[string]int) bool {
	if pkg == nil || len(imports) == 0 {
		return false
	}
	specifier := importSpecifier(pkg)
	if specifier == "" {
		return false
	}
	_, ok := imports[specifier]
	return ok
}

// importSpecifier returns the bare specifier a source file would import pkg
// by. It must be the ecosystem-native name: the bare Name drops the scope, so
// "@tailwindcss/postcss" would be seeded as reachable by any `import "postcss"`
// in the project, and QualifiedName's "tailwindcss:postcss" is not a specifier
// any module resolver ever produces.
func importSpecifier(pkg *model.DependencyNode) string {
	if pkg == nil {
		return ""
	}
	return strings.TrimSpace(pkg.EcosystemName())
}

// annotateProjectUnknown records that one project root could not be analyzed.
//
// It deliberately does not skip a vulnerability another root already
// annotated. That skip was the same first-root-wins loss phase 2.8 removes,
// left standing in the failure path: with roots A and B, A succeeding with
// "unreachable" and B failing to resolve its entry points, the skip dropped B
// entirely and the summary read "unreachable" for a workspace half of which
// was never looked at. DeriveReachability requires every root to say
// unreachable, so B's unknown is exactly what keeps the aggregate honest --
// but only if it is recorded.
func annotateProjectUnknown(req model.AnalyzeRequest, attributor rootAttributor, projectRoot, reason string, now time.Time) int {
	if req.Graph == nil {
		return 0
	}
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, pkg := range req.Graph.DependencyNodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		if attributor.attribute(pkg, projectRoot) == attributedElsewhere {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
		for i := range vulns {
			vulns[i].Reachability = withEvidence(vulns[i].Reachability, model.ReachabilityEvidence{
				ModuleRoot: projectRoot,
				Analyzer:   Name,
				Status:     model.ReachabilityUnknown,
				Tier:       model.TierNone,
				Reason:     reason,
				AnalyzedAt: timestamp,
			}, timestamp)
			count++
		}
	}
	return count
}

func annotateAllUnknown(req model.AnalyzeRequest, reason string, now time.Time) {
	if req.Graph == nil {
		return
	}
	timestamp := now.UTC().Format(time.RFC3339)
	for _, pkg := range req.Graph.DependencyNodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
		for i := range vulns {
			// One evidence record with no module root, which the SDK reads as
			// a whole-scan claim covering every site. A bare annotation would
			// leave consumers unable to tell an empty evidence list meaning
			// "nothing was recorded" from one meaning "no root was found".
			vulns[i].Reachability = withEvidence(vulns[i].Reachability, model.ReachabilityEvidence{
				Analyzer:   Name,
				Status:     model.ReachabilityUnknown,
				Tier:       model.TierNone,
				Reason:     reason,
				AnalyzedAt: timestamp,
			}, timestamp)
		}
	}
}

func pathContainsRoot(path, root string) bool {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// failureReason maps runner errors to stable machine-readable codes.
// Mirrors govulncheck.failureReason so consumers can lump the two
// analyzers together when filtering / grouping.
func failureReason(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not implemented"), strings.Contains(msg, "not on path"), strings.Contains(msg, "not found"):
		return "missing-toolchain"
	case strings.Contains(msg, "no resolvable entry points"), strings.Contains(msg, "package.json not found"):
		return "no-entry-points"
	case strings.Contains(msg, "context"), strings.Contains(msg, "cancel"):
		return "cancelled"
	default:
		return "runner-error"
	}
}

// finishResult applies the package-updates delta protocol to out. When the
// host accepts deltas (req.AcceptPackageUpdates), the analyzer returns only
// the registry packages it annotated instead of the full registry; the host
// folds them back in with sdk.ApplyPackageUpdates. The annotation this
// analyzer writes -- filling Vulnerability.Reachability on existing
// (Source, ID)-keyed vulnerabilities that had none -- is exactly what the
// host-side merge (Package.MergeFrom) expresses, so the delta path is
// equivalent to the legacy in-place path. The one in-place behavior the merge
// cannot express is replacing a Reachability annotation already written by a
// DIFFERENT analyzer; built-in analyzer dispatch is language-disjoint, so no
// two built-ins annotate the same package.
func finishResult(req model.AnalyzeRequest, out model.AnalyzeResult) model.AnalyzeResult {
	if !req.AcceptPackageUpdates || req.Registry == nil {
		return out
	}
	out.Registry = nil
	for _, pkg := range req.Registry.All() {
		if pkg == nil {
			continue
		}
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.Reachability != nil && vuln.Reachability.Analyzer == Name {
				out.PackageUpdates = append(out.PackageUpdates, pkg)
				break
			}
		}
	}
	return out
}
