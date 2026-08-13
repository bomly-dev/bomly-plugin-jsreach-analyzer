# bomly-plugin-jsreach-analyzer

JavaScript/TypeScript reachability analyzer for [Bomly](https://github.com/bomly-dev/bomly-cli).

It discovers your package entry points (`main`, `module`, `exports`, `bin`,
workspaces from npm/pnpm/yarn manifests), builds a static import graph with
[esbuild](https://esbuild.github.io/), and annotates the vulnerabilities Bomly
already found with package-tier reachability: whether the vulnerable npm
package is actually imported from your entry points. Results are cached on
disk under `~/.cache/bomly/analyze/jsreach/` (24h TTL).

> **Safety note:** "unreachable" at any tier means the analysis found no path,
> not that the vulnerability is safe to ignore. Use reachability to prioritize,
> not to dismiss.

## Coverage

- **Ecosystem:** npm (npm, pnpm, Yarn workspaces)
- **Languages:** JavaScript, TypeScript
- **Tiers:** package
- **Requires:** nothing besides the sources — esbuild is embedded

## Embedded in the CLI

The Bomly CLI ships this same analyzer built in — `bomly scan --analyze` uses
it without installing anything. This repository packages the identical module
as a standalone managed plugin, for lite builds and for hosts that load
analyzers as external plugins.

## Install

Download the archive for your platform from the
[releases page](https://github.com/bomly-dev/bomly-plugin-jsreach-analyzer/releases), then:

```sh
bomly plugin install ./bomly-plugin-jsreach-analyzer_<version>_<os>_<arch>.tar.gz
bomly plugin enable jsreach
bomly scan --enrich --analyze
```

## Configuration

The analyzer has no configuration keys. Reachability is switched on with the
host's `--analyze` flag (or the matching config key); caching is on by default
and lives under `~/.cache/bomly/analyze/jsreach/` with a 24-hour TTL.

## Local development

```sh
go build -o bin/bomly-plugin-jsreach-analyzer ./cmd/bomly-plugin-jsreach-analyzer

# Install the dev build into Bomly and scan
bomly plugin install ./bin/bomly-plugin-jsreach-analyzer --dev
bomly plugin enable jsreach
bomly scan --enrich --analyze
```

Run the tests (unit + SDK conformance + a real gRPC handshake probe):

```sh
go test ./...
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
