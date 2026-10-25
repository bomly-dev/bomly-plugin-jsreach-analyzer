# bomly-plugin-jsreach-analyzer

JavaScript/TypeScript reachability analyzer for [Bomly](https://github.com/bomly-dev/bomly-cli).

It discovers your package entry points (`main`, `module`, `exports`, `bin`,
workspaces from npm/pnpm/yarn manifests), builds a static import graph with
[esbuild](https://esbuild.github.io/), and annotates the vulnerabilities Bomly
already found with package-tier reachability: whether the vulnerable npm
package is actually imported from your entry points. Results are cached on
disk under `<user cache dir>/bomly/analyzers/jsreach/` (24h TTL).

> **Safety note:** "unreachable" at any tier means the analysis found no path,
> not that the vulnerability is safe to ignore. Use reachability to prioritize,
> not to dismiss.

## Coverage

- **Ecosystem:** npm (npm, pnpm, Yarn workspaces)
- **Languages:** JavaScript, TypeScript
- **Tiers:** package
- **Requires:** nothing besides the sources — esbuild is embedded. The analyzer declares the pipeline data it needs -- a source tree, a dependency graph, and vulnerability records from a matcher -- so Bomly skips it, with a warning, when a scan cannot supply them.

## Access

`bomly-plugin.json` declares what the analyzer touches, which Bomly shows before you enable it. It is a disclosure, not a sandbox. esbuild runs in-process with output writing off, so the analyzer starts no processes and makes no network calls.

| Access | Why |
| --- | --- |
| Reads `project` | `package.json`, lockfiles, workspace manifests and the sources esbuild walks from your entry points. Like Node and TypeScript, esbuild also consults `package.json` and `tsconfig.json` in the project's parent directories |
| Reads and writes `cache` | The result cache under `<user cache dir>/bomly/analyzers/jsreach/` |
| Environment `HOME`, `XDG_CACHE_HOME`, `LocalAppData` | Locating the user cache directory (`os.UserCacheDir`: `XDG_CACHE_HOME` or `HOME` on Linux, `HOME` on macOS, `LocalAppData` on Windows) |
| Environment `NO_COLOR` | esbuild's logger checks it when deciding whether to colour terminal output; its log level is silent, so nothing is printed |

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
and lives under `<user cache dir>/bomly/analyzers/jsreach/` with a 24-hour TTL.

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
