package plugin

import (
	"context"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// Module returns the jsreach analyzer as an execution-neutral sdk.Module.
// The Bomly CLI embeds the same analyzer in its full build; this repository
// also serves the module as a managed plugin binary (cmd/bomly-plugin-jsreach-analyzer)
// via sdk.ServeModule.
func Module() sdk.Module {
	return sdk.Module{Kind: sdk.PluginKindAnalyzer, Analyzer: &sdk.AnalyzerModule{
		Descriptor: Analyzer{}.Descriptor(),
		New: func(_ context.Context, host sdk.HostContext) (sdk.Analyzer, error) {
			return Analyzer{Logger: host.Logger()}, nil
		},
	}}
}
