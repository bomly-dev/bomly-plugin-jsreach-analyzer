package plugin

import (
	"context"

	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Module returns the jsreach analyzer as an execution-neutral sdk.Module.
// The Bomly CLI embeds the same analyzer in its full build; this repository
// also serves the module as a managed plugin binary (cmd/bomly-plugin-jsreach-analyzer)
// via sdk.ServeModule.
func Module() sdkplugin.Module {
	return sdkplugin.Module{Kind: sdkplugin.PluginKindAnalyzer, Analyzer: &sdkplugin.AnalyzerModule{
		Descriptor: Analyzer{}.Descriptor(),
		New: func(_ context.Context, host sdkplugin.HostContext) (sdkplugin.Analyzer, error) {
			return Analyzer{Logger: host.Logger()}, nil
		},
	}}
}
