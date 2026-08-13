// Command bomly-plugin-jsreach-analyzer serves the jsreach reachability
// analyzer as a managed Bomly plugin over the HashiCorp go-plugin gRPC
// transport. The binary is launched and supervised by Bomly; it is not
// meant to be run by hand.
package main

import (
	sdk "github.com/bomly-dev/bomly-sdk"

	plugin "github.com/bomly-dev/bomly-plugin-jsreach-analyzer/plugin"
)

func main() { sdk.ServeModule(plugin.Module()) }
