package scheduler

import "testing"

func TestParallelPhaseDoesNotCrossDependencyBarrier(t *testing.T) {
	modules := []string{ModuleJSAnalysis, ModuleJSEndpoints, ModuleParamDiscovery, ModuleXSS, ModuleVerify}
	groups := map[string]int{ModuleJSAnalysis: 1, ModuleParamDiscovery: 1}
	got := parallelPhaseIndices(modules, 0, groups, nil)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("param discovery started before JS endpoint barrier: %v", got)
	}
	adjacent := []string{ModuleDirDiscovery, ModuleBackupDiscovery, ModuleXSS}
	got = parallelPhaseIndices(adjacent, 0, map[string]int{ModuleDirDiscovery: 3, ModuleBackupDiscovery: 3}, nil)
	if len(got) != 2 {
		t.Fatalf("independent adjacent phases lost parallelism: %v", got)
	}
}
