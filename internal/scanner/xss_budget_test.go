package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestXSSBrowserBudgetNeverUnderflowsUnderConcurrency(t *testing.T) {
	b := newXSSBrowserBudget(7)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.take() {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != 7 {
		t.Fatalf("admitted browser work=%d, want exactly 7", got)
	}
	if got := b.remaining.Load(); got != 0 {
		t.Fatalf("remaining browser budget=%d, want 0", got)
	}
}

func TestXSSBrowserBudgetsAreIndependent(t *testing.T) {
	a, b := newXSSBrowserBudget(7), newXSSBrowserBudget(11)
	var wg sync.WaitGroup
	for _, budget := range []*xssBrowserBudget{a, b} {
		wg.Add(1)
		go func(budget *xssBrowserBudget) {
			defer wg.Done()
			for budget.take() {
			}
		}(budget)
	}
	wg.Wait()
	c := newXSSBrowserBudget(150)
	if a.take() || b.take() || !c.take() || c.remaining.Load() != 149 {
		t.Fatal("starting another scan must not replenish an existing scan's budget")
	}
}
