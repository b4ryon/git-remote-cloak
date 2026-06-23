// Unit test for the per-remote invocation lock: a second acquirer must not
// proceed while the lock is held, and must proceed once it is released. This
// exercises the flock mechanism that serializes concurrent cloak invocations
// (helper and CLI) for a remote; cross-process exclusion relies on the same
// per-open-file-description lock that two descriptors here contend for.
package state

import (
	"testing"
	"time"
)

func TestLockExcludesSecondAcquirer(t *testing.T) {
	d := &Dir{Root: t.TempDir()}

	release1, err := d.Lock()
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	acquired := make(chan func() error, 1)
	go func() {
		release2, err := d.Lock()
		if err != nil {
			return
		}
		acquired <- release2
	}()

	select {
	case <-acquired:
		t.Fatal("second Lock acquired while the first was still held")
	case <-time.After(250 * time.Millisecond):
		// Expected: the second acquirer is still blocked.
	}

	if err := release1(); err != nil {
		t.Fatalf("releasing first lock: %v", err)
	}

	select {
	case release2 := <-acquired:
		if err := release2(); err != nil {
			t.Fatalf("releasing second lock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Lock did not acquire after the first was released")
	}
}
