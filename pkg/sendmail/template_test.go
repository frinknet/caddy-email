package sendmail

import "testing"

func TestEnqueuerOfRejectsWrongType(t *testing.T) {
	// Must return an error rather than panic on the type assertion.
	if _, err := enqueuerOf(struct{ Name string }{"not an enqueuer"}); err == nil {
		t.Fatal("expected error for app that does not implement shared.Enqueuer")
	}
	if _, err := enqueuerOf(nil); err == nil {
		t.Fatal("expected error for nil app")
	}
}

func TestEnqueuerOfAcceptsEnqueuer(t *testing.T) {
	enq, err := enqueuerOf(fakeEnqueuer{id: "q1"})
	if err != nil {
		t.Fatalf("enqueuerOf: %v", err)
	}
	id, err := enq.Enqueue(nil, nil, nil)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id != "q1" {
		t.Errorf("expected q1, got %q", id)
	}
}
