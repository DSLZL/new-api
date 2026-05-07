package service

import (
	"testing"

	"github.com/QuantumNous/new-api/model"
)

func TestShouldLogTaskPollingRound(t *testing.T) {
	if shouldLogTaskPollingRound(nil) {
		t.Fatalf("expected no polling logs when there are no pending tasks")
	}

	if shouldLogTaskPollingRound([]*model.Task{}) {
		t.Fatalf("expected no polling logs for empty pending task list")
	}

	if !shouldLogTaskPollingRound([]*model.Task{{TaskID: "task-1"}}) {
		t.Fatalf("expected polling logs when pending tasks exist")
	}
}
