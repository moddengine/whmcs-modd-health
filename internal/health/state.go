package health

import "time"

func ApplyObservation(previous StoredState, healthy bool, now time.Time) Transition {
	observed := "failed"
	if healthy {
		observed = "healthy"
	}
	next := previous
	if next.Stable == "" {
		next.Stable = "unknown"
	}
	if previous.Observed == observed {
		next.Consecutive++
	} else {
		next.Consecutive = 1
	}
	next.Observed = observed

	if healthy {
		switch next.Stable {
		case "unknown", "healthy":
			next.Stable = "healthy"
			next.FirstFailureAt = nil
			next.ConfirmedFailureAt = nil
		case "failed":
			if next.Consecutive >= 2 {
				next.Stable = "healthy"
				next.FirstFailureAt = nil
				next.ConfirmedFailureAt = nil
				next.PendingNotification = "recovery"
				return Transition{State: next, Notification: "recovery", Changed: true}
			}
		}
		return Transition{State: next}
	}

	if next.FirstFailureAt == nil {
		first := now.UTC()
		next.FirstFailureAt = &first
	}
	if next.PendingNotification == "recovery" {
		next.PendingNotification = ""
	}
	if next.Stable != "failed" && next.Consecutive >= 2 {
		confirmed := now.UTC()
		next.Stable = "failed"
		next.ConfirmedFailureAt = &confirmed
		next.PendingNotification = "failure"
		return Transition{State: next, Notification: "failure", Changed: true}
	}
	return Transition{State: next}
}
