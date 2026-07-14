# HANDOFF.md — append-only. One block per completed task.
# Format: Did / Verified (paste test output) / Broken / The ONE thing the next person must know.
### [S1] dashboard shell + mock alerts — DONE
Did: created mock_alerts.py (20 alerts, seed 42), rewrote app.py as SOC dashboard, fixed midnight-wrap bug in timelines, fixed cache staleness.
Verified: 0/20 out-of-order timelines, 3 hndl_flag=true, VERDICT PASS from Fable 5.
Broken: alert detail view needs selectbox click not row click (expected, not a bug).
ONE THING: mtime param in load_alerts() is intentional cache-busting — do not rename it with underscore prefix.