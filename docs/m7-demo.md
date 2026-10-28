# M7 checklist: a real nightly run

README section 15, M7 "Done when": *nightly job runs and reports*.

**Already proven in CI:**
- `backend/tests/integration/test_schedules.py`, with the real agent:
  - a succeeded plan is saved as a schedule and approved with a passkey;
  - the scheduler fires the slot, and the agent checks the grant and the slot itself;
  - the run succeeds and is reported (last result, audit, notification);
  - the agent refuses a replayed slot and a slot that isn't now;
  - a failing run stops the schedule and notifies.
- `web/e2e/dashboard.spec.ts`: Save as schedule, approve with the passkey, pause and resume in the browser.
- Cron and grant vectors shared by Python and Go, including the DST days in Copenhagen.

**What only you can check** is one real night on your own setup. It takes 10 min today and a look
tomorrow morning.

## 1. A plan worth repeating

From Claude Code: *"On dev, run `git -C /srv/dev/myapp pull` and `npm test` in /srv/dev/myapp."*
Approve it in the dashboard. ✓ It ends "✓ Succeeded".

## 2. Save it as a schedule

On the plan page: **Save as schedule** → name `nightly-dev-tests`, *Every day at 03:00*, 90 days → **Save
schedule**.
✓ The schedule page opens in "⏸ Awaiting approval", and the Schedules sidebar item shows `1`.

Read the commands. Scroll to the end, then **Approve & sign…** and your passkey.
✓ "Active · Runs every day at 03:00 · next run Tomorrow 03:00".

If you added this passkey after the last signed approver list, sign that pending bundle on the Policy page
first. The agent only accepts a schedule signed by a passkey it already trusts (DECISIONS M7-08).

Want to see a run now instead of at 03:00? Save a second schedule from the same plan with the custom cron
`*/5 * * * *`. Approve it, wait for the next five-minute mark, then delete it.

## 3. The next morning

- Schedules: ✓ `nightly-dev-tests` · last result "✓ Succeeded" and its duration · next run "Tomorrow 03:00".
- Open the run from *Recent runs*. ✓ "Scheduled run of sch_…", with the full output of each step.
- On dev: ✓ `journalctl -u warden-agent` shows the run, and `/var/lib/warden-agent/executed.log` has one
  `sch_…@…Z` line per night. Slots are stored in UTC: 03:00 Copenhagen is 01:00Z in summer and 02:00Z in
  winter.
- `sudo -u warden warden schedule show nightly-dev-tests` lists the run.

## 4. Failure and refusal, once

- Make the test fail on dev (e.g. break a test), and wait for the next run (or use the five-minute copy).
  ✓ The schedule is "■ Stopped" with the failing step, and the Live feed shows it. Fix it and save the
  working plan as a new schedule.
- Run `sudo -u warden warden lockdown`, then wait for a slot. ✓ Last result "○ Missed · lockdown". Lift the
  lockdown afterwards.
