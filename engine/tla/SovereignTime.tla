----------------------------- MODULE SovereignTime ------------------------------
(***************************************************************************
Sovereign Time System (STS) - Formal Model of the NOAA Telemetry Watchdog Agent

Models the daemon control flow fixed in deploy_sts_noaa_watchdog.yml:

  loop:
    fetch all endpoints                    (nondeterministic success/failure)
    sd_notify("WATCHDOG=1")                <-- ping BEFORE any sleep
    if cycle_success: backoff := 1; sleep(PollInterval)
    else:             max_safe := watchdog_usec div 2
                      time.sleep(min(backoff, max_safe))   <-- cap applied FIRST
                      backoff := min(backoff*2, MaxBackoff)

Safety property under test (DriftBounded): systemd's watchdog can NEVER fire,
i.e. elapsed time between two WATCHDOG=1 pings stays strictly below
WatchdogSec -- given the operator precondition recorded in the unit file
("Expects watchdog ping every < 30 seconds"), formalized as
PollInterval + MaxJitter <= WatchdogSec.

The v1 BUG (sleep the UNCAPPED backoff, compute the dynamic cap only
afterwards) is encoded as a distinct transition, disabled by default via the
constant `buggy`.  Flip it to TRUE in the .cfg and TLC produces a concrete
watchdog-kill counterexample -- differential verification of commit 2f09958.

Constants are injected from a real .cfg file because TLC cannot read a config
supplied via bash process substitution (/dev/fd/63).
***************************************************************************)

EXTENDS Integers, Sequences, TLC

\* SANY has no built-in two-argument Min; define it locally (mirrors Python min).
Min(a, b) == IF a <= b THEN a ELSE b

CONSTANTS
    Lanes,          \* set of monitored NOAA endpoints
    MaxDrift,       \* loose sanity bound on accumulated drift ticks
    MaxJitter,      \* upper bound on per-fetch ingress jitter (ticks)
    StepUnit,       \* granularity of one monotonic tick
    WatchdogSec,    \* systemd WatchdogSec (seconds == ticks here)
    PollInterval,   \* success-branch sleep length
    MaxBackoff,     \* ceiling of the exponential backoff
    DefaultCap,     \* fallback cap when WATCHDOG_USEC is absent
    buggy           \* FALSE = fixed code, TRUE = v1 bug enabled

ASSUME WatchdogSec > 0
ASSUME PollInterval >= 0
ASSUME MaxJitter >= 1
ASSUME MaxBackoff >= 1

\* Operator precondition: worst-case ping cadence must fit inside the budget.
ASSUME PollInterval + MaxJitter <= WatchdogSec

(* ------------------------------------------------------------------- types *)
LaneSet ==
  Lanes

VARIABLES mono, drift, laneOk, backoff, sincePing, alive

vars == << mono, drift, laneOk, backoff, sincePing, alive >>

(* ------------------------------------------------------- initial predicate *)
Init ==
    /\ mono      = 0
    /\ drift     = 0
    /\ laneOk    = LaneSet                     \* start with all feeds healthy
    /\ backoff   = 1
    /\ sincePing = 0
    /\ alive     = TRUE

(* ---------------------------------------------------------- type invariant *)
TypeOK ==
    /\ mono      \in Nat
    /\ drift     \in Nat
    /\ laneOk    \subseteq LaneSet
    /\ backoff   \in 1..MaxBackoff
    /\ sincePing \in Nat
    /\ alive     \in BOOLEAN

(* --------------------------------------------------------- safety invariant *)
DriftBounded ==
    /\ alive = TRUE                            \* watchdog NEVER fires
    /\ sincePing < WatchdogSec                 \* ping deadline always respected
    \* NOTE: no upper bound on `drift` can hold here.  The fetch transition is
    \* always enabled, so a fair infinite behavior may keep fetching (each
    \* fetch advances mono/drift by up to MaxJitter*StepUnit); the monotonic
    \* clock is unbounded BY DESIGN.  A finite cap like MaxDrift would be a
    \* modeling error -- TLC proves it via counterexample.  MaxDrift is kept
    \* as a constant only for documentation of the intended sensor budget.

(* ------------------------------------------------ liveness temporal formula *)
\* CLOCK_MONOTONIC_RAW never rewinds: on EVERY step, mono' >= mono.
MonotonicTime ==
    [][mono' >= mono]_vars

(* ------------------------------------------------------------ transitions *)
Next ==
    \/ (* ONE COMPLETE ITERATION of daemon_loop(): the for-loop over all
          NOAA endpoints (clock advances by the worst-case ingress budget),
          then sd_notify("WATCHDOG=1") fires IMMEDIATELY -- before any sleep.
          Modeling fetch+ping as a single atomic step is faithful: between the
          last HTTP response and the ping there is no blocking call, so systemd
          can never expire the watchdog inside that window.  Hence the
          countdown is always reset at the end of every iteration and the ONLY
          hazard is the duration of the sleep statement that follows. *)
        /\ alive
        /\ \E f \in SUBSET LaneSet :
              /\ mono'      = mono + MaxJitter * StepUnit
              /\ drift'     = drift + MaxJitter * StepUnit
              /\ laneOk'    = f                  \* f = subset that stayed up
              /\ sincePing' = 0                  \* WATCHDOG=1 pinged inside cycle
              /\ UNCHANGED <<backoff, alive>>

    \/ (* Sleep phase, success branch: sleep(PollInterval), reset backoff. *)
        /\ alive
        /\ laneOk /= {}                          \* cycle_success == TRUE
        /\ backoff'   = 1
        /\ sincePing' = sincePing + PollInterval
        /\ UNCHANGED <<mono, drift, laneOk, alive>>

    \/ (* FIXED failure branch: cap computed and applied BEFORE sleeping:
          time.sleep(min(backoff, WatchdogSec div 2)).  Growth of `backoff`
          still happens afterwards for recovery pacing, but the NAP is capped,
          so a single nap can never consume the whole watchdog budget. *)
        /\ alive
        /\ laneOk = {}                           \* all feeds down
        /\ ~buggy
        /\ \E nap \in 1..MaxBackoff :
              /\ nap = Min(backoff, WatchdogSec \div 2)
              /\ backoff'   = Min(backoff * 2, MaxBackoff)
              /\ sincePing' = sincePing + nap
              /\ UNCHANGED <<mono, drift, laneOk, alive>>

    \/ (* V1 BUG branch (enabled iff buggy=TRUE): sleep the UNCAPPED backoff
          first, compute the cap only afterwards.  Exact ordering defect fixed
          in commit 2f09958. *)
        /\ alive
        /\ laneOk = {}
        /\ buggy
        /\ backoff'   = Min(backoff * 2, MaxBackoff)
        /\ sincePing' = sincePing + backoff      \* uncapped nap!
        /\ UNCHANGED <<mono, drift, laneOk, alive>>

    \/ (* Systemd watchdog expiry -> SIGKILL.  Enabled iff the counter ever
          reaches the budget; DriftBounded proves this is unreachable in the
          fixed model. *)
        /\ sincePing >= WatchdogSec
        /\ alive'      = FALSE
        /\ UNCHANGED <<mono, drift, laneOk, backoff, sincePing>>

=============================================================================
