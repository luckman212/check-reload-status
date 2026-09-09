## Summary

This change hardens `check_reload_status` against FastCGI transport failures and rapid/transient interface events, and adds explicit convergence handling for gateway monitoring after WAN/interface recovery.

The primary goals are to:

* make FastCGI request/response handling safe with non-blocking sockets
* avoid replaying transient interface events when execution state is ambiguous
* serialize and coalesce `rc.linkup`, `rc.newwanip`, and `rc.newwanipv6` processing per interface
* prevent event storms or PHP-FPM outages from causing unbounded queue growth or tight retry loops
* ensure gateway monitoring converges after dependent interfaces have completely settled

The overall change converts transient interface handling from a collection of independently queued edge-triggered PHP executions into a serialized, state-oriented convergence mechanism.

Under normal conditions the externally visible behavior remains equivalent: interface events still invoke the existing pfSense rc scripts through PHP-FPM.

Under link flapping, PHP-FPM delays/failures, lost FastCGI responses, or overlapping IPv4/IPv6 interface transitions, however, the daemon now favors the newest known interface state, prevents unsafe concurrent replay, bounds resource consumption, and performs a final gateway-monitor convergence pass once recovery has settled.

### FastCGI transport and lifecycle fixes

The FastCGI path has been reworked to track request lifecycle explicitly instead of using the previous `dontexec`/timeout behavior as an implicit completion mechanism.

FastCGI requests now:

* use a fresh FastCGI connection for each execution
* use request IDs in the valid 1–65535 range and wrap safely rather than allowing the integer counter to grow indefinitely
* distinguish requests which have actually been submitted from requests which failed before submission
* detect short writes instead of treating any non-negative `write(2)` return value as successful submission
* use exponential retry backoff for failures where replay is known to be safe
* track aggregate reruns explicitly using `rerun_pending`, allowing one additional execution to be scheduled after the current request completes instead of racing the outstanding request

The response reader has also been rewritten as a persistent non-blocking FastCGI record parser. It now handles:

* partial FastCGI headers
* partial response bodies
* multiple records arriving in one socket activation
* records larger than the previous fixed 4096-byte receive buffer
* FastCGI record padding
* `EAGAIN`, `EWOULDBLOCK`, and interrupted reads without losing parser state
* request-ID validation so a stale/foreign response cannot complete the wrong queued request
* malformed `FCGI_END_REQUEST` records
* premature connection close
* explicit `FCGI_ABORT_REQUEST` and non-success protocol status results

Response timeout handling is now an inactivity timeout owned by the FastCGI socket event and re-armed as response progress is made. This avoids treating a slow but active PHP request as failed merely because its total execution time exceeds a fixed deadline.

Request construction is hardened as well, including bounds checking of the FastCGI parameter block and `REQUEST_URI`, validation of the generated request size, and explicit handling of parameter-buffer failures.

### Safe handling of ambiguous FastCGI failures

A major behavioral change is the distinction between failures which occur before a request is completely submitted and failures which occur afterwards.

Before submission, replay is safe and the command is retried with exponential backoff.

After submission, a timeout or lost connection is fundamentally ambiguous: PHP-FPM may never have executed the request, may still be executing it, or may already have completed it.

Blindly replaying state-transition scripts in this condition can cause an older `rc.linkup`, `rc.newwanip`, or similar operation to execute concurrently with a newer interface transition. This can result in stale state being reapplied and gateway monitoring repeatedly being torn down/recreated.

The new code therefore treats submitted transient events specially rather than immediately replaying them.

### Per-interface serialization and event coalescing

`rc.linkup`, `rc.newwanip`, and `rc.newwanipv6` are now represented by a per-interface state machine.

Only one transient operation for a given interface may be active at a time. Additional events are folded into the existing state machine instead of creating concurrent PHP-FPM jobs.

The state machine implements the following semantics:

* link state is **latest-state-wins**
* repeated `newwanip` requests collapse into a single pending IPv4 reconciliation
* repeated `newwanipv6` requests similarly collapse into one IPv6 reconciliation
* link processing takes priority over address reconciliation
* a final link `stop` makes queued IP reconciliation obsolete
* if a link changes while `newwanip`/`newwanipv6` is running, one additional IP reconciliation is retained so the final interface state is observed
* a newer conflicting link state may supersede an operation which has not yet been submitted to PHP-FPM

Events are initially debounced and additional events extend a short settle interval. A separate maximum debounce interval guarantees forward progress during continuous link flapping so an interface cannot remain indefinitely unconfigured simply because events continue arriving.

### Ambiguous transient-event reconciliation

If a serialized interface command was completely submitted but its FastCGI completion becomes unknown, the historical transition is not immediately replayed.

Instead, the daemon:

1. closes the ambiguous FastCGI connection
2. preserves any newer interface events which arrived while the request was running
3. waits through an extended grace period to allow the potentially still-running PHP worker to exit
4. performs at most one serialized reconciliation of the final desired state

This avoids running duplicate/stale transition handlers concurrently while still providing eventual convergence if the original handler did not complete.

Transient CARP events (`rc.carpmaster`/`rc.carpbackup`) receive the same protection against blind replay after ambiguous submission, but are intentionally not folded into the per-interface link/DHCP state machine because their ordering semantics differ.

### FastCGI retry behavior and queue bounding

Transport failures which are known to be safe to retry now use exponential backoff rather than repeated short-delay execution.

The default sequence is approximately:

`1s -> 2s -> 4s -> 8s -> 16s -> 30s`

with subsequent attempts remaining at the configured maximum delay.

Retries are intentionally indefinite for accepted durable reload work, since silently dropping such commands can leave runtime state inconsistent with configuration.

To prevent an unavailable PHP-FPM service combined with an interface/event storm from consuming unbounded memory, the run queue is now limited to 256 entries. Coalescing is performed before applying the queue limit, so events which can be merged into existing work continue to be accepted without consuming another queue entry.

Transition into and out of the queue-full condition is logged without emitting a syslog message for every rejected event.

### Gateway-monitor reconciliation

The patch adds `/etc/rc.gateway_monitor_reconcile`, a small PHP rc helper which calls only:

`setup_gateways_monitor()`

rather than rerunning the complete `rc.newwanip` workflow.

This addresses a timing condition where a dependent interface can become usable only after the initial WAN event has completed — for example, a GIF tunnel becoming usable or an IPv6 address completing DAD after `rc.newwanip` has already called `setup_gateways_monitor()`. In that case dpinger monitoring may never be created and the gateway can remain in an unknown state.

Successful IPv4/IPv6 interface reconciliation schedules a delayed global gateway-monitor convergence pass. Repeated requests reset the timer so bursts of recovery events collapse into a single pass.

Before running the helper, `check_reload_status` verifies that all serialized interface state machines have settled. If interface recovery is still active, the convergence pass is deferred.

The helper itself also takes a non-blocking `flock(2)`-backed lock under pfSense's runtime temporary directory, providing another layer of duplicate suppression.

The helper is executed through the normal FastCGI queue rather than by spawning an independent PHP process. As a result it inherits the daemon's response tracking, retries, backoff, queue accounting, and logging.

### FastCGI aggregation correctness

Aggregation of FastCGI commands now uses both the command pathname and fully formatted parameter string as its identity.

Previously, commands sharing the same executable could be treated as equivalent even when operating on different interfaces.

For an aggregate FastCGI request already queued or in flight, subsequent identical events now set a single `rerun_pending` flag. Once the current request completes successfully, exactly one fresh execution is scheduled.

This prevents both lost aggregate events and concurrent duplicate executions.

### Control socket hardening

The Unix control-socket input path also receives several correctness fixes:

* reads reserve space for an explicit NUL terminator
* CR/LF stripping operates on the actual received length
* every actual input byte is validated, including input which does not end in a newline
* character classification uses `unsigned char` values safely
* token parsing explicitly terminates the argv array
* `EAGAIN`/`EWOULDBLOCK` no longer cause the connection to be repeatedly polled in a small retry loop
* `accept(2)` now initializes the `socklen_t` input length before use

### File descriptor handling

`set_blockmode()` now handles descriptor-status and file-status flags separately:

* `O_NONBLOCK` is applied through `F_GETFL`/`F_SETFL`
* `FD_CLOEXEC` is applied through `F_GETFD`/`F_SETFD`

This avoids incorrectly passing descriptor flags through the file-status flag interface.

The FastCGI code also consistently uses `-1` as the sentinel for "no socket", eliminating ambiguity with descriptor 0.

### Runtime tuning and testability

Timing values which previously would have been compile-time policy are exposed through the optional:

`/usr/local/etc/check_reload_status.conf`

Configuration includes:

* `fcgi_response_timeout`
* `fcgi_retry_max_delay`
* `transient_initial_debounce`
* `transient_settle_delay`
* `transient_max_debounce`
* `transient_ambiguous_grace`
* `gateway_monitor_reconcile_delay`
* `gateway_monitor_busy_retry`

Values are range-checked and invalid or unknown configuration entries are logged and ignored.

A `CHECK_RELOAD_STATUS_FOREGROUND` environment option and configurable `controlpath` have also been added primarily to support isolated test harnesses without changing normal production daemon behavior.
