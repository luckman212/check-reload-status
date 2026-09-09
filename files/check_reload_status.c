/*
 * check_reload_status.c
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2010-2026 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/sbuf.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>

#include <ctype.h>

#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include <event.h>

#include "server.h"
#include "common.h"

#include <sys/utsname.h>

#include "fastcgi.h"

/*
 * Maximum time, in seconds, to wait for progress on the FastCGI socket
 * before tearing the connection down and retrying the request.  The timer is
 * re-armed on every activation of the socket event, so this is an inactivity
 * timeout rather than a total-response deadline.
 */
#define	CONFIG_PATH	"/usr/local/etc/check_reload_status.conf"

#define	FCGI_RESPONSE_TIMEOUT_DEFAULT	10

/*
 * Upper bound on the number of commands queued at once.  Delivery failures
 * are retried indefinitely, and the commands driven most often by hardware
 * events -- rc.linkup, rc.newwanip, rc.carpmaster and friends -- do not carry
 * the AGGREGATE flag, so each event enqueues a separate entry.  A prolonged
 * PHP-FPM outage during, say, a flapping link would otherwise let the queue
 * grow without limit.  At roughly 2.6 KB per entry this bounds the queue to
 * well under a megabyte.  New events are refused once it is reached rather
 * than discarding queued ones: a queued command is work already accepted.
 */
#define	MAX_QUEUED_COMMANDS	256

/*
 * Delivery failures are retried indefinitely because dropping a queued
 * reload can leave runtime state out of sync with configuration.  Back off
 * exponentially to this ceiling so a prolonged PHP-FPM outage does not
 * cause a tight retry loop.
 */
#define	FCGI_RETRY_MAX_DELAY_DEFAULT	30

/*
 * Transient interface events are state transitions, not durable jobs.  During
 * PHY/CPE startup one interface can generate a burst of alternating link
 * events while earlier PHP handlers are still running.  Serialize those
 * handlers per interface, debounce new events, and after an ambiguous
 * post-submission timeout wait long enough for the old PHP worker to finish
 * before performing at most one reconciliation pass.
 */
#define	TRANSIENT_INITIAL_DEBOUNCE_DEFAULT	1
#define	TRANSIENT_SETTLE_DELAY_DEFAULT	2
#define	TRANSIENT_AMBIGUOUS_GRACE_DEFAULT	10

/*
 * Upper bound on how long dispatch may be deferred by newly arriving events.
 * The settle delay is re-armed by every event for an interface, so without a
 * cap a link flapping faster than TRANSIENT_SETTLE_DELAY never dispatches at
 * all and the interface is left unconfigured for the whole storm -- trading
 * "converges to the wrong state" for "never converges".  Measured from the
 * first event of the current batch, so coalescing is preserved and forward
 * progress is guaranteed.
 */
#define	TRANSIENT_MAX_DEBOUNCE_DEFAULT	20
#define	GATEWAY_MONITOR_RECONCILE_DELAY_DEFAULT	10
#define	GATEWAY_MONITOR_BUSY_RETRY_DEFAULT	2

/*
 * Gateway-monitor convergence runs as an ordinary rc script through the
 * FastCGI path rather than as a directly executed PHP snippet, so that it
 * inherits this daemon's retry, backoff, logging and queue accounting, and so
 * that the interpreter path and include resolution stay in the script where
 * the rest of pfSense keeps them.
 */
#define	GATEWAY_MONITOR_COMMAND	"/etc/rc.gateway_monitor_reconcile"

/*
 * Runtime tuning.  These values start at conservative compiled-in defaults
 * and may be overridden at process startup by CONFIG_PATH.  The configuration
 * file is intentionally optional and is not reloaded while requests are in
 * flight; restart check_reload_status after changing it.
 */
static int fcgi_response_timeout = FCGI_RESPONSE_TIMEOUT_DEFAULT;
static int fcgi_retry_max_delay = FCGI_RETRY_MAX_DELAY_DEFAULT;
static int gateway_monitor_busy_retry = GATEWAY_MONITOR_BUSY_RETRY_DEFAULT;
static int gateway_monitor_reconcile_delay =
    GATEWAY_MONITOR_RECONCILE_DELAY_DEFAULT;
static int transient_ambiguous_grace = TRANSIENT_AMBIGUOUS_GRACE_DEFAULT;
static int transient_initial_debounce = TRANSIENT_INITIAL_DEBOUNCE_DEFAULT;
static int transient_max_debounce = TRANSIENT_MAX_DEBOUNCE_DEFAULT;
static int transient_settle_delay = TRANSIENT_SETTLE_DELAY_DEFAULT;

#define	TRANSIENT_KIND_NONE	0
#define	TRANSIENT_KIND_LINKUP	1
#define	TRANSIENT_KIND_NEWWANIP	2
#define	TRANSIENT_KIND_NEWWANIPV6	3

/*
 * Internal representation of a packet.
 */
struct runq {
	TAILQ_ENTRY(runq) rq_link;
	struct event ev;
	char   command[2048];
	char   params[256];
	int requestId;
	int aggregate;
	int dontexec;
	int rerun_pending;
	int socket;
	int submitted;
	unsigned int retries;
	struct event socket_ev;

	/* Per-interface serialization/coalescing for transient WAN events. */
	int transient_serialized;
	char transient_interface[64];
	int transient_busy;
	int transient_grace;
	int transient_active_kind;
	int transient_active_link_action;
	int transient_active_reconcile;
	int transient_desired_link_action;
	int transient_link_pending;
	int transient_link_reconcile;
	int transient_newwanip_pending;
	int transient_newwanip_reconcile;
	int transient_newwanipv6_pending;
	int transient_newwanipv6_reconcile;
	int transient_gateway_reconcile;
	time_t transient_first_pending;
	int transient_first_pending_valid;
	int transient_debounce_capped;

	/* FastCGI receive state for the non-blocking socket. */
	FCGI_Header fcgi_header;
	size_t fcgi_header_received;
	unsigned char *fcgi_record;
	size_t fcgi_record_len;
	size_t fcgi_record_received;
};
TAILQ_HEAD(runqueue, runq) cmds = TAILQ_HEAD_INITIALIZER(cmds);;

/* function definitions */
static void			load_config(void);
static char			*trim_whitespace(char *);
static void			handle_signal(int);
static void			handle_signal_act(int, siginfo_t *, void *);
static void			run_command(struct command *, char *);
static void			set_blockmode(int socket, int cmd);
struct command *	match_command(struct command *target, char *wordpassed);
struct command *	parse_command(int fd, int argc, char **argv);
static void			socket_read_command(int socket, short event, void *arg);
static void			show_command_list(int fd, const struct command *list);
static void			socket_accept_command(int socket, short event, void *arg);
static void			socket_close_command(int fd, struct event *ev);
static void			socket_read_fcgi(int, short, void *);
static void			fcgi_reset_response(struct runq *);
static void			fcgi_close_socket(struct runq *);
static void			fcgi_drop_command(struct runq *);
static void			fcgi_retry_command(struct runq *);
static int			fcgi_is_transient_command(const struct runq *);
static int			transient_command_kind(const char *);
static int			transient_query_value(const char *, const char *, char *, size_t);
static int			transient_decode_event(const char *, const char *, int *, char *, size_t, int *);
static void			transient_update_pending(struct runq *, int, int);
static int			transient_has_pending(const struct runq *);
static time_t			transient_monotonic(void);
static void			transient_schedule(struct runq *, int, int);
static void			transient_dispatch(int, short, void *);
static void			transient_finish(struct runq *, int);
static void			transient_ambiguous(struct runq *, const char *);
static void			gateway_monitor_schedule(void);
static void			gateway_monitor_reconcile(int, short, void *);
static void			fcgi_response_failure(struct runq *, const char *);
static void			fcgi_arm_socket_timeout(struct runq *);
static void			fcgi_send_command(int, short, void *);
static int			fcgi_open_socket(struct runq *);

static pid_t ppid = -1;
static struct utsname uts;
static int keepalive = 0;
static const char *fcgipath = FCGI_SOCK_PATH;
static const char *controlpath = PATH;
static struct event gateway_monitor_ev;
static int gateway_monitor_ev_initialized = 0;

static int
prepare_packet(FCGI_Header *header, int type, int lcontent, int requestId)
{
        header->version = (unsigned char)FCGI_VERSION_1;
        header->type = (unsigned char)type;
        header->requestIdB1 = (unsigned char)((requestId >> 8) & 0xFF);
        header->requestIdB0 = (unsigned char)(requestId & 0xFF);
        header->contentLengthB1 = (unsigned char)((lcontent >> 8) & 0xFF);
        header->contentLengthB0 = (unsigned char)(lcontent & 0xFF);

        return (0);
}

static int
build_nvpair(struct sbuf *sb, int lkey, int lvalue, const char *key, const char *svalue)
{
        if (lkey < 128)
                sbuf_putc(sb, lkey);
        else {
                sbuf_putc(sb, (u_char)((lkey >> 24) | 0x80));
                sbuf_putc(sb, (u_char)((lkey >> 16) & 0xFF));
                sbuf_putc(sb, (u_char)((lkey >> 8) & 0xFF));
                sbuf_putc(sb, (u_char)(lkey & 0xFF));
        }

        if (lvalue < 128)
                sbuf_putc(sb, lvalue);
        else {
                sbuf_putc(sb, (u_char)((lvalue >> 24) | 0x80));
                sbuf_putc(sb, (u_char)((lvalue >> 16) & 0xFF));
                sbuf_putc(sb, (u_char)((lvalue >> 8) & 0xFF));
                sbuf_putc(sb, (u_char)(lvalue & 0xFF));
        }

        if (lkey > 0)
                sbuf_printf(sb, "%s", key);
        if (lvalue > 0)
                sbuf_printf(sb, "%s", svalue);

        return (0);
}

/*
 * Re-arm the inactivity timeout on an already registered FastCGI socket
 * event.  event_add() on an event that is already pending simply reschedules
 * it, so calling this on every activation gives inactivity semantics without
 * depending on whether the linked libevent re-arms timeouts on persistent
 * events by itself.
 */
static void
fcgi_arm_socket_timeout(struct runq *cmd)
{
        struct timeval tv = { fcgi_response_timeout, 0 };

        if (cmd == NULL || cmd->socket < 0)
                return;

        event_add(&cmd->socket_ev, &tv);
}

static int
fcgi_open_socket(struct runq *cmd)
{
        struct sockaddr_un sun;
        struct timeval tv = { fcgi_response_timeout, 0 };
        int fcgifd;

        fcgifd = socket(PF_UNIX, SOCK_STREAM, 0);
        if (fcgifd < 0) {
                syslog(LOG_ERR, "Could not socket\n");
                return (-1);
        }

        bzero(&sun, sizeof(sun));
        sun.sun_family = PF_UNIX;
        strlcpy(sun.sun_path, fcgipath, sizeof(sun.sun_path));
        if (connect(fcgifd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
                syslog(LOG_ERR, "Could not connect to %s\n", fcgipath);
                close(fcgifd);
                return (-1);
        }

        set_blockmode(fcgifd, O_NONBLOCK | FD_CLOEXEC);

        /*
         * The response timeout lives on the socket event.  Do not arm a
         * second command timer after a successful write; doing so would race
         * this inactivity timeout and could discard an otherwise valid slow
         * response.
         */
        event_set(&cmd->socket_ev, fcgifd, EV_READ | EV_PERSIST,
            socket_read_fcgi, cmd);
        event_add(&cmd->socket_ev, &tv);

        return (fcgifd);
}

static void
show_command_list(int fd, const struct command *list)
{
        int     i;
	char	value[2048];

	if (list == NULL)
		return;

        for (i = 0; list[i].action != NULLOPT; i++) {
                switch (list[i].type) {
                case NON:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s <cr>\n", list[i].keyword);
                        write(fd, value, strlen(value));
                        break;
                case COMPOUND:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s\n", list[i].keyword);
                        write(fd, value, strlen(value));
                        break;
                case ADDRESS:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s <address>\n", list[i].keyword);
                        write(fd, value, strlen(value));
                        break;
                case PREFIX:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s <address>[/len]\n", list[i].keyword);
                        write(fd, value, strlen(value));
                        break;
		case INTEGER:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s <number>\n", list[i].keyword);
                        write(fd, value, strlen(value));
			break;
                case IFNAME:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s <interface>\n", list[i].keyword);
                        write(fd, value, strlen(value));
                        break;
                case STRING:
			bzero(value, sizeof(value));
			snprintf(value, sizeof(value), "\t%s <string>\n", list[i].keyword);
                        write(fd, value, strlen(value));
                        break;
                }
        }
}

struct command *
parse_command(int fd, int argc, char **argv)
{
	struct command	*start = first_level;
	struct command	*match = NULL;
	const char *errstring = "ERROR:\tvalid commands are:\n";

	while (argc >= 0) {
		match = match_command(start, *argv);
		if (match == NULL) {
			errstring = "ERROR:\tNo match found.\n";
			goto error3;
		}

		argc--;
		argv++;

		if (argc > 0 && match->next == NULL) {
			errstring = "ERROR:\textra arguments passed.\n";
			goto error3;
		}
		if (argc < 0 && match->type != NON) {
			if (match->next != NULL)
				start = match->next;
			errstring = "ERROR:\tincomplete command.\n";
			goto error3;
		}
		if (argc == 0 && *argv == NULL && match->type != NON) {
			if (match->next != NULL)
				start = match->next;
			errstring = "ERROR:\tincomplete command.\n";
			goto error3;
		}

		if ( match->next == NULL)
			break;

		start = match->next;
	}

	return (match);
error3:
	write(fd, errstring, strlen(errstring));
	show_command_list(fd, start);
	return (NULL);
}

struct command *
match_command(struct command *target, char *wordpassed)
{
	int i;

	if (wordpassed == NULL)
		return NULL;

	for (i = 0; target[i].action != NULLOPT; i++) {
		if (strcmp(target[i].keyword, wordpassed) == 0)
			return &target[i];
	}

	return (NULL);
}

static void
handle_signal_act(int sig, siginfo_t *unused1 __unused, void *unused2 __unused)
{
	handle_signal(sig);
}

static void
handle_signal(int sig)
{
        switch(sig) {
        case SIGHUP:
        case SIGTERM:
#if 0
		if (child)
			exit(0);
#endif
                break;
        }
}

/*
 * Tear down the FastCGI connection belonging to a queued command and drop
 * any partially received record along with it.  Descriptor -1 consistently
 * means "no connection".
 */
static void
fcgi_close_socket(struct runq *cmd)
{
        if (cmd == NULL)
                return;

        if (cmd->socket >= 0) {
                event_del(&cmd->socket_ev);
                close(cmd->socket);
        }
        cmd->socket = -1;

        fcgi_reset_response(cmd);
}

/*
 * Remove a command from the run queue and release everything it owns.  The
 * caller must not touch cmd afterwards.
 */
static void
fcgi_drop_command(struct runq *cmd)
{
        if (cmd == NULL)
                return;

        TAILQ_REMOVE(&cmds, cmd, rq_link);
        timeout_del(&cmd->ev);
        fcgi_close_socket(cmd);
        free(cmd);
}

/*
 * Schedule another delivery attempt after a failure for which replay is known
 * to be safe (for example, connect failure, an incomplete request write, or an
 * explicit FastCGI response saying the request was not completed).  Use 1, 2,
 * 4, 8, 16, then 30-second retries.
 */
static void
fcgi_retry_command(struct runq *cmd)
{
        struct timeval tv;
        unsigned int shift;
        int delay;

        if (cmd == NULL)
                return;

        /*
         * No request is in flight while this command is waiting in retry
         * backoff.  Keeping submitted set here would prevent a newer conflicting
         * serialized link event from safely superseding the stale retry.
         */
        cmd->submitted = 0;

        if (cmd->retries < UINT_MAX)
                cmd->retries++;

        shift = (cmd->retries > 0) ? cmd->retries - 1 : 0;
        if (shift >= 5)
                delay = fcgi_retry_max_delay;
        else {
                delay = 1 << shift;
                if (delay > fcgi_retry_max_delay)
                        delay = fcgi_retry_max_delay;
        }

        tv.tv_sec = delay;
        tv.tv_usec = 0;
        timeout_del(&cmd->ev);
        timeout_set(&cmd->ev, fcgi_send_command, cmd);
        timeout_add(&cmd->ev, &tv);

        syslog(LOG_NOTICE,
            "Retrying FastCGI request id=%d command=%s params=%s in %d second%s",
            cmd->requestId, cmd->command, cmd->params, delay,
            delay == 1 ? "" : "s");
}

/*
 * These commands describe transient interface edges.  Once a complete request
 * has been handed to PHP-FPM, a lost/late response does not tell us whether the
 * script is still running or already completed.  Replaying one of these events
 * in that ambiguous state can execute stale link/IP transitions concurrently
 * with newer ones and repeatedly bounce gateway monitoring.
 */
static int
fcgi_is_transient_command(const struct runq *cmd)
{
        static const char * const transient[] = {
                "/etc/rc.newwanip",
                "/etc/rc.newwanipv6",
                "/etc/rc.linkup",
                "/etc/rc.carpmaster",
                "/etc/rc.carpbackup",
                NULL
        };
        int i;

        if (cmd == NULL)
                return (0);

        for (i = 0; transient[i] != NULL; i++) {
                if (strcmp(cmd->command, transient[i]) == 0)
                        return (1);
        }
        return (0);
}

/*
 * Return the serialized transient class for commands that operate on a single
 * interface.  CARP commands remain under the v8 response-side protection but
 * are not folded into this state machine because their ordering semantics are
 * different from link/DHCP reconciliation.
 */
static int
transient_command_kind(const char *command)
{
        if (command == NULL)
                return (TRANSIENT_KIND_NONE);
        if (strcmp(command, "/etc/rc.linkup") == 0)
                return (TRANSIENT_KIND_LINKUP);
        if (strcmp(command, "/etc/rc.newwanip") == 0)
                return (TRANSIENT_KIND_NEWWANIP);
        if (strcmp(command, "/etc/rc.newwanipv6") == 0)
                return (TRANSIENT_KIND_NEWWANIPV6);
        return (TRANSIENT_KIND_NONE);
}

/* Extract an unescaped key=value field from the small query strings used here. */
static int
transient_query_value(const char *params, const char *key, char *value,
    size_t value_size)
{
        const char *p, *end, *eq;
        size_t key_len, value_len;

        if (params == NULL || key == NULL || value == NULL || value_size == 0)
                return (0);

        key_len = strlen(key);
        p = params;
        while (*p != '\0') {
                end = strchr(p, '&');
                if (end == NULL)
                        end = p + strlen(p);
                eq = memchr(p, '=', (size_t)(end - p));
                if (eq != NULL && (size_t)(eq - p) == key_len &&
                    strncmp(p, key, key_len) == 0) {
                        value_len = (size_t)(end - eq - 1);
                        if (value_len >= value_size)
                                value_len = value_size - 1;
                        memcpy(value, eq + 1, value_len);
                        value[value_len] = '\0';
                        return (1);
                }
                if (*end == '\0')
                        break;
                p = end + 1;
        }
        return (0);
}

/*
 * Decode a transient event into (kind, interface, link action).  Return zero
 * if the command does not have the parameter shape expected by the state
 * machine; the caller then falls back to the ordinary v8 path.
 */
static int
transient_decode_event(const char *command, const char *params, int *kind,
    char *interface, size_t interface_size, int *link_action)
{
        char action[16];
        int k;

        k = transient_command_kind(command);
        if (k == TRANSIENT_KIND_NONE)
                return (0);
        if (!transient_query_value(params, "interface", interface,
            interface_size) || interface[0] == '\0')
                return (0);

        *kind = k;
        *link_action = -1;
        if (k == TRANSIENT_KIND_LINKUP) {
                if (!transient_query_value(params, "action", action,
                    sizeof(action)))
                        return (0);
                if (strcmp(action, "start") == 0)
                        *link_action = 1;
                else if (strcmp(action, "stop") == 0)
                        *link_action = 0;
                else
                        return (0);
        }
        return (1);
}

/*
 * Seconds from a monotonic source, so the debounce cap is unaffected by
 * wall-clock steps.  Falls back to time(3) only if the clock is unavailable.
 */
static time_t
transient_monotonic(void)
{
        struct timespec ts;

        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
                return (ts.tv_sec);
        return (time(NULL));
}

static int
transient_has_pending(const struct runq *cmd)
{
        return (cmd != NULL && (cmd->transient_link_pending ||
            cmd->transient_newwanip_pending ||
            cmd->transient_newwanipv6_pending));
}

/*
 * Merge a newly observed interface event into the desired state.  Link events
 * are latest-state wins.  newwanip/newwanipv6 collapse to one pending
 * reconciliation each.  If a link changes while newwanip is in flight, run
 * one more newwanip after the link has settled because the in-flight one may
 * have observed an obsolete interface state.
 */
static void
transient_update_pending(struct runq *cmd, int kind, int link_action)
{
        if (cmd == NULL)
                return;

        /*
         * Start the debounce window at the first event of a batch.  Later
         * events for the same batch extend the settle delay but cannot push
         * dispatch past TRANSIENT_MAX_DEBOUNCE from this point.
         */
        if (!cmd->transient_first_pending_valid) {
                cmd->transient_first_pending = transient_monotonic();
                cmd->transient_first_pending_valid = 1;
        }

        switch (kind) {
        case TRANSIENT_KIND_LINKUP:
                cmd->transient_desired_link_action = link_action;
                cmd->transient_link_pending = 1;
                cmd->transient_link_reconcile = 0;
                if (cmd->transient_busy &&
                    cmd->transient_active_kind == TRANSIENT_KIND_NEWWANIP) {
                        cmd->transient_newwanip_pending = 1;
                        cmd->transient_newwanip_reconcile = 0;
                } else if (cmd->transient_busy &&
                    cmd->transient_active_kind == TRANSIENT_KIND_NEWWANIPV6) {
                        cmd->transient_newwanipv6_pending = 1;
                        cmd->transient_newwanipv6_reconcile = 0;
                }

                /*
                 * If the active operation has not been fully submitted yet,
                 * a newer conflicting link state can safely supersede it.
                 * Do not spend retry time delivering a STOP after a newer UP.
                 */
                if (cmd->transient_busy && !cmd->submitted &&
                    (cmd->transient_active_kind != TRANSIENT_KIND_LINKUP ||
                    cmd->transient_active_link_action != link_action)) {
                        timeout_del(&cmd->ev);
                        fcgi_close_socket(cmd);
                        cmd->transient_busy = 0;
                        cmd->transient_active_kind = TRANSIENT_KIND_NONE;
                        cmd->transient_active_reconcile = 0;
                        cmd->retries = 0;
                }
                break;
        case TRANSIENT_KIND_NEWWANIP:
                cmd->transient_newwanip_pending = 1;
                cmd->transient_newwanip_reconcile = 0;
                break;
        case TRANSIENT_KIND_NEWWANIPV6:
                cmd->transient_newwanipv6_pending = 1;
                cmd->transient_newwanipv6_reconcile = 0;
                break;
        default:
                break;
        }
}

/* Schedule the state-machine dispatcher, replacing any previous idle timer. */
static void
transient_schedule(struct runq *cmd, int delay, int grace)
{
        struct timeval tv;
        time_t elapsed;
        int remaining;

        if (cmd == NULL)
                return;

        if (!transient_has_pending(cmd)) {
                fcgi_drop_command(cmd);
                return;
        }

        /*
         * Clamp the settle delay so a sustained event storm cannot defer
         * dispatch forever.  The ambiguous grace period is exempt: that
         * deadline exists to let a possibly-still-running PHP worker finish,
         * and shortening it would defeat its purpose.
         */
        if (grace == 0 && cmd->transient_first_pending_valid) {
                elapsed = transient_monotonic() - cmd->transient_first_pending;
                if (elapsed < 0)
                        elapsed = 0;
                remaining = transient_max_debounce - (int)elapsed;
                if (remaining < 0)
                        remaining = 0;
                if (delay > remaining) {
                        if (!cmd->transient_debounce_capped) {
                                syslog(LOG_NOTICE,
                                    "Interface %s has produced events for %d seconds without settling; dispatching now",
                                    cmd->transient_interface,
                                    transient_max_debounce);
                                cmd->transient_debounce_capped = 1;
                        }
                        delay = remaining;
                }
        }

        tv.tv_sec = delay;
        tv.tv_usec = 0;
        cmd->transient_grace = grace;
        timeout_del(&cmd->ev);
        timeout_set(&cmd->ev, transient_dispatch, cmd);
        timeout_add(&cmd->ev, &tv);
}

/*
 * Pick exactly one operation for an interface.  Link reconciliation always
 * has priority over newwanip work.  A STOP makes pending IP reconciliation
 * obsolete; a later START event will create/request fresh work as needed.
 */
static void
transient_dispatch(int fd __unused, short event __unused, void *arg)
{
        struct runq *cmd = arg;
        int reconcile;

        if (cmd == NULL || cmd->transient_busy)
                return;

        cmd->transient_grace = 0;
        cmd->transient_active_kind = TRANSIENT_KIND_NONE;
        cmd->transient_active_link_action = -1;
        cmd->transient_active_reconcile = 0;

        /* This batch is being dispatched; the next one starts a new window. */
        cmd->transient_first_pending_valid = 0;
        cmd->transient_debounce_capped = 0;

        if (cmd->transient_link_pending) {
                reconcile = cmd->transient_link_reconcile;
                cmd->transient_link_pending = 0;
                cmd->transient_link_reconcile = 0;
                cmd->transient_active_kind = TRANSIENT_KIND_LINKUP;
                cmd->transient_active_link_action =
                    cmd->transient_desired_link_action;
                cmd->transient_active_reconcile = reconcile;
                strlcpy(cmd->command, "/etc/rc.linkup",
                    sizeof(cmd->command));
                snprintf(cmd->params, sizeof(cmd->params),
                    "action=%s&interface=%s",
                    cmd->transient_active_link_action ? "start" : "stop",
                    cmd->transient_interface);
        } else if (cmd->transient_newwanip_pending) {
                reconcile = cmd->transient_newwanip_reconcile;
                cmd->transient_newwanip_pending = 0;
                cmd->transient_newwanip_reconcile = 0;
                cmd->transient_active_kind = TRANSIENT_KIND_NEWWANIP;
                cmd->transient_active_reconcile = reconcile;
                strlcpy(cmd->command, "/etc/rc.newwanip",
                    sizeof(cmd->command));
                snprintf(cmd->params, sizeof(cmd->params), "interface=%s",
                    cmd->transient_interface);
        } else if (cmd->transient_newwanipv6_pending) {
                reconcile = cmd->transient_newwanipv6_reconcile;
                cmd->transient_newwanipv6_pending = 0;
                cmd->transient_newwanipv6_reconcile = 0;
                cmd->transient_active_kind = TRANSIENT_KIND_NEWWANIPV6;
                cmd->transient_active_reconcile = reconcile;
                strlcpy(cmd->command, "/etc/rc.newwanipv6",
                    sizeof(cmd->command));
                snprintf(cmd->params, sizeof(cmd->params), "interface=%s",
                    cmd->transient_interface);
        } else {
                fcgi_drop_command(cmd);
                return;
        }

        cmd->transient_busy = 1;
        cmd->submitted = 0;
        cmd->retries = 0;
        syslog(LOG_NOTICE,
            "Dispatching serialized transient command=%s params=%s%s",
            cmd->command, cmd->params,
            cmd->transient_active_reconcile ? " (reconciliation)" : "");
        fcgi_send_command(-1, 0, cmd);
}

/*
 * Schedule one global gateway-monitor convergence pass.  Every new request
 * replaces the existing timer, so bursts of interface recovery work collapse
 * into one setup_gateways_monitor() call after the system has been quiet.
 */
static void
gateway_monitor_schedule(void)
{
        struct timeval tv = { gateway_monitor_reconcile_delay, 0 };

        if (!gateway_monitor_ev_initialized) {
                timeout_set(&gateway_monitor_ev, gateway_monitor_reconcile, NULL);
                gateway_monitor_ev_initialized = 1;
        }

        timeout_del(&gateway_monitor_ev);
        timeout_add(&gateway_monitor_ev, &tv);
        syslog(LOG_NOTICE,
            "Scheduled gateway-monitor reconciliation in %d seconds",
            gateway_monitor_reconcile_delay);
}

/*
 * Run only after all serialized transient interface work has settled.  A GIF
 * or other dependent interface can become usable after rc.newwanip's original
 * setup_gateways_monitor() call (for example, after IPv6 DAD completes).
 * Re-running only gateway monitoring is sufficient to converge dpinger state
 * without replaying the much larger rc.newwanip workflow.
 *
 * The work is queued as a normal FastCGI command so that a failure is retried
 * with backoff, participates in the queue bound, and is logged like any other,
 * instead of being forked off into an unobserved PHP process.  This does not
 * globally serialize it against unrelated FastCGI work; the delayed convergence
 * timer and serialized-interface settling check are what keep it away from the
 * interface recovery storm that motivated this pass.
 */
static void
gateway_monitor_reconcile(int fd __unused, short event __unused, void *arg __unused)
{
        struct runq *cmd, *command;
        struct timeval retry = { gateway_monitor_busy_retry, 0 };
        struct timeval start = { 1, 0 };
        unsigned int queued = 0;
        int settling = 0, already_queued = 0;

        TAILQ_FOREACH(cmd, &cmds, rq_link) {
                queued++;
                if (cmd->transient_serialized &&
                    (cmd->transient_busy || transient_has_pending(cmd) ||
                    cmd->transient_grace))
                        settling = 1;
                if (strcmp(cmd->command, GATEWAY_MONITOR_COMMAND) == 0)
                        already_queued = 1;
        }

        /* Wait until every interface state machine has finished. */
        if (settling) {
                timeout_add(&gateway_monitor_ev, &retry);
                return;
        }

        /* One convergence pass is enough; a queued one already covers us. */
        if (already_queued)
                return;

        if (queued >= MAX_QUEUED_COMMANDS) {
                syslog(LOG_ERR,
                    "Command queue is full (%u entries); deferring gateway-monitor reconciliation",
                    queued);
                timeout_add(&gateway_monitor_ev, &retry);
                return;
        }

        command = calloc(1, sizeof(*command));
        if (command == NULL) {
                syslog(LOG_ERR,
                    "Calloc failure for %s", GATEWAY_MONITOR_COMMAND);
                timeout_add(&gateway_monitor_ev, &retry);
                return;
        }

        /* -1, not calloc()'s 0, is the sentinel for no open socket. */
        command->socket = -1;
        command->aggregate = 0;
        command->transient_active_link_action = -1;
        command->transient_desired_link_action = -1;
        strlcpy(command->command, GATEWAY_MONITOR_COMMAND,
            sizeof(command->command));

        syslog(LOG_NOTICE,
            "Reconciling gateway monitoring after interface recovery");
        TAILQ_INSERT_HEAD(&cmds, command, rq_link);
        timeout_set(&command->ev, fcgi_send_command, command);
        timeout_add(&command->ev, &start);
}

/*
 * A serialized request completed successfully.  Move on only after a short
 * settle interval.  For link STOP, IP reconciliation queued before the STOP
 * is stale and is discarded.
 */
static void
transient_finish(struct runq *cmd, int success)
{
        int active_kind, active_action;

        if (cmd == NULL)
                return;

        active_kind = cmd->transient_active_kind;
        active_action = cmd->transient_active_link_action;
        fcgi_close_socket(cmd);
        cmd->submitted = 0;
        cmd->retries = 0;
        cmd->transient_busy = 0;
        cmd->transient_active_kind = TRANSIENT_KIND_NONE;
        cmd->transient_active_reconcile = 0;

        if (success && (active_kind == TRANSIENT_KIND_NEWWANIP ||
            active_kind == TRANSIENT_KIND_NEWWANIPV6))
                cmd->transient_gateway_reconcile = 1;

        if (success && active_kind == TRANSIENT_KIND_LINKUP &&
            active_action == 0 && !cmd->transient_link_pending) {
                cmd->transient_newwanip_pending = 0;
                cmd->transient_newwanip_reconcile = 0;
                cmd->transient_newwanipv6_pending = 0;
                cmd->transient_newwanipv6_reconcile = 0;
        }

        if (transient_has_pending(cmd)) {
                transient_schedule(cmd, transient_settle_delay, 0);
        } else {
                if (cmd->transient_gateway_reconcile)
                        gateway_monitor_schedule();
                fcgi_drop_command(cmd);
        }
}

/*
 * A complete request was submitted, but completion is unknown.  Do not replay
 * the historical operation immediately.  Preserve newer events, and if this
 * was not itself the one reconciliation pass, schedule exactly one final
 * reconciliation of the current state after a long grace period.  This gives
 * the possibly-still-running PHP worker time to leave the interface alone.
 */
static void
transient_ambiguous(struct runq *cmd, const char *reason)
{
        int kind, action, was_reconcile;

        if (cmd == NULL)
                return;

        kind = cmd->transient_active_kind;
        action = cmd->transient_active_link_action;
        was_reconcile = cmd->transient_active_reconcile;

        syslog(LOG_ERR,
            "FastCGI request id=%d command=%s params=%s was submitted but %s; completion state is unknown%s",
            cmd->requestId, cmd->command, cmd->params, reason,
            was_reconcile ? "; reconciliation will not be repeated" :
            "; scheduling one final serialized reconciliation");

        fcgi_close_socket(cmd);
        cmd->submitted = 0;
        cmd->retries = 0;
        cmd->transient_busy = 0;
        cmd->transient_active_kind = TRANSIENT_KIND_NONE;
        cmd->transient_active_reconcile = 0;

        if (kind == TRANSIENT_KIND_NEWWANIP ||
            kind == TRANSIENT_KIND_NEWWANIPV6)
                cmd->transient_gateway_reconcile = 1;

        /* A final desired STOP makes any queued IP reconciliation obsolete. */
        if (kind == TRANSIENT_KIND_LINKUP && action == 0 &&
            !cmd->transient_link_pending) {
                cmd->transient_newwanip_pending = 0;
                cmd->transient_newwanip_reconcile = 0;
                cmd->transient_newwanipv6_pending = 0;
                cmd->transient_newwanipv6_reconcile = 0;
        }

        if (!was_reconcile) {
                switch (kind) {
                case TRANSIENT_KIND_LINKUP:
                        /* Do not overwrite a newer link event. */
                        if (!cmd->transient_link_pending) {
                                cmd->transient_desired_link_action = action;
                                cmd->transient_link_pending = 1;
                                cmd->transient_link_reconcile = 1;
                        }
                        break;
                case TRANSIENT_KIND_NEWWANIP:
                        if (!cmd->transient_newwanip_pending) {
                                cmd->transient_newwanip_pending = 1;
                                cmd->transient_newwanip_reconcile = 1;
                        }
                        break;
                case TRANSIENT_KIND_NEWWANIPV6:
                        if (!cmd->transient_newwanipv6_pending) {
                                cmd->transient_newwanipv6_pending = 1;
                                cmd->transient_newwanipv6_reconcile = 1;
                        }
                        break;
                default:
                        break;
                }
        }

        if (transient_has_pending(cmd)) {
                transient_schedule(cmd, transient_ambiguous_grace, 1);
        } else {
                if (cmd->transient_gateway_reconcile)
                        gateway_monitor_schedule();
                fcgi_drop_command(cmd);
        }
}

/*
 * Handle an ambiguous response-side failure.  Before successful submission,
 * replay is safe.  Serialized transient interface commands use their
 * per-interface state machine after submission.  Other transient commands keep
 * the v8 rule of not replaying an ambiguous historical edge.
 */
static void
fcgi_response_failure(struct runq *cmd, const char *reason)
{
        if (cmd == NULL)
                return;

        if (cmd->submitted && cmd->transient_serialized) {
                transient_ambiguous(cmd, reason);
                return;
        }

        if (cmd->submitted && fcgi_is_transient_command(cmd)) {
                syslog(LOG_ERR,
                    "FastCGI request id=%d command=%s params=%s was submitted but %s; completion state is unknown, not replaying transient event",
                    cmd->requestId, cmd->command, cmd->params, reason);
                fcgi_drop_command(cmd);
                return;
        }

        syslog(LOG_ERR,
            "FastCGI request id=%d command=%s params=%s failed after submission=%d (%s); scheduling retry",
            cmd->requestId, cmd->command, cmd->params, cmd->submitted, reason);
        fcgi_close_socket(cmd);
        fcgi_retry_command(cmd);
}

static void
fcgi_send_command(int fd __unused , short event __unused, void *arg)
{
        FCGI_BeginRequestRecord *bHeader;
        FCGI_Header *tmpl;
        struct sbuf sb;
        struct runq *cmd;
        static int requestId = 0;
        ssize_t params_len, result;
        size_t len;
        char *p, sbuf[4096], buf[4096], *bufptr;
        char request_uri[sizeof(cmd->command) + sizeof(cmd->params) + 2];

        cmd = arg;
        if (cmd == NULL)
                return;

        /*
         * FCGI commands do not use dontexec as a lifecycle marker.  Aggregate
         * events that arrive while a request is outstanding are represented
         * explicitly by rerun_pending and are scheduled only after the
         * current request completes successfully.  socket_ev owns response
         * liveness through its inactivity timeout.
         */

        /*
         * Always issue a request on a freshly opened connection.  Re-using a
         * socket that may still carry records belonging to the previous
         * request ID would let a late response complete the wrong request,
         * and would leave stale receive state in place.
         */
        fcgi_close_socket(cmd);
        cmd->submitted = 0;

        /* FastCGI request IDs are 16-bit and ID 0 is reserved. */
        if (++requestId > 65535)
                requestId = 1;
        cmd->requestId = requestId;

        memset(sbuf, 0, sizeof(sbuf));
        if (sbuf_new(&sb, sbuf, sizeof(sbuf), 0) == NULL) {
                syslog(LOG_ERR,
                    "Could not initialize FastCGI parameter buffer for %s",
                    cmd->command);
                fcgi_drop_command(cmd);
                return;
        }

        /* TODO: Use hardcoded length instead of strlen allover later on */
        /* TODO: Remove some env variables since might not be needed at all!!! */
        build_nvpair(&sb, strlen("GATEWAY_INTERFACE"), strlen("FastCGI/1.0"), "GATEWAY_INTERFACE", "FastCGI/1.0");
        build_nvpair(&sb, strlen("REQUEST_METHOD"), strlen("GET"), "REQUEST_METHOD", "GET");
        build_nvpair(&sb, strlen("NO_HEADERS"), strlen("1"), "NO_HEADERS", "1");
        build_nvpair(&sb, strlen("SCRIPT_FILENAME"), strlen(cmd->command), "SCRIPT_FILENAME", cmd->command);
        p = strrchr(cmd->command, '/');
        if (p == NULL) {
                syslog(LOG_ERR,
                    "Command %s has no path separator; dropping it",
                    cmd->command);
                fcgi_drop_command(cmd);
                return;
        }
        build_nvpair(&sb, strlen("SCRIPT_NAME"), strlen(p), "SCRIPT_NAME", p);
        build_nvpair(&sb, strlen("DOCUMENT_URI"), strlen(p), "DOCUMENT_URI", p);
        if (!cmd->params[0]) {
                build_nvpair(&sb, strlen("REQUEST_URI"), strlen(p), "REQUEST_URI", p);
        } else {
                int uri_len;

                build_nvpair(&sb, strlen("QUERY_STRING"), strlen(cmd->params),
                    "QUERY_STRING", cmd->params);
                uri_len = snprintf(request_uri, sizeof(request_uri), "%s?%s",
                    p, cmd->params);
                if (uri_len < 0 || (size_t)uri_len >= sizeof(request_uri)) {
                        syslog(LOG_ERR,
                            "FastCGI REQUEST_URI is too large for %s; dropping it",
                            cmd->command);
                        fcgi_drop_command(cmd);
                        return;
                }
                build_nvpair(&sb, strlen("REQUEST_URI"), uri_len,
                    "REQUEST_URI", request_uri);
        }

        if (sbuf_finish(&sb) != 0) {
                syslog(LOG_ERR,
                    "FastCGI parameter block overflowed for %s; dropping it",
                    cmd->command);
                fcgi_drop_command(cmd);
                return;
        }
        params_len = sbuf_len(&sb);
        if (params_len < 0) {
                syslog(LOG_ERR,
                    "Could not determine FastCGI parameter length for %s; dropping it",
                    cmd->command);
                fcgi_drop_command(cmd);
                return;
        }

        len = (3 * sizeof(FCGI_Header)) + sizeof(FCGI_BeginRequestRecord) +
            (size_t)params_len;
        if (len > sizeof(buf)) {
                syslog(LOG_ERR,
                    "FastCGI request for %s is too large (%zu bytes, maximum %zu); dropping it",
                    cmd->command, len, sizeof(buf));
                fcgi_drop_command(cmd);
                return;
        }

        memset(buf, 0, sizeof(buf));

        bufptr = buf;
        bHeader = (FCGI_BeginRequestRecord *)buf;
        prepare_packet(&bHeader->header, FCGI_BEGIN_REQUEST,
            sizeof(bHeader->body), cmd->requestId);
        bHeader->body.roleB0 = (unsigned char)FCGI_RESPONDER;
        bHeader->body.flags = (unsigned char)(keepalive ? FCGI_KEEP_CONN : 0);

        bufptr += sizeof(FCGI_BeginRequestRecord);
        tmpl = (FCGI_Header *)bufptr;
        prepare_packet(tmpl, FCGI_PARAMS, (int)params_len, cmd->requestId);

        bufptr += sizeof(FCGI_Header);
        memcpy(bufptr, sbuf_data(&sb), (size_t)params_len);

        bufptr += params_len;
        tmpl = (FCGI_Header *)bufptr;
        prepare_packet(tmpl, FCGI_PARAMS, 0, cmd->requestId);

        bufptr += sizeof(FCGI_Header);
        tmpl = (FCGI_Header *)bufptr;
        prepare_packet(tmpl, FCGI_STDIN, 0, cmd->requestId);

        if ((cmd->socket = fcgi_open_socket(cmd)) < 0) {
                syslog(LOG_ERR,
                    "Could not submit FastCGI request id=%d command=%s params=%s; connect failed",
                    cmd->requestId, cmd->command, cmd->params);
                fcgi_retry_command(cmd);
                return;
        }

        result = write(cmd->socket, buf, len);
        if (result != (ssize_t)len) {
                /*
                 * A partially written request cannot safely be resumed
                 * without write-side state.  Retry the whole request on a
                 * fresh connection and request ID instead.
                 */
                if (result < 0)
                        syslog(LOG_ERR,
                            "Something wrong happened while sending request: %m");
                else
                        syslog(LOG_ERR,
                            "Short write (%zd of %zu bytes) sending request for %s",
                            result, len, cmd->command);
                fcgi_close_socket(cmd);
                fcgi_retry_command(cmd);
                return;
        }

        cmd->submitted = 1;
        syslog(LOG_DEBUG,
            "Submitted FastCGI request id=%d command=%s params=%s",
            cmd->requestId, cmd->command, cmd->params);

        /*
         * Do not arm cmd->ev here.  socket_ev exclusively owns response
         * liveness; a later aggregate event is recorded in rerun_pending and
         * will be scheduled after this request completes successfully.
         */
}

static void
run_command_detailed(int fd __unused, short event __unused, void *arg) {
	struct runq *cmd;
	struct timeval tv = { 8, 0 };

	cmd = (struct runq *)arg;

	if (cmd == NULL)
		return;

	if (cmd->dontexec) {
		TAILQ_REMOVE(&cmds, cmd, rq_link);
		timeout_del(&cmd->ev);
		if (cmd->socket >= 0)
			close(cmd->socket);
		free(cmd);
		return;
	}


	switch (vfork()) {
	case -1:
		syslog(LOG_ERR, "Could not vfork() error %d - %s!!!", errno, strerror(errno));
		break;
	case 0:
		/* Possibly optimize by creating argument list and calling execve. */
		if (cmd->params[0])
			execl("/bin/sh", "/bin/sh", "-c", cmd->command, cmd->params, (char *)NULL);
		else
			execl("/bin/sh", "/bin/sh", "-c", cmd->command, (char *)NULL);
		syslog(LOG_ERR, "could not run: %s", cmd->command);
		_exit(127); /* Protect in case execl errors out */
		break;
	default:
		if (cmd->aggregate > 0) {
			cmd->dontexec = 1;
			timeout_add(&cmd->ev, &tv);
		} else {
			TAILQ_REMOVE(&cmds, cmd, rq_link);
			timeout_del(&cmd->ev);
			if (cmd->socket >= 0)
				close(cmd->socket);
			free(cmd);
		}
		break;
	}
}

static void
run_command(struct command *cmd, char *argv) {
	struct runq *command, *tmpcmd;
	struct timeval tv = { 1, 0 };
	static int queue_full = 0;
	unsigned int queued = 0;
	int aggregate = 0;
	int transient_kind = TRANSIENT_KIND_NONE;
	int transient_link_action = -1;
	int transient_serializable = 0;
	char command_params[256] = { 0 };
	char transient_interface[64] = { 0 };

	/*
	 * Build the parameter string before searching the queue so FastCGI
	 * aggregation can use (command, params) as its identity.  Commands such
	 * as interface reloads share the same executable but target different
	 * interfaces and must not suppress each other.
	 */
	if (cmd->cmd.params)
		snprintf(command_params, sizeof(command_params), cmd->cmd.params,
		    argv != NULL ? argv : "");

	if ((cmd->cmd.flags & FCGICMD) &&
	    transient_decode_event(cmd->cmd.command, command_params,
	    &transient_kind, transient_interface, sizeof(transient_interface),
	    &transient_link_action))
		transient_serializable = 1;

	TAILQ_FOREACH(tmpcmd, &cmds, rq_link) {
		queued++;

		if (transient_serializable && tmpcmd->transient_serialized &&
		    strcmp(tmpcmd->transient_interface, transient_interface) == 0) {
			/*
			 * One state machine owns this physical interface.  Fold the
			 * new edge/reconciliation request into its desired state rather
			 * than creating another concurrent PHP-FPM job.
			 */
			transient_update_pending(tmpcmd, transient_kind,
			    transient_link_action);
			if (argv != NULL)
				syslog(LOG_NOTICE, cmd->cmd.syslog, argv);
			else
				syslog(LOG_NOTICE, "%s", cmd->cmd.syslog);

			/*
			 * While an ambiguous-submission grace period is running,
			 * leave its timer alone.  That deadline belongs to the
			 * possibly-still-running PHP worker, not to debouncing;
			 * re-arming it on every event let a link flapping faster
			 * than the grace period defer dispatch indefinitely.
			 * The desired state has already been merged above.
			 */
			if (!tmpcmd->transient_busy && !tmpcmd->transient_grace)
				transient_schedule(tmpcmd,
				    transient_settle_delay, 0);
			return;
		}
		if (!(cmd->cmd.flags & AGGREGATE) ||
		    strcmp(tmpcmd->command, cmd->cmd.command) != 0)
			continue;

		if (cmd->cmd.flags & FCGICMD) {
			/*
			 * A matching FastCGI command is already queued or in flight.
			 * Coalesce the new event immediately, including the second
			 * event, but only when the fully formatted parameter strings
			 * also match.  Remember exactly one rerun and schedule it only
			 * after the outstanding request completes successfully.
			 */
			if (strcmp(tmpcmd->params, command_params) == 0) {
				if (!tmpcmd->rerun_pending) {
					syslog(LOG_NOTICE, cmd->cmd.syslog, argv);
					tmpcmd->rerun_pending = 1;
				}
				return;
			}
			continue;
		}

		/* Preserve the original non-FastCGI aggregate behavior. */
		aggregate += tmpcmd->aggregate;
		if (aggregate > 1) {
			if (tmpcmd->dontexec && aggregate < 3) {
				syslog(LOG_NOTICE, cmd->cmd.syslog, argv);
				tmpcmd->dontexec = 0;
				tv.tv_sec = 5;
				timeout_del(&tmpcmd->ev);
				timeout_add(&tmpcmd->ev, &tv);
			}
			return;
		}
	}

	/*
	 * Coalescing above never grows the queue, so the bound only has to be
	 * enforced on the path that allocates a new entry.  Report the
	 * transition into and out of the full state rather than every refusal:
	 * the events that fill the queue arrive in bursts, and one log line per
	 * refused event would flood syslog for as long as the condition lasts.
	 */
	if (queued >= MAX_QUEUED_COMMANDS) {
		if (!queue_full) {
			syslog(LOG_ERR,
			    "Command queue is full (%u entries); refusing new "
			    "events until it drains. Is the FastCGI server "
			    "responding?", queued);
			queue_full = 1;
		}
		return;
	}

	command = calloc(1, sizeof(*command));
	if (command == NULL) {
		syslog(LOG_ERR, "Calloc failure for command %s", argv);
		return;
	}

	if (queue_full) {
		syslog(LOG_NOTICE,
		    "Command queue has drained to %u entries; accepting new "
		    "events again", queued);
		queue_full = 0;
	}

	/* -1, not calloc()'s 0, is the sentinel for no open socket. */
	command->socket = -1;

	command->aggregate = aggregate + 1;
	//memcpy(command->command, cmd->cmd.command, sizeof(command->command));
	strlcpy(command->command, cmd->cmd.command, sizeof(command->command));
	strlcpy(command->params, command_params, sizeof(command->params));

	if (transient_serializable) {
		command->transient_serialized = 1;
		strlcpy(command->transient_interface, transient_interface,
		    sizeof(command->transient_interface));
		command->transient_desired_link_action = -1;
		command->transient_active_link_action = -1;
		transient_update_pending(command, transient_kind,
		    transient_link_action);
	}

	if (!(cmd->cmd.flags & AGGREGATE))
		command->aggregate = 0;

	switch (cmd->type) {
	case NON:
		syslog(LOG_NOTICE, "%s", cmd->cmd.syslog);
		break;
	case COMPOUND: /* XXX: Should never happen. */
		syslog(LOG_ERR, "trying to execute COMPOUND entry!!! Please report it.");
		free(command);
		return;
		/* NOTREACHED */
		break;
	case ADDRESS:
	case PREFIX:
	case INTEGER:
	case IFNAME:
	case STRING:
		if (argv != NULL)
			syslog(LOG_NOTICE, cmd->cmd.syslog, argv);
		else
			syslog(LOG_NOTICE, "%s", cmd->cmd.syslog);
		break;
	}

	TAILQ_INSERT_HEAD(&cmds, command, rq_link);

	if (command->transient_serialized) {
		tv.tv_sec = transient_initial_debounce;
		timeout_set(&command->ev, transient_dispatch, command);
	} else if (cmd->cmd.flags & FCGICMD) {
		timeout_set(&command->ev, fcgi_send_command, command);
	} else {
		timeout_set(&command->ev, run_command_detailed, command);
	}
	timeout_add(&command->ev, &tv);

	return;
}

static void
socket_close_command(int fd, struct event *ev)
{
	event_del(ev);
	free(ev);
        close(fd);
}

static void
fcgi_reset_response(struct runq *cmd)
{
	if (cmd == NULL)
		return;

	free(cmd->fcgi_record);
	cmd->fcgi_record = NULL;
	cmd->fcgi_record_len = 0;
	cmd->fcgi_record_received = 0;
	cmd->fcgi_header_received = 0;
	memset(&cmd->fcgi_header, 0, sizeof(cmd->fcgi_header));
}

static void
socket_read_fcgi(int fd, short event, void *arg)
{
        struct runq *tmpcmd = arg;
        FCGI_Header *header;
        FCGI_EndRequestBody *end_body;
        size_t content_len, record_len, remaining;
        int request_id, success;
        ssize_t n;

        if (tmpcmd == NULL)
                return;

        /* Prefer readable data if readiness and timeout arrive together. */
        if ((event & EV_TIMEOUT) && !(event & EV_READ)) {
                fcgi_response_failure(tmpcmd,
                    "the response timed out after the request was submitted");
                return;
        }

        /*
         * Restart the inactivity timeout for this activation.  Doing it once
         * here, unconditionally, keeps the deadline correct under both a
         * libevent that re-arms persistent timeouts itself and one that does
         * not, and avoids leaving the connection with no timeout at all when
         * a readable notification turns out to carry nothing.
         */
        fcgi_arm_socket_timeout(tmpcmd);

        /*
         * The FastCGI socket is non-blocking, so a single recv() is not
         * guaranteed to return either a complete header or a complete
         * record. Preserve receive state in the runq and continue parsing
         * when libevent tells us more data is available.
         */
        for (;;) {
                header = &tmpcmd->fcgi_header;

                /* Read the complete FastCGI header. */
                while (tmpcmd->fcgi_header_received < sizeof(*header)) {
                        n = recv(fd,
                            (unsigned char *)header + tmpcmd->fcgi_header_received,
                            sizeof(*header) - tmpcmd->fcgi_header_received, 0);

                        if (n > 0) {
                                tmpcmd->fcgi_header_received += (size_t)n;
                                continue;
                        }

                        if (n == 0) {
                                fcgi_response_failure(tmpcmd,
                                    "the FastCGI connection closed while waiting for a response");
                                return;
                        }

                        if (errno == EAGAIN || errno == EWOULDBLOCK ||
                            errno == EINTR)
                                return;

                        fcgi_response_failure(tmpcmd,
                            "receiving the FastCGI response header failed");
                        return;
                }

                if (header->version != FCGI_VERSION_1) {
                        syslog(LOG_ERR,
                            "Unsupported FastCGI version %u for request id=%d command=%s params=%s",
                            header->version, tmpcmd->requestId, tmpcmd->command,
                            tmpcmd->params);
                        fcgi_response_failure(tmpcmd,
                            "the response used an unsupported FastCGI version");
                        return;
                }

                content_len =
                    ((size_t)header->contentLengthB1 << 8) |
                    header->contentLengthB0;
                record_len = content_len + header->paddingLength;

                /*
                 * FastCGI contentLength is 16 bits and paddingLength is 8
                 * bits, bounding payload plus padding to 65535 + 255 bytes.
                 */
                if (tmpcmd->fcgi_record == NULL) {
                        if (record_len > 0) {
                                tmpcmd->fcgi_record = malloc(record_len);
                                if (tmpcmd->fcgi_record == NULL) {
                                        syslog(LOG_ERR,
                                            "Could not allocate %zu bytes for FastCGI response",
                                            record_len);
                                        fcgi_response_failure(tmpcmd,
                                            "response buffering failed");
                                        return;
                                }
                                tmpcmd->fcgi_record_len = record_len;
                        }
                } else if (tmpcmd->fcgi_record_len != record_len) {
                        syslog(LOG_ERR,
                            "FastCGI receive state inconsistent for request id=%d command=%s params=%s (have %zu, header says %zu)",
                            tmpcmd->requestId, tmpcmd->command, tmpcmd->params,
                            tmpcmd->fcgi_record_len, record_len);
                        fcgi_response_failure(tmpcmd,
                            "the response framing became inconsistent");
                        return;
                }

                /* Read the complete content and padding for this record. */
                while (tmpcmd->fcgi_record_received < record_len) {
                        remaining = record_len - tmpcmd->fcgi_record_received;
                        n = recv(fd,
                            tmpcmd->fcgi_record + tmpcmd->fcgi_record_received,
                            remaining, 0);

                        if (n > 0) {
                                tmpcmd->fcgi_record_received += (size_t)n;
                                continue;
                        }

                        if (n == 0) {
                                fcgi_response_failure(tmpcmd,
                                    "the FastCGI connection closed while receiving response data");
                                return;
                        }

                        if (errno == EAGAIN || errno == EWOULDBLOCK ||
                            errno == EINTR)
                                return;

                        fcgi_response_failure(tmpcmd,
                            "receiving FastCGI response data failed");
                        return;
                }

                /*
                 * Only records belonging to the request we sent may act on
                 * this command.  Consume mismatched records to keep framing
                 * synchronized, then ignore them.
                 */
                request_id =
                    ((int)header->requestIdB1 << 8) | header->requestIdB0;
                if (request_id != tmpcmd->requestId) {
                        syslog(LOG_ERR,
                            "Ignoring FastCGI record for request %d (expected %d) on %s",
                            request_id, tmpcmd->requestId, tmpcmd->command);
                        fcgi_reset_response(tmpcmd);
                        continue;
                }

                success = 0;

                switch (header->type) {
                case FCGI_DATA:
                case FCGI_STDOUT:
                case FCGI_STDERR:
                        break;
                case FCGI_ABORT_REQUEST:
                        syslog(LOG_ERR,
                            "FastCGI request id=%d command=%s params=%s was explicitly aborted; retrying",
                            tmpcmd->requestId, tmpcmd->command, tmpcmd->params);
                        fcgi_close_socket(tmpcmd);
                        fcgi_retry_command(tmpcmd);
                        return;
                case FCGI_END_REQUEST:
                        /* Padding is not part of FCGI_EndRequestBody. */
                        if (content_len < sizeof(FCGI_EndRequestBody) ||
                            tmpcmd->fcgi_record == NULL) {
                                syslog(LOG_ERR,
                                    "Short FCGI_END_REQUEST record (%zu bytes) for request id=%d command=%s params=%s",
                                    content_len, tmpcmd->requestId, tmpcmd->command,
                                    tmpcmd->params);
                                fcgi_response_failure(tmpcmd,
                                    "the FastCGI completion record was malformed");
                                return;
                        }

                        end_body =
                            (FCGI_EndRequestBody *)tmpcmd->fcgi_record;

                        switch (end_body->protocolStatus) {
                        case FCGI_CANT_MPX_CONN:
                                syslog(LOG_ERR,
                                    "The FCGI server cannot multiplex\n");
                                break;
                        case FCGI_OVERLOADED:
                                syslog(LOG_ERR,
                                    "The FCGI server is overloaded\n");
                                break;
                        case FCGI_UNKNOWN_ROLE:
                                syslog(LOG_ERR,
                                    "FCGI role is unknown\n");
                                break;
                        case FCGI_REQUEST_COMPLETE:
                                success = 1;
                                break;
                        default:
                                syslog(LOG_ERR,
                                    "Unknown FCGI protocol status %u for %s",
                                    end_body->protocolStatus, tmpcmd->command);
                                break;
                        }

                        if (success) {
                                syslog(LOG_DEBUG,
                                    "Completed FastCGI request id=%d command=%s params=%s",
                                    tmpcmd->requestId, tmpcmd->command, tmpcmd->params);
                                if (tmpcmd->transient_serialized) {
                                        transient_finish(tmpcmd, 1);
                                        return;
                                }
                                if (tmpcmd->rerun_pending) {
                                        struct timeval tv = { 5, 0 };

                                        /*
                                         * A matching aggregate event arrived
                                         * while this request was outstanding.
                                         * The completed request is done; close
                                         * its socket and schedule exactly one
                                         * fresh execution five seconds from
                                         * now rather than dropping the runq.
                                         */
                                        fcgi_close_socket(tmpcmd);
                                        tmpcmd->submitted = 0;
                                        tmpcmd->rerun_pending = 0;
                                        tmpcmd->retries = 0;
                                        timeout_del(&tmpcmd->ev);
                                        timeout_set(&tmpcmd->ev,
                                            fcgi_send_command, tmpcmd);
                                        timeout_add(&tmpcmd->ev, &tv);
                                        return;
                                }

                                fcgi_drop_command(tmpcmd);
                                return;
                        }

                        syslog(LOG_ERR,
                            "FastCGI request id=%d command=%s params=%s was explicitly not completed by the server; retrying",
                            tmpcmd->requestId, tmpcmd->command, tmpcmd->params);
                        fcgi_close_socket(tmpcmd);
                        fcgi_retry_command(tmpcmd);
                        return;
                default:
                        syslog(LOG_ERR,
                            "Ignoring unexpected FastCGI record type %u for %s",
                            header->type, tmpcmd->command);
                        break;
                }

                /*
                 * This record is complete. Reset the parser and immediately try
                 * to consume another queued record. If none is present, recv()
                 * returns EAGAIN and control returns to libevent with the
                 * inactivity timeout already armed for this activation.
                 */
                fcgi_reset_response(tmpcmd);
        }

}

static void
socket_read_command(int fd, short event, void *arg)
{
        struct command *cmd;
        struct event *ev = arg;
        enum { bufsize = 2048 };
        char buf[bufsize];
        char *argv[bufsize], *p, *token;
        size_t input_len;
        int argc, i, n;

        if (event == EV_TIMEOUT) {
                socket_close_command(fd, ev);
                return;
        }

tryagain:
        bzero(buf, sizeof(buf));
        /* Reserve the final byte so the input is always NUL terminated. */
        if ((n = read(fd, buf, bufsize - 1)) == -1) {
                if (errno == EINTR)
                        goto tryagain;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                        return;
                socket_close_command(fd, ev);
                return;
        } else if (n == 0) {
                socket_close_command(fd, ev);
                return;
        }

        input_len = (size_t)n;
        buf[input_len] = '\0';

        if (input_len > 0 && buf[input_len - 1] == '\n')
                buf[--input_len] = '\0';
        if (input_len > 0 && buf[input_len - 1] == '\r')
                buf[--input_len] = '\0';

        /* Validate every actual input byte, including a non-newline tail. */
        for (i = 0; i < (int)input_len; i++) {
                unsigned char ch = (unsigned char)buf[i];

                if (!isalpha(ch) && !isspace(ch) && !isdigit(ch) &&
                    !ispunct(ch)) {
                        write(fd, "ERROR:\tonly alphanumeric chars allowd", 37);
                        socket_close_command(fd, ev);
                        return;
                }
        }

        p = buf;
        argc = 0;
        while ((token = strsep(&p, " \t")) != NULL) {
                if (*token == '\0')
                        continue;
                if (argc >= bufsize - 1)
                        break;
                argv[argc++] = token;
        }
        argv[argc] = NULL;

        if (argc > 0) {
                p = argv[argc - 1];
                argc--;
        } else {
                p = NULL;
        }

        cmd = parse_command(fd, argc, argv);
        if (cmd != NULL) {
                write(fd, "OK\n", 3);
                run_command(cmd, p);
        }
}

static void
socket_accept_command(int fd, __unused short event, __unused void *arg)
{
	struct sockaddr_un sun;
	struct timeval tv = { 10, 0 };
	struct event *ev;
	socklen_t len;
	int newfd;

	len = sizeof(sun);
	if ((newfd = accept(fd, (struct sockaddr *)&sun, &len)) < 0) {
		if (errno != EWOULDBLOCK && errno != EINTR)
			syslog(LOG_ERR, "problems on accept");
		return;
	}
	set_blockmode(newfd, O_NONBLOCK | FD_CLOEXEC);

	if ((ev = malloc(sizeof(*ev))) == NULL) {
		syslog(LOG_ERR, "Cannot allocate new struct event.");
		close(newfd);
		return;
	}

	event_set(ev, newfd, EV_READ | EV_PERSIST, socket_read_command, ev);
	event_add(ev, &tv);
}

static char *
trim_whitespace(char *s)
{
        char *end;

        while (*s != '\0' && isspace((unsigned char)*s))
                s++;

        end = s + strlen(s);
        while (end > s && isspace((unsigned char)end[-1]))
                *--end = '\0';

        return (s);
}

struct config_setting {
        const char *name;
        int *value;
        int default_value;
        int min_value;
        int max_value;
};

static void
load_config(void)
{
        static struct config_setting settings[] = {
                { "fcgi_response_timeout", &fcgi_response_timeout,
                    FCGI_RESPONSE_TIMEOUT_DEFAULT, 1, 300 },
                { "fcgi_retry_max_delay", &fcgi_retry_max_delay,
                    FCGI_RETRY_MAX_DELAY_DEFAULT, 1, 300 },
                { "gateway_monitor_busy_retry", &gateway_monitor_busy_retry,
                    GATEWAY_MONITOR_BUSY_RETRY_DEFAULT, 1, 60 },
                { "gateway_monitor_reconcile_delay",
                    &gateway_monitor_reconcile_delay,
                    GATEWAY_MONITOR_RECONCILE_DELAY_DEFAULT, 1, 300 },
                { "transient_ambiguous_grace", &transient_ambiguous_grace,
                    TRANSIENT_AMBIGUOUS_GRACE_DEFAULT, 1, 300 },
                { "transient_initial_debounce", &transient_initial_debounce,
                    TRANSIENT_INITIAL_DEBOUNCE_DEFAULT, 0, 60 },
                { "transient_max_debounce", &transient_max_debounce,
                    TRANSIENT_MAX_DEBOUNCE_DEFAULT, 1, 300 },
                { "transient_settle_delay", &transient_settle_delay,
                    TRANSIENT_SETTLE_DELAY_DEFAULT, 0, 60 },
                { NULL, NULL, 0, 0, 0 }
        };
        struct config_setting *setting;
        FILE *fp;
        char line[512], *key, *value, *equals, *end;
        long parsed;
        unsigned int lineno = 0;
        int saw_config = 0;

        fp = fopen(CONFIG_PATH, "r");
        if (fp == NULL) {
                if (errno != ENOENT)
                        syslog(LOG_WARNING, "Could not open %s: %m", CONFIG_PATH);
                return;
        }

        while (fgets(line, sizeof(line), fp) != NULL) {
                lineno++;

                if (strchr(line, '\n') == NULL && !feof(fp)) {
                        int ch;

                        while ((ch = fgetc(fp)) != '\n' && ch != EOF)
                                ;
                        syslog(LOG_WARNING,
                            "%s:%u: line is too long; ignoring it",
                            CONFIG_PATH, lineno);
                        continue;
                }

                key = trim_whitespace(line);
                if (*key == '\0' || *key == '#')
                        continue;

                equals = strchr(key, '=');
                if (equals == NULL) {
                        syslog(LOG_WARNING,
                            "%s:%u: expected name=value; ignoring line",
                            CONFIG_PATH, lineno);
                        continue;
                }

                *equals = '\0';
                value = trim_whitespace(equals + 1);
                key = trim_whitespace(key);

                if (*key == '\0' || *value == '\0') {
                        syslog(LOG_WARNING,
                            "%s:%u: empty setting name or value; ignoring line",
                            CONFIG_PATH, lineno);
                        continue;
                }

                setting = NULL;
                for (struct config_setting *candidate = settings;
                    candidate->name != NULL; candidate++) {
                        if (strcmp(candidate->name, key) == 0) {
                                setting = candidate;
                                break;
                        }
                }
                if (setting == NULL) {
                        syslog(LOG_WARNING,
                            "%s:%u: unknown setting '%s'; ignoring it",
                            CONFIG_PATH, lineno, key);
                        continue;
                }

                errno = 0;
                parsed = strtol(value, &end, 10);
                end = trim_whitespace(end);
                if (errno == ERANGE || end == value || *end != '\0' ||
                    parsed < setting->min_value || parsed > setting->max_value) {
                        syslog(LOG_WARNING,
                            "%s:%u: invalid value '%s' for %s; expected %d..%d; using previous value %d",
                            CONFIG_PATH, lineno, value, setting->name,
                            setting->min_value, setting->max_value,
                            *setting->value);
                        continue;
                }

                *setting->value = (int)parsed;
                saw_config = 1;
        }

        if (ferror(fp))
                syslog(LOG_WARNING, "Error reading %s: %m", CONFIG_PATH);
        fclose(fp);

        if (transient_max_debounce < transient_initial_debounce ||
            transient_max_debounce < transient_settle_delay) {
                syslog(LOG_WARNING,
                    "%s: transient_max_debounce (%d) must be >= both transient_initial_debounce (%d) and transient_settle_delay (%d); using built-in defaults for all three debounce settings",
                    CONFIG_PATH, transient_max_debounce,
                    transient_initial_debounce, transient_settle_delay);
                transient_initial_debounce = TRANSIENT_INITIAL_DEBOUNCE_DEFAULT;
                transient_max_debounce = TRANSIENT_MAX_DEBOUNCE_DEFAULT;
                transient_settle_delay = TRANSIENT_SETTLE_DELAY_DEFAULT;
        }

        if (!saw_config)
                return;

        syslog(LOG_NOTICE, "Using configuration from %s", CONFIG_PATH);
        for (setting = settings; setting->name != NULL; setting++) {
                if (*setting->value != setting->default_value)
                        syslog(LOG_NOTICE, "%s=%d (default %d)",
                            setting->name, *setting->value,
                            setting->default_value);
        }
}

static void
set_blockmode(int fd, int cmd)
{
        int flags;

        if (cmd & O_NONBLOCK) {
                if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
                        err(1, "fcntl F_GETFL");
                if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
                        err(1, "fcntl F_SETFL");
        }

        if (cmd & FD_CLOEXEC) {
                if ((flags = fcntl(fd, F_GETFD, 0)) == -1)
                        err(1, "fcntl F_GETFD");
                if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
                        err(1, "fcntl F_SETFD");
        }
}

int
main(void)
{
	struct event ev;
	struct sockaddr_un sun;
	struct sigaction sa;
	mode_t *mset, mode;
	sigset_t set;
	int fd, errcode = 0;
	char *p;
	int foreground = 0;

	tzset();

	/*
	 * The foreground mode exists for isolated test harnesses.  Production
	 * startup is unchanged: daemonize and create the normal monitor child.
	 */
	if ((p = getenv("CHECK_RELOAD_STATUS_FOREGROUND")) != NULL &&
	    p[0] != '\0' && strcmp(p, "0") != 0)
		foreground = 1;

	if (!foreground && daemon(0, 0) < 0) {
		syslog(LOG_ERR, "check_reload_status could not start.");
		errcode = 1;
		goto error;
	}

	syslog(LOG_NOTICE, "check_reload_status is starting.");

	load_config();

	uname(&uts);

	if ((p = getenv("fcgipath")) != NULL) {
		fcgipath = p;
		syslog(LOG_NOTICE, "fcgipath from environment %s", fcgipath);
	}
	if ((p = getenv("controlpath")) != NULL) {
		if (p[0] == '\0' || strlen(p) >= sizeof(sun.sun_path)) {
			syslog(LOG_ERR, "invalid controlpath from environment");
			errcode = 1;
			goto error;
		}
		controlpath = p;
		syslog(LOG_NOTICE, "controlpath from environment %s", controlpath);
	}

	sigemptyset(&set);
	sigfillset(&set);
	sigdelset(&set, SIGHUP);
	sigdelset(&set, SIGTERM);
	sigdelset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, NULL);
	signal(SIGCHLD, SIG_IGN);

	sa.sa_handler = handle_signal;
	sa.sa_sigaction = handle_signal_act;
        sa.sa_flags = SA_SIGINFO|SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	ppid = getpid();
	if (!foreground && fork() == 0) {
		setproctitle("Monitoring daemon of check_reload_status");
		/* Prepare code to monitor the parent :) */
		struct kevent kev;
		int kq;

		while (1) {
			kq = kqueue();
			EV_SET(&kev, ppid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
			kevent(kq, &kev, 1, NULL, 0, NULL);
			switch (kevent(kq, NULL, 0, &kev, 1, NULL)) {
			case 1:
				syslog(LOG_ERR, "Reloading check_reload_status because it exited from an error!");
				execl("/usr/local/sbin/check_reload_status", "/usr/local/sbin/check_reload_status", (char *)NULL);
				_exit(127);
				syslog(LOG_ERR, "could not run check_reload_status again");
				/* NOTREACHED */
				break;
			default:
				/* XXX: Should report any event?! */
				break;
			}
			close(kq);
		}
		exit(2);
	}

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		errcode = -1;
		printf("Could not socket\n");
		goto error;
	}

#if 0
	if (unlink(PATH) == -1) {
		errcode = -2;
		printf("Could not unlink\n");
		close(fd);
		goto error;
	}
#else
	unlink(controlpath);
#endif

	bzero(&sun, sizeof(sun));
        sun.sun_family = PF_UNIX;
        strlcpy(sun.sun_path, controlpath, sizeof(sun.sun_path));
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		errcode = -2;
		printf("Could not bind\n");
		close(fd);
		goto error;
	}

	set_blockmode(fd, O_NONBLOCK | FD_CLOEXEC);

        if (listen(fd, 30) == -1) {
                printf("control_listen: listen");
		close(fd);
                return (-1);
        }

	/* 0666 */
	if ((mset = setmode("0666")) != NULL) {
		mode = getmode(mset, S_IRUSR|S_IWUSR | S_IRGRP|S_IWGRP | S_IROTH|S_IWOTH);
		chmod(controlpath, mode);
		free(mset);
	}

	TAILQ_INIT(&cmds);

	event_init();
	event_set(&ev, fd, EV_READ | EV_PERSIST, socket_accept_command, &ev);
	event_add(&ev, NULL);
	event_dispatch();

	return (0);
error:
	syslog(LOG_NOTICE, "check_reload_status is stopping.");

	return (errcode);
}
