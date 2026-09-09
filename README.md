# check_reload_status

## What is this repo?

This is a modified version of [`check_reload_status`](https://github.com/pfsense/FreeBSD-ports/tree/devel/sysutils/check_reload_status/) along with a couple of extra bits to assist with the new functionality. It was adapted from the original `check_reload_status.c` source (part of the [pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports/) repo).

As I was unraveling a problem where my [RRD monitoring graphs would suddenly stop updating](https://forum.netgate.com/topic/201165/status-monitoring-no-monitoring-data-logged-while-in-wan-failover/20), it became clear that one of the underlying causes was this buggy CRS daemon. So I decided to try to fix them and [submit a patch](https://forum.netgate.com/topic/201294/submitting-a-pr-for-check_reload_status).

## What is check_reload_status?

I asked this [exact question](https://forum.netgate.com/topic/112573/what-is-check_reload_status/) almost 10 years ago. And yet, it's still a bit of a mystery.

Put simply, `check_reload_status` is the pfSense event dispatch daemon. It receives system events and invokes the appropriate pfSense rc scripts through PHP-FPM using FastCGI.

It handles events such as interface link changes, IP address changes,
filter reloads, gateway monitoring updates, and other system reload
requests that occur as you navigate and change the pfSense configuration using the webConfigurator. Things like reconfiguring gateways and routes when a WAN goes down (or comes back up) or an Ethernet cable gets unplugged.

There have been issues reported with this daemon (on both CE and Plus) for many years. A handful of examples are below:

- [check_reload_status 100% CPU Again](https://forum.netgate.com/topic/185816/check_reload_status-100-cpu-again-again) (2024)
- [Bug #14891: High CPU usage when interface get down and up due to proces check_reload_status](https://redmine.pfsense.org/issues/14891) (2023)
- [100% /usr/local/sbin/check_reload_status after gateway down](https://forum.netgate.com/topic/182503/100-usr-local-sbin-check_reload_status-after-gateway-down/) (2023)
- [/usr/local/sbin/check_reload_status hits high CPU usage](https://forum.netgate.com/topic/180563/usr-local-sbin-check_reload_status-hits-high-cpu-usage) (2023)
- [check_reload_status hanging with 100% CPU load](https://forum.netgate.com/topic/181782/check_reload_status-hanging-with-100-cpu-load) (2023)
- [check_reload_status using 100% of my cpu • r/PFSENSE](https://www.reddit.com/r/PFSENSE/comments/5cm6sg/usrlocalsbincheck_reload_status_using_100_of_my/) (2016)
- [Bug #2555: check_reload_status consumes 100% CPU usage](https://redmine.pfsense.org/issues/2555) (2012)

## Installing this package

I compiled a `.pkg` (amd64) that can be installed directly from your device's console with:

```
cp /usr/local/sbin/check_reload_status /usr/local/sbin/check_reload_status.orig
fetch -o check_reload_status-0.0.18.pkg https://github.com/luckman212/check-reload-status/releases/download/0.0.18/check_reload_status-0.0.18.pkg
pkg add -f check_reload_status-0.0.18.pkg
```

For now, this package is built for **amd64** architecture only. I don't have an ARM build environment set up right now. My env is newer than what pfSense 26.07 was built with, so if you skip the `-f` flag, you'll likely see this warning when trying to install:

```
Newer FreeBSD version for package check_reload_status:
To ignore this error set IGNORE_OSVERSION=yes
- package: 1600021
- running userland: 1600018
Ignore the mismatch and continue? [y/N]:
```

That is safe to answer "y" to. After it installs, you need to either reboot or respawn `check_reload_status` with e.g.
```
pkill -9 check_reload_status
nice -n20 /usr/local/sbin/check_reload_status
```

## Testing

Some people have been reporting more issues since updating to pfSense 26.07 or CE 2.9.0. Things like gateways remaining offline after WAN flaps, or CPU spikes that persist indefinitely, or dpinger suddenly disappearing. **Please test with this patched version and report back if it makes a difference for your setup.**

If you're going to file an issue, include as much detail as you can. At a minimum, the below would be useful:

- a copy of `/var/log/system.log` from around the time of the event (redacted if you want)
- a copy of each `*.out` file produced by the commands below:

```
p=$(pgrep -fx /usr/local/sbin/check_reload_status)
pgrep -alf dpinger > /tmp/dpinger_status.out
procstat -f $p > /tmp/procstat_f.out
procstat -t $p > /tmp/procstat_t.out
procstat -kk $p > /tmp/procstat_kk.out
truss -o /tmp/crs_truss_output.txt -fDp $p > /tmp/crs_truss.out
```
> _after a couple of seconds, hit Ctrl+C to stop that truss command!_

## Uninstalling / Rolling back

Copy the backup you made back in place and restart the daemon:

```
pkill -9 check_reload_status
cp /usr/local/sbin/check_reload_status.orig /usr/local/sbin/check_reload_status
nice -n20 /usr/local/sbin/check_reload_status
```

## So what was the actual problem? What did you fix?

The main problems that most users would _experience_ are:

- a runaway 100% CPU thread being eaten by `check_reload_status`
- gateways failing to return to ONLINE status after interface flaps
- services failing to restart cleanly (RRD, dpinger, unbound, etc)

Some users never experienced these problems, while others are mysteriously plagued with them constantly. That probably depends a lot on how certain hardware and ISP circuits/CPE devices behave.

The original version of check_reload_status.c assumes headers/records arrive atomically, may have issues with the size of its buffer, and re-executes failed requests without distinguishing pre-submission failures from ambiguous post-submission failures (it schedules FastCGI work after response failures without knowing whether the PHP handler already ran). Its response parser assumes basically ideal socket behavior. The upstream control socket also reads the full 2048-byte buffer without reserving a NUL byte and validates only through n-1, both of which this patch corrects.

### New Files

- `rc.gateway_monitor_reconcile`: a new rc helper that assists with ensuring gateway monitoring is left in a consistent state after coalescing multiple or out of sequence events
- `check_reload_status.conf.sample`: this file can be copied to `/usr/local/etc/check_reload_status.conf` to override some of the internal defaults (only if you understand and actually need to- most people should not need to do this!)

## More Technical Details

A more technical writeup of the changes this patch brings to the table are in [README_IF_YOU_DARE.md](./README_IF_YOU_DARE.md)

I have days and days of logs, chats, notes, test results and iterations of this patch and am trying to figure out if it's worth collating them for reference. I think the best source of truth is the C code itself, but I am happy to privately share some of the longer discussions with any developers or Netgate staff if they request it.

## AI disclosure

Although I have 40 years of computing experience (with some programming in there here and there), I'm not a C programmer by trade. I got assistance from both ChatGPT 5.6 and Claude Opus 5 with the implementation here. I guided the process using my 15 years of experience with pfSense, and tested every single change on my local pfSense+ 26.07 system to validate it. Some things worked, and some didn't. Over the course of about 10 days and dozens of iterations, I arrived at this first public version. I've been putting it through its paces and it's been very stable and survived many various real and simulated WAN flaps.

I read all of the code and understand it well enough to feel safe running this. I'm hoping to get some wider feedback on it, especially from anyone who feels they know C well enough to spot problems with the solution or at least question why a decision was made.

As part of the testing, I also built a Python test harness that started with a few tests and grew to 33 distinct "torture tests" which were validated on a live system: some errors are theoretical and others are definitely things that have been encountered in the real world like hangs, requests with only partial headers/body, floods of duplicate requests, etc.

That stress test (`fcgi_torture.py`) is also [downloadable](https://github.com/luckman212/check-reload-status/releases/download/0.0.18/fcgi_torture.py) if anyone wants to set up a FreeBSD 16 build environment, compile and test this themselves (encouraged!)

```
# assuming you compiled check_reload_status
# and placed a copy at /root on your build VM:

./fcgi_torture.py \
  --self-test \
  --daemon /root/check_reload_status
```
