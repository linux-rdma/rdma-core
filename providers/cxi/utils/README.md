# CXI launcher

`cxi_launcher` provides privileged setup and teardown for standalone CXI verbs
tests without a workload manager. It links directly to `libcxiverbs`; there is
no generic launcher, vendor plugin, or module-search environment variable.

Build with `cmake --build build --target cxi_launcher`. For an uninstalled tree:

```sh
sudo env IBV_DRIVERS=cxiverbs LD_LIBRARY_PATH="$PWD/build/lib" \
  build/bin/cxi_launcher -d rdmap1s0 --vni 42 --tc 3 -- \
  "$PWD/build/bin/ibv_ru_pingpong" -d rdmap1s0 -g 0 -c -n 1000
```

Run the same command on the peer with the server hostname appended to
`ibv_ru_pingpong`. Use `ibv_ru_rma` in place of `ibv_ru_pingpong` for RMA.
Device/VNI/TC values must agree with the intended test policy on both ends.

The ibv_ru_pingpong and ibv_ru_rma examples call the launcher themselves on
a Slingshot device: run them as `sudo ibv_ru_pingpong -d rdmap1s0 ...` (add
`-j ID` to choose the JobID/VNI). They re-run themselves under the launcher,
as the sudo user, and the second run finds `UET_JOB_FD` and starts the test.
Automatic relaunch uses only the compiled-in installation directory, never a
sibling executable from a build directory. For an uninstalled tree, invoke
the built `cxi_launcher` explicitly as in the command above.

`cxi_launcher_test` checks the descriptor-closing fallback without creating
device resources. Run it under sudo if the process hard descriptor limit is
below 70001; only forked test children raise and then lower their own limits.

The launcher must be run by root (real and effective uid 0) and exits at
once otherwise. It refuses to run if it is installed setuid or with file
capabilities, and it is never meant to be. It needs no privilege beyond
what root already has: it keeps root only to create and destroy the
service and job grant and to clean up after the command.

The parent creates a service restricted to the child UID, allocates and
exports a generic job grant, launches the child, waits for it, and
releases its owned resources. The child UID is `SUDO_UID` or `--uid`; the
command is not run as root unless `--uid 0` is given explicitly. Immediately after fork the child closes
every descriptor except stdio and the exported job grant, drops
supplementary groups, gid and uid for good, and sets no_new_privs, so
it holds no capabilities and cannot regain them. Inherited `UET_*`,
`SLINGSHOT_*` and `CXI_VERBS_*` variables are removed before the launcher
defines its own, so the caller cannot pre-set a service or job.
SIGINT/SIGTERM/SIGHUP are forwarded to the child process group, and
cleanup errors make the launch fail.

`--service ID` reuses an existing enabled service only if its UID, every VNI,
and every requested TC are permitted. The launcher does not modify or destroy
that service. There is no default-service fallback. `--tc` selects the child's
class; repeat `--allow-tc` to grant the service additional classes. The selected
class must be included. `SLINGSHOT_TCS` receives the full bitmask, while
`UET_TC` remains the selected class. Without `--allow-tc`, the selected class is
the only grant. `--create-tc` configures all granted classes on a newly owned
service. `--tc-* MAX[:RESERVED]` options set resource limits; unspecified maxima
come from device capacity, and explicit zero limits are retained. These are
administrator test grants, not Slurm's per-thread resource-budget calculation.

`--threads-per-task N` models Slurm's depth-based defaults by reserving the
per-thread resource default multiplied by N, capped at the configured maximum.
The design defaults are PTES=6, TXQS=2, TGQS=1, EQS=2, CTS=1, ACS=2, TLES=1,
and LES=16 per thread. Override them with
`--default-{ptes,txqs,tgqs,eqs,cts,acs,tles,les}`. Explicit `--tc-* MAX`
options override the maximum while retaining the depth-based reservation;
`MAX:RESERVED` supplies both values explicitly. Resource-limit calculations
apply only when creating a service, not when reusing one.

The child receives `SLINGSHOT_SVC_IDS`, `SLINGSHOT_VNIS`, `SLINGSHOT_TCS` and
the native `SLINGSHOT_DEVICES` name correlated by NID. `UET_JOB_ID`,
`UET_JOB_FD`, `UET_SERVICE_ID`, `UET_TC` and `CXI_VERBS_DEVICE` retain the current
RU example handoff. Values alone are not authorization: the service and exported
grant must permit the operations.

Repeat `--vni` to grant a step VNI and an optional shared-job VNI (up to the
native four-VNI service limit). The first value is used as the transport job
ID; every value is placed, in order, in `SLINGSHOT_VNIS` and is checked against
an existing service before reuse. The service stores the exact list, not the
min/max range around it. Multi-device provisioning, full native
membership/update/LPR management and the complete unchanged Slurm/libcxi
workflow remain separate required work.

## Optional Job Address Tables

The launcher keeps zero-entry jobs as its default. Explicit-AH requests do not
need a table. Applications choosing indexed addressing must explicitly request
a positive `max_addr_entries` with `IBV_JOB_ATTR_MAX_ADDR_ENTRIES`.
For example, `cxi_launcher --max-addr-entries 16` opts a launched job into a
16-entry table; omitting the option preserves the zero-entry default. The RU
RMA example requests 16 entries automatically when `-A` is selected.

Build `cxi_le_test` and run it without arguments for device-free checks. These
exercise omitted/zero capacity through the public API, actual provider command
encoding for explicit and indexed SEND/WRITE/READ, pre-lock address resolution,
extended-batch abort/rollback, and concurrent mock table updates/submissions.
The command ring and doorbell are ordinary memory, not hardware mappings.

With hardware-test approval, run `cxi_le_test --resources DEVICE` for the
existing explicit-AH/zero-entry resource checks. Running the same command with
`CXI_TEST_INDEXED=1` opts the sending job into a two-entry table and exercises
real insert/query/remove, duplicate/unset/out-of-bounds entries, and indexed
SEND at index 1. These resource tests alter device resources and must not be
run as part of device-free validation.

NIC RMA completion, concurrent kernel-table updates versus NIC sends, and
performance measurements remain hardware validation gates. Compare explicit-AH
and indexed paths with identical message sizes, batch sizes, thread counts,
completion handling, and device setup; report throughput, CPU time, and latency
including lookup cost. The indexed path queries the kernel for each address
snapshot rather than caching possibly stale entries. The extended API stages
requests in a reusable buffer before emission. Neither CPU-only tests nor a
successful build establish a NIC performance result. Indexed addressing must
not become the default without this comparison.

## Checkpatch Exceptions

Use the userspace exclusions in `buildlib/azp-checkpatch` when reviewing this
series. In particular, kernel type names and negative errno returns are not
the libibverbs API conventions. Do not change those contracts for checkpatch.

The following additional diagnostics are documented exceptions, not disabled
checks:

- Imported UAPI headers use portable packed attributes and explicit bit
  constants rather than kernel-private `__packed` and `BIT()` helpers.
- The command-queue status and event accesses retain `volatile` for device
  updates. The launcher's `volatile sig_atomic_t` state is shared with signal
  handlers. Removing these qualifiers is not a formatting change.
- `CXI_MATCH_ID` repeats its width argument to remain a constant expression
  in static initializers. Callers must pass a side-effect-free width.

Check each patch separately to avoid false duplicate-trailer diagnostics.
If a combined header-import patch produces type-inference diagnostics in a
later file, check that file independently before changing valid declarations.
