Prefix: DOAS
Next: 7

# Open work
### DOAS-1 · P3 · Borrow policy rules during selection

- **Area:** policy · ownership
- **Where:** src/main.rs:206; src/policy.rs:111
- **Problem:** Authorization clones the whole rules vector before selection, then copies the selected permit into the next stage. The lookup already takes a borrowed slice and downstream stages do not read the rules vector.
- **Recommendation:** Borrow the rules through matching and keep ownership of the selected permit. Run the rule ordering, whole pipeline and guest execution checks.
- **Fix with:** typing-audit
- **Effort:** S

### DOAS-2 · P3 · Measure large policy check cost

- **Area:** performance · policy
- **Where:** src/config.rs:4; src/policy.rs:111; tests/cli.rs:39
- **Problem:** Valid large policies are parsed and searched without a time or CPU comparison; input limits and functional tests do not reveal a slowdown.
- **Recommendation:** Compare repeated -C checks of a representative multi-fragment large policy against a reference on a quiet Linux host, asserting the expected last-match result; use CPU sampling separately to attribute changes.
- **Fix with:** none
- **Effort:** S

### DOAS-3 · P3 · Report timestamp identity failures during clear

- **Area:** CLI · timestamp
- **Where:** src/timestamp.rs:69; src/timestamp.rs:264; src/main.rs:845
- **Problem:** Clear treats failure to derive the timestamp path as success, so a failed session or proc identity lookup can leave an approval in place while doas -L reports success. The operational trigger is unproven; the existing guest check covers an unlink failure only.
- **Recommendation:** Reproduce a timestamp identity lookup failure in a disposable Linux environment, distinguish it from an absent approval, and propagate the failure with a regression test.
- **Fix with:** error-model
- **Effort:** S

### DOAS-4 · P4 · Measure installed command startup and cached approval

- **Area:** performance · execution
- **Where:** src/main.rs:227; src/main.rs:854; harness/vm-guest-priv.sh:65
- **Problem:** Installed nopass and persisted-approval execution have functional coverage but no latency or syscall baseline, so extra setup or timestamp I/O may go unnoticed before the command starts.
- **Recommendation:** In a disposable Linux guest compare repeated successful setuid nopass and valid-persist runs of a trivial marker command against an interleaved reference, checking the marker; use a separate syscall-count trace to attribute timestamp I/O, excluding human password entry.
- **Fix with:** none
- **Effort:** M

### DOAS-5 · P4 · Observe peak memory for policy checks

- **Area:** performance · memory
- **Where:** src/config.rs:4; src/main.rs:204; tests/adversarial.rs:82
- **Problem:** Policy bounds and correctness checks do not measure peak memory; allocations and the rules clone can increase memory consumed by a large valid policy.
- **Recommendation:** Measure peak RSS of successful -C runs with representative large valid policies using a process resource counter, checking the decision; use an allocation profiler separately if growth needs attribution.
- **Fix with:** none
- **Effort:** S

### DOAS-6 · P4 · Track release binary size against a reference

- **Area:** performance · artifact
- **Where:** README.md:75; Cargo.toml:7; Dockerfile:1
- **Problem:** The README notes a historical approximate size and says it is logged rather than gated; it does not establish a reproducible current size comparison, so artifact growth can go unnoticed.
- **Recommendation:** Compare byte counts of pinned target release binaries built with identical inputs using stat or wc -c; inspect section sizes with size when growth needs attribution.
- **Fix with:** none
- **Effort:** S

