# Koschei Node Shield v0.1

Koschei Node Shield is the install-time security gate for untrusted SoloHost, Docker, and OCI workloads.

## Goal

Answer one question before execution: **what power will this workload gain over the host?**

Node Shield v0.1 is intentionally platform-neutral. Platform adapters normalize workload metadata into a common `WorkloadManifest`; the policy scanner then emits a deterministic `ALLOW`, `WARN`, or `BLOCK` report.

## Fail-closed risks

The first release blocks conditions that can collapse host isolation, including:

- privileged containers;
- Docker socket exposure;
- sensitive host mounts such as `/proc`, `/sys`, `/dev`, and Docker state;
- dangerous privilege/capability expansion;
- other critical isolation failures.

High- and medium-risk conditions such as host networking, host PID/IPC namespaces, missing immutable artifact identity, root execution, and unbounded egress produce warnings until enforcement policy is tightened.

## Provenance rule

A workload review is meaningful only when bound to an immutable artifact identity. Each scan therefore accepts an artifact SHA-256. Package updates must be treated as a new artifact and scanned again.

## Architecture

```text
SoloHost / Docker / OCI package
            |
         Adapter
            |
   WorkloadManifest
            |
     Node Shield Scan
            |
  Findings + risk score
            |
   ALLOW / WARN / BLOCK
```

The current Docker adapter consumes `docker inspect` JSON. A SoloHost adapter will be added once the package/manifest schema is stable and publicly documented.

## Non-goals for v0.1

- malware execution or detonation;
- runtime syscall enforcement;
- distributed-compute job verification;
- Pi-specific bridge logic;
- automatic installation of third-party workloads.

Those belong to later Node Shield and Verified Compute phases.
