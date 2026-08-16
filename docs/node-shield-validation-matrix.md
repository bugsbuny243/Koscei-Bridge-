# Node Shield validation matrix

Node Shield deliberately separates evidence classes so a weaker environment cannot be mistaken for live kernel prevention.

| Evidence class | Environment | What it proves | What it does NOT prove |
|---|---|---|---|
| Static/unit | Go test runner | scanner/runtime/policy logic and fail-closed contracts | live kernel enforcement |
| Compile/vet | Linux build container | Go backend and integration harness compile cleanly | BPF LSM availability or successful attach |
| BPF object build | compatible Linux toolchain | CO-RE sources compile and object digests are reproducible for that build | kernel accepts/attaches programs |
| Container red-team | Railway/container platform | higher-level adversarial application behavior | host BPF/LSM control |
| Privileged kernel proof | dedicated BPF LSM host | actual attach + map initialization + allow/deny behavior on the running kernel | universal security on different kernels/hardware |

Only the final class may satisfy the PR merge gate for the `pre_action_deny` claim.
