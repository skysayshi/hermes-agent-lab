---
name: agent-os-security-audit
description: |
  Evidence-first, threat-led audit for autonomous agents that can orchestrate an operating
  system through terminal, files, browser, code execution, MCP, plugins, skills, memory,
  schedulers, gateways, APIs, and subagents. Use before installation, unattended operation,
  network exposure, or granting broad host privileges.
version: 1.1.0
platforms: [linux, macos, windows]
category: security
triggers:
  - "audit this agent before installation"
  - "deep security audit"
  - "audit as an OS orchestrator"
  - "is this agent safe to run on my computer"
  - "review terminal and tool security"
  - "agent vulnerability assessment"
  - "red team this autonomous agent"
  - "audit Hermes Agent security"
  - "full host access audit"
toolsets: [terminal, web, file, delegation]
---

# Agent-as-OS-Orchestrator Security Audit

## Mission

Audit the agent as a **privileged software system**, not as a chatbot.

Primary question:

> Can attacker-controlled or merely untrusted content cause the agent to exceed the
> operator's intended authority, persist that authority, conceal the real result, or make
> recovery unreliable?

Treat model output, retrieved content, tool results, extension metadata, memory, and
subagent output as untrusted input connected to real capabilities. Produce separate
`go | constrained_go | no_go` verdicts for each deployment posture. Every material claim
must be tied to a pinned revision, code path, configuration, or reproducible test.

## Non-Negotiable Premises

1. Model output is untrusted input.
2. Prompt injection is only a lead. Trace it to privileged action, disclosure, persistence,
   cross-user impact, integrity loss, or boundary escape.
3. Approval prompts, regex deny-lists, redaction, prompt scanners, tool allow-lists, and
   model instructions are defense in depth, not containment.
4. The load-bearing boundary against an adversarial model is the operating system or an
   equivalent external isolation boundary.
5. Distinguish:
   - `host_local`: main process and tools run as the operator on the host;
   - `terminal_isolated`: terminal/file paths are isolated, while the main process or other
     execution paths may remain on the host;
   - `whole_process_isolated`: the complete agent process tree shares one enforced
     filesystem, network, process, device, credential, and inference policy.
6. A documented dangerous behavior may be a trust assumption rather than a vulnerability.
   It still affects the deployment verdict.
7. Never execute untrusted repository code on the analyst's host. Dynamic work belongs in
   a disposable whole-process sandbox with synthetic data and revocable credentials.
8. No self-approval: implementation, verification, risk acceptance, and release authority
   are separate roles.

## Engagement Contract

```yaml
engagement:
  repository: "<owner/repo or path>"
  target_ref: "<immutable commit SHA>"
  intended_decision: install | pilot | production | public_service | upgrade
  intended_deployment:
    posture: host_local | terminal_isolated | whole_process_isolated
    operating_systems: []
    unattended_operation: false
    network_exposure: none | loopback | private_network | public
    input_surfaces: []
    enabled_capabilities: []
    secrets_available: []
    persistence_enabled: []
    multi_user: false
  permissions:
    read_repository: true
    run_static_checks: true
    run_in_disposable_sandbox: true
    modify_files: false
    create_branch: false
    push: false
    publish_vulnerability: false
  exclusions: []
  unavailable_access: []
```

Infer only enough to continue read-only work. Mark assumptions. Treat a full-workstation
or unattended agent as at least `C3`, and as `C4` when compromise can affect safety,
regulated data, critical infrastructure, professional decisions, or other people.

## Required Review Passes

Use independent passes for security architecture, application security, OS/container
isolation, identity/authorization, secrets, extension and supply-chain security,
gateway/session isolation, persistence/recovery, and final acceptance. A delegated reviewer
must not share a writable workspace with the implementation agent when independence matters.

## Deployment and Extension Classification

Classify every executable extension before scoring it:

```yaml
extension:
  name:
  source: bundled | user_directory | project_directory | package_entrypoint | remote_catalog
  trust_class: bundled_core | operator_trusted_code | reviewed_third_party | untrusted
  execution_location: main_process | privileged_child | restricted_child | sandbox
  load_phase: install | discovery | import | registration | request | background
  provenance:
  version_or_digest:
  capability_grants: []
  direct_dispatch_available:
  middleware_authority:
  environment_visibility:
  filesystem_visibility:
  network_visibility:
  secret_visibility:
  update_channel:
  revocation_and_rollback:
```

Trust classes:

- `bundled_core`: part of the pinned artifact; still privileged and in audit scope.
- `operator_trusted_code`: explicit full-code trust accepted by the operator.
- `reviewed_third_party`: provenance/review exist, but authority must remain bounded.
- `untrusted`: must not execute in the privileged process or receive raw dispatch.

Do not equate `enabled`, `reviewed`, `bundled`, or a clean scanner report with confinement.
Record whether trust is documented, reasonable for the intended deployment, and revocable.

## Hermes-Oriented Audit Map

For Hermes Agent or a close fork inspect at minimum:

- `run_agent.py`, `agent/prompt_builder.py` — conversation and prompt lifecycle;
- `model_tools.py`, `tools/registry.py`, `toolsets.py` — schema exposure, gating, dispatch;
- `tools/approval.py`, terminal/file/code paths, `tools/environments/` — approval and
  claimed isolation;
- `hermes_cli/plugins.py`, middleware, hooks, skills, MCP loaders — import-time execution,
  direct dispatch, result mutation, provenance;
- `gateway/`, platform adapters, `tui_gateway/`, `acp_adapter/` — caller authorization,
  session ownership, approval resolution, reconnect/retry;
- `cron/`, memory/session state, generated skills — durable authority and revocation;
- installers, updater, lockfiles, release workflows, artifacts, SBOM/provenance;
- `SECURITY.md` and deployment documentation — claimed versus actual trust boundaries.

Reconstruct the actual import graph, process tree, and execution graph from the pinned SHA.

## Mandatory Security Invariants

Test mechanically. A credible counterexample is a finding.

```yaml
invariants:
  model_output_is_untrusted: true
  untrusted_content_cannot_grant_authority: true
  retrieved_content_cannot_change_security_policy: true
  privileged_action_requires_authenticated_actor_and_policy: true
  approval_is_bound_to_exact_action_arguments_context_and_revision: true
  post_approval_mutation_invalidates_approval: true
  session_id_is_not_authorization: true
  network_surface_fails_closed_without_allowlist: true
  unsupported_or_ambiguous_scope_hard_stops: true
  secret_values_never_enter_logs_prompts_or_lower_trust_children: true
  shell_file_code_mcp_and_extensions_match_the_claimed_isolation: true
  lower_trust_components_receive_minimum_environment: true
  executable_extension_content_and_provenance_are_visible_before_trust: true
  extension_authority_is_explicit_and_capability_bounded: true
  raw_dispatch_is_unreachable_to_lower_trust_principals: true
  execution_time_revalidates_tool_availability_and_grants: true
  configured_isolation_failure_never_falls_back_to_host: true
  prompt_or_context_assembly_has_no_execution_side_effects: true
  execution_result_cannot_claim_success_without_bound_sink_completion: true
  persistent_memory_cannot_silently_create_new_authority: true
  delegated_agent_cannot_amplify_parent_authority: true
  scheduled_task_cannot_outlive_or_exceed_its_authorization: true
  update_cannot_replace_code_without_provenance_and_rollback: true
  failed_audit_logging_blocks_or_explicitly_degrades_critical_actions: true
  cancellation_timeout_and_retry_do_not_duplicate_privileged_actions: true
  recovery_does_not_require_the_compromised_agent: true
```

## Audit Workflow

### Phase 0 — Freeze and Protect

Record commit SHA, submodules, artifact hashes, versions, configuration, and unavailable
evidence. Disable hooks and automatic package execution. Never run `curl | sh`,
`iex(irm ...)`, lifecycle scripts, plugin imports, MCP servers, or repository binaries on
the analyst host.

### Phase 1 — Reconstruct Authority

Produce:

- process and privilege tree;
- trust-boundary and data-flow diagrams;
- capability inventory by actor, session, extension, and deployment posture;
- authorization and approval flow from input surface to execution sink;
- extension trust inventory;
- raw-dispatch/alternate-execution map;
- persistence, secret, update, rollback, and evidence chains.

For every sink record:

```yaml
sink:
  path_and_symbol:
  reachable_from: []
  principal:
  authenticated_actor:
  session_identity:
  granted_tools_and_toolsets:
  availability_check:
  authorization_check:
  approval_check:
  arguments_bound_to_approval:
  input_trust_level:
  effective_arguments:
  environment_received:
  filesystem_scope:
  network_scope:
  process_scope:
  persistence:
  audit_event:
  result_integrity:
  can_claim_success_without_sink_completion:
  cancellation_semantics:
  retry_idempotency:
  claimed_boundary:
  actual_boundary:
```

### Phase 2 — Static Source-to-Sink Audit

Trace normal, alternate, error, retry, reconnect, migration, and background paths. Focus on
prompt assembly, tool exposure versus execution-time enforcement, approvals, subprocesses,
paths/symlinks, environment filtering, dynamic imports, gateway identity, cron, memory,
updates, logging, and any conversion of unknown/blocked outcomes into success.

#### Mandatory raw-dispatch sweep

Enumerate every caller of at least:

```text
registry.dispatch(
ToolRegistry.dispatch(
registered handler invocation
next_call(
subprocess / Popen / run / check_output
import_module / spec_from_file_location / exec_module
entry_points / plugin loaders
exec( / eval(
```

For each caller record principal, session, tool grants, `check_fn` state, approval context,
effective arguments, middleware, sink, and audit event. The normal model-facing gate is not
authoritative while an ungated plugin, scheduler, migration, hook, or helper can reach the
same sink.

Use manual review plus available call-graph, Semgrep/CodeQL, Bandit, dependency, secret,
SBOM, and configuration checks. Scanner output is a lead, never proof by itself.

### Phase 3 — Isolation and Fail-Open Audit

For `host_local`, enumerate the operator-account blast radius: home, SSH/GPG, browser and
cloud credentials, keychains, control sockets, mounted drives, accessibility/device APIs,
and persistence mechanisms.

For `terminal_isolated`, prove which main-process, code-execution, MCP, plugin, hook,
browser, scheduler, credential-provider, and temporary-file paths bypass the backend.

**Fail-closed requirement:** when an operator explicitly selected Docker or another isolated
backend, malformed, unreadable, unavailable, or partially initialized configuration must
make execution unavailable. It must never silently select `local`. Validate with a host
canary inaccessible from the intended sandbox.

For `whole_process_isolated`, verify non-root/rootless execution, namespaces, capabilities,
seccomp/LSM, mounts, control sockets, devices, egress/DNS, credentials, resource limits,
patch level, forensic export, restore, and external kill/revocation. “Containerized” is not
evidence when mounts or sockets recreate host authority.

### Phase 4 — Prompt and Lifecycle Purity

Treat prompt/context assembly as a pure operation unless explicitly documented otherwise.
Instrument process, network, filesystem, sandbox, and billing canaries. Building or
refreshing a prompt must not silently create environments, execute probes, access external
services, mutate durable state, or consume paid resources. If startup attestation is needed,
perform it in a controlled phase and inject a structured cached result.

### Phase 5 — Extensions and Result Integrity

Verify import/install-time execution, transitive dependencies, hidden files, symlinks,
generated/binary content, environment/secret access, direct dispatch, middleware authority,
updates, quarantine, and rollback.

Distinguish observer extensions from privileged middleware. Test whether an extension can:

- invoke a tool not exposed or granted to its session;
- execute while `check_fn` is false, stale, or unavailable;
- mutate arguments after approval;
- avoid the bound sink but return success;
- execute a sibling side effect and fabricate the displayed/audited result;
- suppress or rewrite security-relevant audit evidence.

A single-use `next_call` guard prevents one duplicate call frame; it does not sandbox the
middleware or prove end-to-end result integrity.

### Phase 6 — Identity, Approval, Sessions, and Persistence

Test missing allowlists/keys, identity normalization, group/thread confusion, session
resume/fork/redirect/reconnect, approval ownership, exact binding to command/args/cwd/env/
backend/revision/expiry, replay and TOCTOU, multiple callers, subagent inheritance, cron
creation/execution/revocation, memory poisoning, and self-created skills.

### Phase 7 — Secrets, Supply Chain, and Updates

Trace every secret copy through environment, files, keychains, prompts, logs, sessions,
children, MCP, extensions, browser state, backups, and exports. Verify minimum disclosure,
permissions, destination control, deletion, and revocation.

Trace source commit to installed bytes: lockfiles, hashes, signatures, attestations, SBOM,
pinned Actions, release permissions, package indexes, bootstrap binaries, installers,
archive extraction, partial update recovery, rollback/downgrade, and maintainer compromise.
State exactly what every one-line installer trusts and provide an offline-verifiable path.

### Phase 8 — Dynamic Adversarial Validation

Use only harmless canaries, fake credentials, loopback sinks, and disposable accounts.
Build chains from web/file/email/MCP/tool output, extension metadata/code, memory, subagent,
gateway, and scheduled payloads to shell/code execution, file access, disclosure, approval
replay, persistence, cross-session impact, SSRF, update compromise, or misleading success.

### Phase 9 — Recovery and Forensics

Test interruption, timeout, late completion, duplicate delivery, reconnect, corruption,
disk full, audit-log failure, partial update, credential loss, extension revocation, restore,
and removal of every persistence mechanism. A runbook is not recovery evidence.

### Phase 10 — Independent Re-Assessment

A fresh reviewer reproduces Critical/High findings, challenges prerequisites, searches for
sibling paths, verifies mitigations, confirms posture-specific verdicts, and checks that the
author did not accept residual risk.

## Required Dynamic Test Corpus

Statuses are strictly:
`passed | failed | blocked | inconclusive | not_run | not_applicable`.

At minimum test:

- authorized and unauthorized callers; missing allowlist; conflicting identity;
- direct and indirect prompt injection with no tool and with a privileged tool;
- command quoting, paths, symlink swap, archive traversal;
- secret canary inheritance and disallowed egress/SSRF;
- approval replay, expiry, backend/cwd/env binding, and post-approval mutation;
- session read/write/fork/approval separation and reconnect/redelivery;
- cancellation, timeout, late completion, duplicate non-idempotent retry;
- plugin/skill import-time execution and compromised update;
- cron persistence after revocation; memory poisoning and historical replay;
- corrupted update/rollback, audit-storage failure, dangerous mounts/sockets;
- resource exhaustion and recovery without the compromised runtime.

### Hermes-specific mandatory cases

1. Compare direct `registry.dispatch` with normal `handle_function_call` for the same tool.
   Record authorization, `check_fn`, toolset, approval, middleware, session identity, result
   normalization, and audit events.
2. Direct-dispatch a tool not exposed to the active session: it must be denied or assigned
   to an explicit trusted principal with a bounded grant.
3. Direct-dispatch while `check_fn` is false, stale, or unavailable: execution-time policy
   must be authoritative.
4. Attempt raw dispatch outside the caller's granted toolsets.
5. Install a harmless canary plugin whose top-level import and `register()` each attempt a
   distinct sandbox-only side effect; verify execution location and host-canary protection.
6. Use execution middleware that returns success without calling `next_call`; the result
   must be distinguishable from completed privileged execution.
7. Use middleware that mutates arguments after approval; the approval must invalidate.
8. Break explicitly selected Docker/backend configuration; no host-local canary may run.
9. Build prompts/context while monitoring process, network, filesystem, sandbox, and billing
   canaries; no undeclared side effect may occur.
10. Verify parent/subagent workspace policy, cron revocation, and host-canary access under
    whole-process isolation.

A difference between direct and normal dispatch is not automatically a vulnerability. Every
bypass must map to a documented trust assumption, explicit principal, bounded capability,
and deployment-appropriate isolation.

## Finding Contract

```yaml
finding:
  id: AGOS-###
  title:
  severity: critical | high | medium | low | informational
  confidence: A | B | C | D | E
  category:
  affected_postures: []
  affected_versions:
  boundary_claimed:
  boundary_crossed:
  attacker_prerequisites:
  user_interaction:
  attack_path:
  source:
  sink:
  affected_assets:
  blast_radius:
  evidence:
    code_locations: []
    configuration:
    reproduction:
    observed_result:
    expected_result:
  exploitability:
  impact:
  existing_controls:
  why_controls_fail:
  trust_assumption:
    documented:
    reasonable_for_intended_deployment:
    violation_is_vulnerability:
    excessive_trust_is_posture_gap:
  vulnerability_or_posture_gap:
  remediation:
    immediate_containment:
    durable_fix:
    defense_in_depth:
  verification_test:
  rollback:
  residual_risk:
  owner:
  disclosure_channel:
```

Severity follows material boundary impact, not dramatic wording. Prompt injection without a
material consequence is not Critical. Trusted in-process code is not automatically a
vulnerability; excessive or misleading trust can still make a deployment no-go.

## Scoring and Ceilings

Use weakest-link scoring across threat model, boundary integrity, authentication,
authorization, approval binding, dispatch, sandboxing, secrets, extension supply chain,
updates, sessions, persistence, forensics, recovery, and independent validation.

- No reproducible tests: maximum 5.9.
- Host-local with untrusted inputs and broad tools: maximum 6.9 deployment safety.
- Terminal-only sandbox presented as whole-agent containment: maximum 6.9.
- No independent reproduction of Critical/High paths: maximum 8.4.
- No restore/rollback exercise: maximum 8.9.
- Full production requires whole-process evidence, negative tests, provenance, operational
  history, and a named residual-risk authority.

## Output Contract

Return in this order:

A. **Executive Verdict** — pinned SHA, posture-specific safety, largest risk, strongest
control, largest unknown, next single best action, confidence.

B. **Scope, Evidence, Limitations** — artifacts, revisions, commands, environments,
unavailable evidence, assumptions, and exact statuses.

C. **Runtime and Trust Reconstruction** — process/capability tree, extension trust inventory,
authorization flow, persistence/secret/update maps, claimed-versus-actual isolation, and the
raw-dispatch map.

D. **Attack-Surface Matrix**

| Surface | Principal | Untrusted input | Authority | Sink | Persistence | Boundary | Evidence |
|---|---|---|---|---|---|---|---|

E. **Invariant Results** — status, evidence, counterexample, posture, and reproduction.

F. **Findings** — full contract, ordered by severity.

G. **Exploit Chains** —
`untrusted source → parser/context → decision → authorization/approval → sink → impact → persistence/cover-up`,
with the stop point for every posture.

H. **Deployment Verdicts** — separate decisions for personal host-local, terminal sandbox,
whole-process sandbox, unattended cron/gateway, private network, and public/multi-user.

I. **Secure Pilot Baseline** — dedicated non-admin identity or isolated host, whole-process
sandbox, narrow mounts and egress, no control socket, minimum tools, caller allowlists,
synthetic credentials, pinned extensions, persistence disabled until tested, external kill
switch, secret-minimized logs, tested uninstall/rollback/revocation. Do not invent config keys.

J. **Remediation Plan** — boundary correctness → authorization → secrets → supply chain →
persistence → observability → usability. Include owner, dependency, minimal patch, tests,
rollback, and exit criterion.

K. **Verification Record** — every method, expected/actual result, and strict status.

L. **Residual Risk and Acceptance** — named owner and exact assumptions; the auditor does not
accept risk.

M. **Final Decision**

```yaml
final_decision:
  install_now:
  pilot_only:
  production_ready:
  public_service_ready:
  mandatory_preconditions: []
  prohibited_configurations: []
  unresolved_critical_questions: []
  next_gate:
  kill_criteria: []
  confidence:
```

## Immediate No-Go / Shutdown Criteria

- unauthenticated remote dispatch or approval;
- untrusted content reaches host execution contrary to the declared posture;
- configured isolation failure silently degrades to host-local execution;
- lower-trust code reaches raw dispatch without an explicit bounded grant;
- middleware/extension fabricates successful privileged execution without trustworthy audit
  distinction;
- prompt/context construction performs undeclared execution or external side effects;
- real credentials reach lower-trust code without necessity;
- executable extension/update content or provenance is hidden;
- persistence cannot be enumerated and revoked;
- intended session/caller boundaries fail;
- audit evidence can be silently suppressed while critical actions continue;
- recovery requires trusting the compromised runtime;
- documentation materially misstates isolation.

## Minimal Invocation

```yaml
repository: "<owner/repo>"
target_ref: "<commit SHA or release>"
intended_decision: "Decide whether this agent may be installed as a full OS orchestrator"
intended_deployment:
  posture: whole_process_isolated
  operating_systems: [linux]
  unattended_operation: true
  network_exposure: private_network
  input_surfaces: [cli, web, email, gateway, repository_files, mcp]
  enabled_capabilities: [terminal, files, browser, code_execution, memory, cron, plugins, skills, mcp]
permissions:
  modify_files: false
  publish_vulnerability: false
```

Begin with the immutable target and intended posture. End with the one action that creates
the most security evidence with the least risk.
