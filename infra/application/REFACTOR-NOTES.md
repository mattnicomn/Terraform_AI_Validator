# AI Validator — Phase 2 Target-Architecture Terraform Refactor Notes

Branch: `migration/ai-validator-102-refactor` (local only; NOT committed/pushed).
Status: REPOSITORY EDITS ONLY. No `terraform init/plan/apply/import`, no AWS/DNS
mutations. This document records what was refactored, what is still required
before the config is deployable, and the module-status matrix.

Destination account: **102726256311** (usmissionhero-ai-dev). Account-agnostic:
account id is taken from `data.aws_caller_identity.current`, never hard-coded.

## New layout
```
bootstrap/                     # remote-state S3 bucket (LOCAL state; applied once, separately)
infra/application/             # NEW authoritative account-agnostic root
  providers.tf                 # aws + aws.us_east_1 alias; S3 backend via -backend-config
  variables.tf                 # parameterized (domain, model, cognito, buckets, alerts)
  locals.tf                    # account-id-derived names; live API surface only
  main.tf                      # composition (least-privilege, PromptHandler-only API)
  outputs.tf
modules/frontend/              # NEW: private S3 + CloudFront + OAC + dedicated ACM
modules/dns/                   # NEW: delegated ai.usmissionhero.com zone (102 side only)
modules/cognito/               # REFACTORED: auth-code only, MFA-capable, legacy inputs removed
modules/{s3,iam,lambda,api_gateway,sns_alerts,bedrock}/  # EXISTING (reused; see status)
```

## Removed (historical / source-coupled)
- Root `main.tf`, `locals.tf`, `variables.tf`, `provider.tf`, `output.tf`, `version.tf`
  (superseded by `infra/application/`). These carried:
  - hard-coded `arn:aws:iam::253881689673:role/S3AmazonAccess` (source-account coupling) — REMOVED
  - legacy Cognito callback `https://www.usmissionhero.com/index.html` and
    `https://d11k4vck88gnf5.cloudfront.net/index.html` — REMOVED
  - personal emails (`<personal-email-redacted>`) as SNS/Cognito defaults — REMOVED (now `alert_email_endpoints` var, no default)
  - repository-only API routes `/scan-file /transfer-file /classification-report /scan-bucket` — REMOVED (live API surface is PromptHandler only)
- `s3_assets_upload.tf`, `cleanup_s3_bucket.tf` (US-Mission-Hero portfolio asset
  upload + local-exec cleanup; legacy www frontend) — REMOVED
- `ssm_parameters.tf` (CloudFront signing-key SSM params) — REMOVED
  (signed-URL mechanism dropped from required initial architecture; frozen owner decision #3).

## Account-coupling removed
- Only one hard-coded source-account ARN existed in AI TF (`S3AmazonAccess`), in the
  old root cognito block — removed with the legacy root. A repo-wide grep for
  `253881689673` in `**/*.tf` now returns no matches in the AI Validator tree
  (petops-ai/petcare-hero hits are other repos, out of scope).

## Bedrock
- Model parameterized: `var.bedrock_model_id` default
  `anthropic.claude-haiku-4-5-20251001-v1:0` (EOL `claude-3-haiku-20240307` replaced).
- Access enablement/validation deferred to a later mutation/validation gate. Not enabled.

## Cognito (destination, NEW pool)
- Public client, **authorization-code flow only** (implicit removed).
- Scopes default `openid/email/profile`; `aws.cognito.signin.user.admin` only if app requires (not default).
- Callbacks/logout target `https://ai.usmissionhero.com/`. `PreventUserExistenceErrors = ENABLED`.
- MFA: design supports MFA; operational default `OPTIONAL` (software token). Owner may set `ON`/`OFF`.
- Legacy inputs removed: `s3_access_iam_role_arn`, `user_email`. Users re-established separately (frozen decision #2).

## DNS (subdomain delegation — frozen decision #5)
- `modules/dns` creates ONLY the delegated `ai.usmissionhero.com` hosted zone in account 102
  and outputs its `name_servers`. It does NOT manage the parent `usmissionhero.com` zone.
- The parent NS delegation record is owned by `website_infrastructure` (account 253) via a
  separate future gate, using the `dns_name_servers` output from this stack.

## IAM (least-privilege) — MODULE REFACTOR REQUIRED
`infra/application/main.tf` passes least-privilege inputs to `modules/iam`
(`bedrock_model_arn`, `processor_function_name`, `prompt_function_name`,
`data_bucket_arns`, `alerts_topic_arn`, `attach_extra_prompt_policies=false`).
The existing `modules/iam` still contains the broad source design and MUST be
rewritten to consume these inputs and emit scoped policies:
- Processor: logs(own group) + s3(source read / dest+results write, bucket ARNs) + sns:Publish(topic) + comprehend PII.
- PromptHandler: logs(own group) + bedrock:InvokeModel(model ARN only).
- Agent role: bedrock:InvokeModel(model) + lambda:InvokeFunction(processor ARN only). NO AdministratorAccess / FullAccess.
This module rewrite is the next edit task (kept minimal in this gate to avoid
touching all 9 modules at once).

## Unresolved inputs (must be supplied before deploy)
1. **Lambda code package provenance** — repo has NO authoritative deployable
   package for `SecurityDataTransferProcessor` / `BedrockPromptHandler`
   (`processor_s3_bucket/key`, `prompt_s3_bucket/key` default null). Source code
   origin must be identified/packaged at a deployment gate.
2. **Frontend application source** — see classification below.
3. **Bedrock agent full instruction + OpenAPI** — `openapi/security_data_transfer_api.yaml`
   exists in-repo; the agent instruction is a trimmed placeholder to restore from source.
4. **Alert email endpoint(s)** — owner-provided at apply (no default).
5. **S3 data copy** — recreate-empty now; copy is a later gate (frozen decision #1).
6. **modules/iam, modules/api_gateway, modules/bedrock, modules/lambda, modules/s3**
   input-contract alignment with the new composition (verify variable names).

## Frontend-source classification (Phase 14)
- `modules/s3/*.html|css|js` = the historical **"US Mission Hero" corporate/marketing
  portfolio site** (government/commercial pages, resume assets, references legacy
  CloudFront `d11k4vck88gnf5`). It is NOT the AI Validator application UI.
- Classification: **PARTIAL_OR_STALE** — a corporate marketing site, not the Validator SPA.
  The actual AI Validator application SPA is **NOT_PRESENT** as a clean, reusable source in this repo.
- Consequence: `modules/frontend` provides the hosting (S3+CloudFront+OAC+ACM) but the
  Validator app content is an unresolved deployment input. Do NOT treat Phase 2 as having
  produced a deployable frontend. The corporate portfolio content should NOT be deployed to
  `ai.usmissionhero.com`; it belongs (if anywhere) to `website_infrastructure`.

## Not done in this gate (by design)
- No terraform init/plan/apply/validate/fmt. No AWS calls. No DNS. No commit/push.
- Legacy `modules/s3/` marketing HTML left in place (not wired by the new root) pending an
  owner decision on whether any of it moves to `website_infrastructure`.

---

# Phase 2B — module contract alignment + least-privilege IAM (completed, edits only)

## PromptHandler Bedrock call path
- Historical (early Phase 2B) status was `PROMPT_HANDLER_BEDROCK_CALL_PATH =
  NOT_VERIFIED`: at that point no authoritative Lambda source had been recovered,
  so the PromptHandler role was left with no Bedrock permission and gated toggles.
- **RESOLVED (superseded).** The authoritative source was subsequently recovered
  and reconstructed at `src/prompt_handler/lambda_function.py`. It calls
  `bedrock-agent-runtime` `invoke_agent` (NOT `invoke_model`). The reconciled
  implementation therefore grants the PromptHandler role **`bedrock:InvokeAgent`**
  (see `modules/iam/main.tf`, `aws_iam_role_policy.prompt`), scoped to this
  account/region's agent-alias resources
  (`arn:aws:bedrock:<region>:<account>:agent-alias/*`). There are no
  `prompt_bedrock_invoke_model` / `prompt_bedrock_invoke_agent` toggles in the
  shipped module; the permission is granted directly. `bedrock:InvokeModel` is
  NOT granted to the PromptHandler role.

## IAM module — rewritten to least-privilege
- No AdministratorAccess / *FullAccess / wildcard-account ARNs remain.
- Processor role: own-log-group logs; s3 Get/GetTagging + ListBucket on source;
  PutObject/PutObjectTagging/GetObject + ListBucket on destination/results
  (bucket ARNs only); sns:Publish on the alerts topic; `comprehend:DetectPiiEntities`
  only (Resource `*` — this action does not support resource scoping).
- Prompt role: own-log-group logs + `bedrock:InvokeAgent` scoped to the
  account/region agent-alias resources (reconciled implementation; supersedes the
  earlier "gated OFF" note above).
- Bedrock agent role: `bedrock:InvokeModel` on the parameterized model ARN only,
  with an `aws:SourceAccount` trust condition. It does **NOT** get
  `lambda:InvokeFunction`: the action-group invocation is authorized on the
  LAMBDA side via `aws_lambda_permission` (principal bedrock.amazonaws.com) in
  the application root — the correct side for that relationship.
- Outputs preserved: `processor_role_arn`, `prompt_role_arn`, `bedrock_agent_role_arn`.

## Bedrock module — action group enabled + prepare gated
- Enabled `aws_bedrockagent_agent_action_group` (executor = Processor Lambda) —
  previously commented out.
- `prepare_agent` now a variable (default **false**); aliases only created when
  prepared. Rationale: preparing/aliasing requires MODEL ACCESS in 102 (later gate).
- Agent instruction remains a **PLACEHOLDER (UNRESOLVED)** — full live instruction
  not recovered (Phase 0.6). Not deployment-ready until recovered.

## Lambda module — package guard
- Added a `lifecycle.precondition`: a Zip function must have
  `code_s3_bucket` + `code_s3_key` or plan fails — prevents silently deploying a
  bogus/empty function while code-package provenance is unresolved.

## API Gateway — duplicate permission removed
- The root-level `aws_lambda_permission.apigw_invoke_prompt` was REMOVED; the
  api_gateway module already creates a per-route `aws_lambda_permission`
  (`invoke_by_apigw`). Only the Bedrock→Processor Lambda permission remains in root.

## S3 module — encryption fix
- Removed a `lookup(var.buckets[each.key], "kms_key_id", ...)` reference to a
  non-declared object attribute (would fail validate). Data buckets use SSE-S3
  (AES256)+bucket keys; KMS on data buckets is a documented future enhancement.

## Stale architecture audit
- AI-repo `.tf`: **zero** matches for 253881689673 / d11k4vck88gnf5 /
  bedrockfrontend / quarantine / private_key.pem / public_key.pem /
  AdministratorAccess / FullAccess / personal emails / www callback.
- `modules/s3/*.html` (contact/test-lazy-load/government/commercial/docs) STILL
  contain the legacy corporate/portfolio site referencing `d11k4vck88gnf5`,
  Cognito domain, old API, and personal names. Classification: **HISTORICAL_SOURCE**,
  NOT wired by the new composition. Owner decision pending on whether any moves to
  website_infrastructure. Must NOT be deployed to ai.usmissionhero.com.
  (Also present under git-ignored local-only/evidence snapshot — out of scope.)

## Backend locking
- Application backend uses S3 with `use_lockfile` (S3-native locking). Support
  requires Terraform **>= 1.10**; bootstrap `required_version >= 1.10.0` sets that
  floor, application root `>= 1.7.0`. To guarantee lockfile support the application
  init must run with Terraform >= 1.10. **BACKEND_LOCKING_MODEL = REQUIRES_TF>=1.10**
  (documented, not executed/verified). Application layer does not create its own
  backend bucket (bootstrap/ does, with local state).

## AI_VALIDATOR_SPA_SOURCE = NOT_PRESENT
- No clean AI Validator application SPA exists in-repo; only the historical
  corporate portfolio HTML. `modules/frontend` provides hosting only.

---

# Recovery — direct Bedrock Converse (replaces Agents Classic)

Amazon Bedrock **Agents Classic** is closed to new customers and cannot be
created in destination account 102726256311 (`CreateAgent` returns
`AccessDeniedException: Bedrock Agents is in Maintenance Mode`). The Stage-1
apply therefore failed on the agent resource (40/46 resources created).

**Architecture change (this branch):** the application no longer provisions a
Bedrock agent or action group. Instead:

- `src/prompt_handler/lambda_function.py` calls `bedrock-runtime` **Converse**
  directly on the cross-region inference profile
  (`us.anthropic.claude-haiku-4-5-20251001-v1:0`), with a `toolConfig`
  describing the four Processor operations.
- On a model `toolUse`, PromptHandler validates the tool name against an
  explicit allowlist (`scanFile`/`transferFile`/`getClassificationReport`/
  `scanBucket` → the identically-named Processor `operation`), invokes the
  **Processor Lambda directly** (`lambda:InvokeFunction`, RequestResponse,
  using the Processor's existing `{"operation": ...}` dispatch), returns the
  result to Converse as a `toolResult`, and loops (bounded by
  `MAX_TOOL_ROUNDS = 5`) until the model produces final text.
- Response contract unchanged: `POST /BedrockPromptHandler`, `{"prompt": ...}`
  → `{"response": ...}`. Cognito/JWT boundary unchanged at API Gateway.

**IAM:** the PromptHandler execution role now has `bedrock:InvokeModel` (on the
inference-profile ARN + regional foundation-model ARNs) and
`lambda:InvokeFunction` scoped to the Processor ARN. There is **no**
`aws_lambda_permission` for PromptHandler→Processor (same-account,
identity-based invocation). `bedrock:InvokeAgent` and the Bedrock agent
execution role are removed (`create_bedrock_agent_role = false`).

**No managed agent memory** in V1: session/orchestration is a single
request-scoped Converse loop owned by the application.

**System instruction packaging:** `agent/instruction.txt` remains the single
source of truth; `scripts/build_lambdas.py` embeds it in the PromptHandler ZIP
as `instruction.txt` (used as the Converse system prompt).

**Obsolete:** `modules/bedrock/` is no longer instantiated by the root and is
retained only as obsolete/unused code. `openapi/security_data_transfer_api.yaml`
is no longer wired into Terraform (the tool schema is defined in PromptHandler);
it remains as reference.
