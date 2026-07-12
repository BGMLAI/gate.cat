"""A4: ready-made veto policy presets.

Policies are DATA ONLY. Matching/decision logic lives in the engine's
policy wall (one mechanism - VETO_PIPELINE_PLAN.md). Patterns come from
real incidents in agent-framework issue trackers (e.g. the $106k AutoGen
runaway, autogen#7770; duplicate payments, crewAI#5802).

Honest line: a veto policy is only certain about what it BLOCKS, never
about what it lets through. Actions outside these patterns are NOT
"verified safe" - they are unchecked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Policy:
    """A named set of deny patterns handed to the engine's policy wall.

    ``level`` (hybrid design, council 5/5): "block" = a known-catastrophic class,
    hard stop, no prompt (rm ~/backup, dd to disk). "warn" = a class that is
    genuinely AMBIGUOUS - the same shape is sometimes fine, sometimes fatal, and
    a static pattern can't tell (e.g. `python -c "shutil.rmtree(X)"` where X may
    be a backup OR a build cache). Ambiguous-executable classes surface to the
    human instead of hard-blocking, so the middle tier stays honest and the
    silent-allow default is never used for the unknown.
    """

    name: str
    patterns: tuple[str, ...]
    reason: str  # ASCII only (D1): shown on cp1252 consoles and hook stderr
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    level: str = "block"  # "block" | "warn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "patterns": list(self.patterns),
            "reason": self.reason,
            "description": self.description,
            "params": dict(self.params),
            "level": self.level,
        }


TERRAFORM_PROD = Policy(
    name="TERRAFORM_PROD",
    patterns=(
        # apply/destroy may sit after global opts (e.g. `terraform -chdir=envs/prod
        # destroy`); lookahead requires the verb, then match prod or -auto-approve.
        # NB: `\bdestroy\b` already matches the `-destroy` flag form (the `-` is a
        # word boundary), so `terraform apply -destroy -auto-approve` is covered here.
        r"\b(terraform|tofu)\b(?=.*\b(apply|destroy)\b).*(\bprod|-auto-approve)",
        # AGENT INTERACTIVE-PROMPT BYPASS (0.4.10): a bare `terraform destroy`
        # normally stops for a human ("Enter a value: yes"). An autonomous agent
        # defeats that prompt by piping the confirmation in — `yes | terraform
        # destroy`, `echo yes | terraform destroy`, `printf 'yes\n' | tofu destroy`.
        # We key on the pipe TARGET, not the source: piping anything into
        # `terraform/tofu … destroy` has no legitimate use (destroy reads config
        # from files, never stdin) and is always an auto-confirm of an irreversible
        # teardown. Keying on the target is also robust to the engine's data-scrub
        # (quoted `'yes'` becomes __INERT__, so a source-side match would miss).
        # A bare interactive `terraform destroy` (a human answers) still passes.
        r"\|\s*(sudo\s+)?(terraform|tofu)\b(?=[^|]*\bdestroy\b)",
    ),
    reason="terraform apply/destroy against production, auto-approved, or with the "
           "interactive confirmation piped in (no human in the loop) requires a human",
    description="Blocks Terraform/OpenTofu apply/destroy touching prod, auto-approved, "
                "or with the interactive 'yes' prompt piped in (agent bypass).",
)

# SQL inter-keyword whitespace that ALSO swallows an inline `/* */` comment, so
# `DELETE/**/FROM`, `DROP/**/TABLE` (comment-obfuscation, free-hand red-team) can't
# split the keyword pair.
_SQLWS = r"(?:\s|/\*[\s\S]*?\*/)+"

DB_DESTRUCTIVE = Policy(
    name="DB_DESTRUCTIVE",
    patterns=(
        r"\bDROP" + _SQLWS + r"(TABLE|DATABASE|SCHEMA)\b",
        r"\bTRUNCATE" + _SQLWS + r"TABLE\b",
        # Unbounded DELETE: block unless a WHERE binds to THIS statement. The old
        # form `(?![\s\S]*\bWHERE\b)` scanned the ENTIRE remaining string, so a
        # WHERE anywhere later — inside a `-- comment`, a `;`-separated later
        # statement, or a string literal — falsely cleared an unbounded wipe.
        # Fail-closed: the lookahead searches only up to the first statement/comment
        # terminator (`;`, newline, `--`, `#`) for a bound WHERE. `[^;\n#-]` in the
        # run (plus an explicit non-`--` guard for a lone `-`) means a WHERE reached
        # only by crossing a `;`/comment does NOT satisfy it → the wipe stays blocked.
        r"\bDELETE" + _SQLWS + r"FROM\b(?!(?:[^;\n#-]|-(?!-))*?\bWHERE\b)",
        # Tautological WHERE = an unbounded wipe wearing a filter (round-7 free-hand:
        # `DELETE FROM accounts WHERE 1=1` passed the "has a WHERE" check yet deletes
        # every row). Catch a self-equal predicate: 1=1 / 0=0 / true / 'x'='x' /
        # col=col (same token both sides). A real filter (`id = 5`) has distinct
        # sides and is NOT matched.
        r"\bDELETE" + _SQLWS + r"FROM\b[\s\S]{0,160}?\bWHERE\b\s+"
        r"(?:1\s*=\s*1|0\s*=\s*0|true\b|'([^']*)'\s*=\s*'\1'|(\w+)\s*=\s*\2)\b",
    ),
    reason="destructive SQL (DROP/TRUNCATE/unbounded or tautological DELETE) requires a human",
    description="Blocks schema-destroying SQL and DELETE without a real WHERE clause.",
)

EMAIL_SEND = Policy(
    name="EMAIL_SEND",
    patterns=(
        r"\b(sendmail|mailx?)\b",
        r"\bsmtplib\b",
        r"messages\.send|sendEmail|send_email",
    ),
    reason="outbound email from an agent requires a human",
    description="Blocks agents from sending email autonomously.",
)

CLOUD_DESTROY = Policy(
    name="CLOUD_DESTROY",
    patterns=(
        # AWS destructive ops are `<verb>-<noun>` subcommands (terminate-instances,
        # delete-bucket) or `s3 rb`; the negative lookbehind keeps benign `--delete`
        # flags and `.../delete-after/` path segments from false-blocking
        r"\baws\b.*(?<![\w/-])(delete-|terminate-|remove-|deregister-)\w+",
        r"\baws\s+s3\s+rb\b",
        # gcloud/az: bare positional `delete` verb; excluded when it is part of a
        # filter (~delete, :delete), a flag (--delete), or a hyphenated value
        r"\bgcloud\b.*(?<![\w~:=/-])delete(?![\w-])",
        r"\baz\b.*(?<![\w~:=/-])delete(?![\w-])",
        r"\bvastai\s+destroy\b",
        # k8s: delete of any stateful/irreplaceable resource (CSO recall-gap:
        # pvc/pod/secret/sts were passing). helm uninstall/delete tears down a release.
        # Flag-tolerant: `kubectl delete` may carry interleaved flags/values before
        # the resource kind (`kubectl delete -n prod deploy x`, `kubectl --context
        # prod delete pvc x`) — the old form required the kind immediately after
        # `delete` and silently ALLOWed the flagged idiom. Require the `delete` verb
        # and a resource kind anywhere after it on the line.
        # kubectl OR the near-universal `k` alias. `\b(?:kubectl|k)\b` keeps the
        # word boundary so `awk`/`take`/`k9s` do not trip it; the `delete` lookahead
        # and a resource-kind token are still both required (a bare `k get` PASSES).
        # crd/customresourcedefinition added: deleting a CRD cascade-deletes every
        # custom resource of that type cluster-wide (finalizer teardown of the
        # backing infra) - same tier as a namespace delete.
        r"\b(?:kubectl|k)\b(?=[^\n]*\bdelete\b)[^\n]*\b(ns|namespace|deploy|deployment|"
        r"pvc|pv|pod|pods|secret|secrets|statefulset|sts|configmap|cm|job|cronjob|"
        r"service|svc|replicaset|rs|ingress|daemonset|ds|crd|crds|"
        r"customresourcedefinitions?|all)\b",
        r"\bhelm\s+(uninstall|delete)\b",
        # managed-cluster teardown wrappers: eksctl (AWS EKS) and doctl (DO managed
        # k8s) are the most common real-world way to destroy a managed cluster - the
        # native aws eks delete-cluster / az aks delete are already blocked, so these
        # wrappers must be too. `delete cluster` (verb+resource) so create/get/upgrade
        # cluster PASS. Local-dev clusters (kind/minikube/k3d) are deliberately NOT
        # here - they are trivially recreatable, blocking them would be a false-block.
        r"\beksctl\s+delete\s+cluster\b",
        r"\bdoctl\s+kubernetes\s+cluster\s+delete\b",
        # kubeadm reset reverts a node from kubeadm-initialized state (wipes
        # /etc/kubernetes certs/config, tears down static-pod manifests, removes the
        # local etcd member on a control-plane node -> on a single-CP cluster this
        # destroys all cluster state). `reset` is the only destructive kubeadm verb;
        # init/token/config/version/upgrade carry no `reset` and PASS.
        r"\bkubeadm\b[^\n]*\breset\b",
        # Argo CD `app delete ... --cascade` (the DEFAULT) deletes the Application
        # plus every live k8s resource it manages (Deployments/PVCs/Services). The
        # metadata-only `--cascade=false` (keeps the live resources) is the benign
        # twin and is EXCLUDED; app get/list/sync carry no `delete` and PASS.
        r"\bargocd\s+app\s+delete\b(?![^\n]*--cascade=false\b)",
    ),
    reason="cloud resource deletion requires a human",
    description="Blocks delete/terminate calls to AWS/GCP/Azure/vast.ai/k8s/helm/eksctl/doctl/kubeadm/argocd.",
)

# Cloud key/secret destruction (2026-07-09): CLOUD_DESTROY keys off the
# `delete`/`terminate` verbs, so the `destroy`/`disable`/`purge` forms of
# encryption-key and secret-store ops passed the gate (measured on 0.4.7).
# Destroying a KMS key makes every byte encrypted under it unrecoverable - the
# most catastrophic irreversible class there is. Promoted from the opt-in
# cloud_secrets pack (each rule tested to fire on its danger, not its benign twin).
KMS_KEY_DESTROY = Policy(
    name="KMS_KEY_DESTROY",
    patterns=(
        r"\baws\s+kms\s+(schedule-key-deletion|disable-key)\b",
        r"\bgcloud\s+kms\s+keys\s+versions\s+destroy\b",
        r"\baz\s+keyvault\s+key\s+purge\b",
    ),
    reason="destroying/disabling an encryption key makes all data encrypted under it permanently unrecoverable - requires a human",
    description="Blocks AWS KMS schedule-key-deletion/disable-key, gcloud KMS destroy, az keyvault key purge.",
)

# Audit-trail blinding (2026-07-12): disabling or deleting cloud audit logging
# is the canonical first move of a covert intrusion (MITRE T1562.008, Impair
# Defenses / Disable Cloud Logs). CLOUD_DESTROY keys on the delete-/terminate-/
# remove- VERBS, so `stop-logging` and the cloudwatch/logs/config delete-* verbs
# slip past it. Not always strictly irreversible (start-logging re-enables), but
# every event during the blind window is lost forever and the whole point is to
# act unobserved - there is no high-frequency benign counterpart, so a hard block
# (not warn) is correct. Each rule fires on its danger, not its start-/describe-/
# get- twin (aws cloudtrail start-logging / describe-trails / get-trail-status,
# aws logs describe-log-groups all PASS - they carry no stop/delete verb).
AUDIT_LOG_TAMPER = Policy(
    name="AUDIT_LOG_TAMPER",
    patterns=(
        r"\baws\s+cloudtrail\s+(?:stop-logging|delete-trail|put-event-selectors)\b",
        r"\baws\s+(?:cloudwatch|logs)\s+delete-(?:log-group|log-stream|alarms)\b",
        r"\baws\s+config\s+(?:delete-\w+|stop-configuration-recorder)\b",
        r"\baws\s+guardduty\s+delete-detector\b",
    ),
    reason="disabling or deleting cloud audit logging (CloudTrail/CloudWatch/Config/GuardDuty) blinds the audit trail - requires a human",
    description="Blocks aws cloudtrail stop-logging/delete-trail, cloudwatch/logs delete-log-group/stream/alarms, config delete-*/stop-configuration-recorder, guardduty delete-detector.",
)

SECRET_STORE_DELETE = Policy(
    name="SECRET_STORE_DELETE",
    patterns=(
        r"\bvault\s+(kv\s+)?(delete|destroy)\b",
        r"\bvault\s+kv\s+metadata\s+delete\b",
        r"\baz\s+keyvault\s+secret\s+purge\b",
        r"\bdoppler\s+secrets?\s+delete\b",
        r"\baws\s+secretsmanager\s+delete-secret\b[^\n]*--force-delete-without-recovery\b",
    ),
    reason="deleting/purging a stored secret is irreversible (and can break running services) - requires a human",
    description="Blocks Vault delete, az keyvault secret purge, doppler delete, secretsmanager force-delete.",
)

# --- Coverage-audit promotions (2026-07-09, COVERAGE_AUDIT_2026-07-09): three
# UNIVERSAL + catastrophic classes the audit found PASSING the default gate,
# promoted from opt-in packs into core per the binding business-model rule
# (universal + catastrophic -> always free core; the same rule that sent KMS/Vault
# above). CLOUD_DESTROY keys on the `delete-`/`terminate-`/`remove-` VERBS, so these
# NON-delete shapes slip past it: IAM privilege escalation (attach/put/add-binding -
# the enabler of every later irreversible action), backup destruction (restic/borg
# forget|prune, zfs destroy - deleting the recovery point), and the HTTP-API modality
# (curl -X DELETE to an identity/DNS/domain host - a delete the CLI-verb walls never
# see). Patterns ported verbatim from the tested packs (packs/iam.py, packs/backup.py,
# packs/http_api.py); each fires on its danger, not its benign twin (attach ReadOnly,
# add roles/viewer binding, restic snapshots, curl -X GET all still PASS). Stack-
# specific HTTP breadth (observability/SaaS/registry) stays a PAID pack - NOT here.

IAM_PRIVILEGE_ESCALATION = Policy(
    name="IAM_PRIVILEGE_ESCALATION",
    patterns=(
        r"\baws\s+iam\s+attach-(?:user|role|group)-policy\b[^\n]*(?:AdministratorAccess|PowerUserAccess|IAMFullAccess|:policy/Admin)",
        r"\baws\s+iam\s+put-(?:user|role|group)-policy\b[^\n]*\"Action\"\s*:\s*\"\*\"",
        r"\bgcloud\s+projects\s+add-iam-policy-binding\b[^\n]*roles/(?:owner|editor)",
        r"\bgcloud\s+(?:projects|resource-manager)\s+set-iam-policy\b",
        r"\baz\s+role\s+assignment\s+create\b[^\n]*--role\s+[\"']?(?:Owner|Contributor|User Access Administrator)",
        r"\baz\s+rest\b[^\n]*directoryRoles[^\n]*members",
        r"\bsetCustomUserClaims\b[^\n]*admin",
    ),
    reason="granting admin/owner privilege to a principal enables account-wide irreversible actions - requires a human",
    description="Blocks IAM privilege escalation: attach admin/owner policy, put wildcard inline policy, add owner/editor binding, set-iam-policy overwrite, az Owner role, Firebase admin claim.",
)

IAM_IDENTITY_TAMPER = Policy(
    name="IAM_IDENTITY_TAMPER",
    # warn (ambiguous): a real admin does deactivate an MFA device or detach a
    # policy; the failure mode is doing it to the WRONG principal (lock-out / prod
    # break), so surface to a human rather than hard-block. (delete-login-profile
    # is also caught by CLOUD_DESTROY's delete- verb, which pre-empts to block -
    # that overlap is intentional, not a duplicate to remove.)
    level="warn",
    patterns=(
        r"\baws\s+iam\s+deactivate-mfa-device\b",
        r"\baws\s+iam\s+(?:detach-(?:user|role|group)-policy|delete-login-profile)\b",
        r"\baz\s+ad\s+user\s+update\b[^\n]*--account-enabled\s+false",
        r"\bgcloud\s+projects\s+remove-iam-policy-binding\b[^\n]*roles/(?:owner|admin)",
    ),
    reason="stripping permissions, deactivating MFA, or disabling an account can break prod or lock out admins - review before running",
    description="Warns on detach-policy, deactivate-mfa-device, delete-login-profile, disable account, remove owner binding.",
)

BACKUP_DESTROY = Policy(
    name="BACKUP_DESTROY",
    # NON-delete-verb shapes CLOUD_DESTROY misses: dedicated backup tools
    # (restic/borg/velero/wal-g/pgbackrest/proxmox), filesystem snapshot
    # destruction (zfs destroy, btrfs subvolume delete), cloud snapshot/backup
    # deletion, and recursive S3 delete of a *backup* path. A recursive delete of a
    # build-cache/temp path still passes (the S3 rules require a backup keyword).
    patterns=(
        r"\brestic\b[^\n]*\b(?:forget|prune)\b",
        r"\bborg\s+(?:delete|prune|compact)\b",
        r"\bvelero\s+(?:backup|schedule)\s+delete\b",
        r"\bwal-g\s+delete\b",
        r"\bpgbackrest\b[^\n]*\bstanza-delete\b",
        r"\bproxmox-backup-client\s+(?:snapshot\s+)?forget\b",
        r"\bzfs\s+destroy\b",
        r"\bbtrfs\s+subvolume\s+delete\b",
        r"\baz\s+backup\s+(?:protection\s+disable|item\s+delete|recoverypoint)\b",
        r"\baws\s+(?:backup\s+delete-|(?:ec2|rds)\s+delete-(?:snapshot|db-snapshot|db-cluster-snapshot))",
        r"\bgcloud\s+(?:compute\s+snapshots\s+delete|sql\s+backups\s+delete)\b",
        r"\baws\s+dynamodb\s+(?:delete-backup|update-continuous-backups\b[^\n]*[Ee]nabled=false)",
        r"\baws\s+s3\s+rm\b[^\n]*--recursive[^\n]*(?:backup|snapshot|archive|/dr[-/]|disaster)",
        r"\baws\s+s3\s+rm\b[^\n]*(?:backup|snapshot|archive)[^\n]*--recursive",
    ),
    reason="deleting a backup/snapshot removes the recovery point - irreversible, requires a human",
    description="Blocks restic/borg/velero/wal-g/pgbackrest/proxmox backup deletion, zfs destroy, btrfs subvolume delete, cloud snapshot/backup deletion, and recursive S3 delete of a backup path.",
)

# HTTP-API modality: the audit's biggest structural gap - many irreversible ops act
# via a raw REST call the CLI-verb walls never see. CORE subset only (universal:
# identity providers okta/auth0/entra/firebase, DNS/registrar/domain, directory-role
# priv-esc, token revoke-all) plus a generic external-DELETE WARN as a safety net.
# HTTP_API_IDENTITY_DNS_DESTROY (block) MUST precede HTTP_API_DELETE_GENERIC (warn)
# in DOGFOOD_DEFAULTS so a core-host DELETE resolves as a hard block, not a warn.
_HTTP_CORE_HOSTS = (r"(?:\.okta\.com|auth0\.com|graph\.microsoft\.com|identitytoolkit\.googleapis|"
                    r"admin\.googleapis\.com|api\.cloudflare\.com|api\.godaddy\.com|api\.gandi\.net|"
                    r"api\.namecheap\.com|porkbun\.com|route53)")
_HTTP_CORE_PATHS = (r"(?:accounts:batchDelete|updateNs|transfer-domain|deleteRecord|"
                    r"Command=namecheap\.domains|tokens/revoke_all|/revoke_all)")
_HTTP_DEL = r"(?:-X\s*|--request\s+|-[a-zA-Z]*X\s*)DELETE\b"

HTTP_API_IDENTITY_DNS_DESTROY = Policy(
    name="HTTP_API_IDENTITY_DNS_DESTROY",
    patterns=(
        rf"\b(?:curl|wget)\b[^\n]*{_HTTP_DEL}[^\n]*{_HTTP_CORE_HOSTS}",
        rf"\b(?:curl|wget)\b[^\n]*{_HTTP_CORE_HOSTS}[^\n]*{_HTTP_DEL}",
        rf"\b(?:curl|wget)\b[^\n]*(?:-X\s*|--request\s+)(?:POST|PUT|PATCH)\b[^\n]*{_HTTP_CORE_HOSTS}",
        r"\baz\s+rest\b[^\n]*--method\s+POST[^\n]*directoryRoles[^\n]*members",
        rf"\b(?:curl|wget)\b[^\n]*{_HTTP_CORE_PATHS}",
    ),
    reason="an HTTP API call that deletes/overwrites a cloud identity, DNS record, zone, or domain is irreversible and affects everyone - requires a human",
    description="Blocks curl/wget/az-rest DELETE (and destructive POST/PUT/PATCH) to identity providers and DNS/registrar/domain APIs.",
)

HTTP_API_DELETE_GENERIC = Policy(
    name="HTTP_API_DELETE_GENERIC",
    # warn (universal safety net): an external HTTP DELETE removes a resource, but
    # the target is unknown to the gate - surface it rather than hard-block. Local
    # hosts (localhost/127.0.0.1/...) are excluded so dev loops are not warned.
    level="warn",
    patterns=(
        r"\b(?:curl|wget)\b[^\n]*(?:-X\s*|--request\s+|-[a-zA-Z]*X\s*)DELETE\b[^\n]*(?:https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])|\$\w+/|/api/|/v\d)",
    ),
    reason="an HTTP DELETE to an external API removes a resource - unchecked, review before running",
    description="Warns on curl/wget -X DELETE to any external host (universal safety net).",
)

# CSO recall-gaps 2026-07-05: git/gh/docker/registry front-ends were in the
# ActionPipeline SAFE_VERBS allow-list, so their DESTRUCTIVE subcommands passed
# as a SILENT allow (never even warn). These policies close that: a guardrail
# must not let an irreversible action through just because the binary is common.

GIT_DESTRUCTIVE = Policy(
    name="GIT_DESTRUCTIVE",
    patterns=(
        # deleting a REMOTE branch/tag (irreversible for collaborators): both the
        # `--delete` form and the `push origin :refs/...` / `push origin +ref` forms
        r"\bgit\b[^\n]*\bpush\b[^\n]*(--delete\b|(?:^|\s):(?:refs/)?|\s\+[\w/]+(?:\s|$))",
        # --mirror/--prune push makes the remote MATCH local exactly => deletes any
        # remote branch/tag not present locally (Codex round-4 under-block).
        r"\bgit\b[^\n]*\bpush\b[^\n]*\s(--mirror|--prune)\b",
        r"\bgit\s+tag\s+-d\b|\bgit\s+tag\s+--delete\b",
        # Only the CAPITAL `-D` force-deletes a branch unconditionally. The
        # lowercase `-d` is the BENIGN TWIN: git itself refuses to delete a
        # branch not fully merged, so `git branch -d merged-branch` is safe and
        # must PASS (project rule: benign twin passes). The walls run under
        # re.IGNORECASE, so a plain `-D` would also match `-d`; pin the flag
        # case-sensitively with `(?-i:-D)` (same precedent as GIT_FORCE_PUSH's
        # `(?-i:-f)` below). The dangerous `-d --force` variant is still caught
        # by the second alternative, which matches -d OR --delete followed by
        # --force regardless of case.
        r"\bgit\s+branch\s+(?-i:-D)\b|\bgit\s+branch\s+(-d|--delete)\s+[^\n]*--force",
        r"\bgit\s+update-ref\s+-d\b",
        # batch ref DELETE via `update-ref --stdin` (round-7 free-hand:
        # `git for-each-ref --format='delete %(refname)' | git update-ref --stdin`
        # wipes every branch at once). Require BOTH the --stdin batch verb AND a
        # `delete` token on the line, so benign batch ref CREATION is not matched.
        r"\bgit\b(?=[^\n]*\bupdate-ref\b[^\n]*--stdin)(?=[^\n]*\bdelete\b)",
        r"\bgit\s+reset\s+--hard\b",   # discards uncommitted work + can rewind far
    ),
    reason="deleting a remote branch/tag or hard-resetting destroys history/work - requires a human",
    description="Blocks git push --delete/:refs, tag -d, branch -D, update-ref -d/--stdin delete, reset --hard.",
)

GH_DESTRUCTIVE = Policy(
    name="GH_DESTRUCTIVE",
    patterns=(
        # permanent GitHub destruction via the gh CLI: repo/release/secret delete,
        # and the raw `gh api -X DELETE`.
        r"\bgh\s+repo\s+delete\b",
        # `delete` as its own subcommand (deletes the whole release/secret/...),
        # NOT `delete-asset` (removes one re-uploadable asset — recoverable, so
        # out of the irreversible scope). The (?!-) stops `\bdelete\b` from
        # matching the `delete` inside `delete-asset`.
        r"\bgh\s+(release|secret|ssh-key|gpg-key|label)\s+delete\b(?!-)",
        # `gh api` DELETE via the short flag (-X DELETE) OR its long-form synonym
        # (--method DELETE) — the CLI accepts both, so matching only -X was a bypass.
        r"\bgh\s+api\b[^\n]*(?:-X\s*|--method\s+)(DELETE|delete)\b",
        r"""\bglab\s+(?:repo|project)\s+delete\b|\bglab\s+api\s+-X\s*DELETE\b""",
    ),
    reason="permanent GitHub destruction (repo/release/secret delete) requires a human",
    description="Blocks gh repo/release/secret delete and gh api -X DELETE.",
)

CONTAINER_DESTROY = Policy(
    name="CONTAINER_DESTROY",
    # forced container/image/volume removal loses data + local state. warn (not
    # block): removing a throwaway container is routine, but the -f/volume forms
    # are data-losing and should reach a human.
    level="warn",
    patterns=(
        r"\bdocker\b[^\n]*\b(rm\s+-[a-z]*f|rmi\b|image\s+rm\b|volume\s+rm\b|"
        r"volume\s+prune\b|system\s+prune\b|container\s+prune\b)",
        # `docker compose down -v/--volumes` deletes named volumes = data loss
        # (Codex round-4 under-block). Covers `docker compose` and `docker-compose`.
        r"\bdocker(?:\s+compose|-compose)\b[^\n]*\bdown\b[^\n]*(?:\s-[a-z]*v\b|\s--volumes\b)",
        r"\bpodman\b[^\n]*\b(rm\s+-[a-z]*f|rmi\b|volume\s+rm\b)",
        r"""\bdocker\s+(?:image|network|builder|buildx|container)\s+prune\b(?=.*-[a-z]*f)""",
        r"""\bdocker\s+(?:swarm\s+leave\b(?=.*--force)|stack\s+rm\b)""",
        r"""\bpodman\s+(?:system\s+reset\b|volume\s+prune\b)""",
        r"""\bdocker\s+buildx\s+rm\b(?=.*(?:--all-inactive|-f))""",
    ),
    reason="forced removal of a container/image/volume can lose data - review",
    description="Warns on docker/podman rm -f, rmi, volume rm/prune, system prune.",
)

REGISTRY_PUBLISH = Policy(
    name="REGISTRY_PUBLISH",
    # publishing to a public registry is an irreversible outward release (a
    # package name/version can't be truly unpublished). warn -> human confirms.
    level="warn",
    patterns=(
        r"\b(npm|pnpm|yarn)\s+publish\b",
        r"\bnpm\s+unpublish\b",
        r"\bcargo\s+publish\b|\bcargo\s+yank\b",
        r"\btwine\s+upload\b|\bflit\s+publish\b|\bpoetry\s+publish\b",
        r"\bgem\s+push\b",
        r"\bdocker\s+push\b|\bpodman\s+push\b",
    ),
    reason="publishing to a public registry is an irreversible outward release - requires a human",
    description="Warns on npm/cargo/twine/gem/docker publish/push and unpublish/yank.",
)


# --- irreversible classes beyond rm/cloud/db (coverage gap found 2026-07-05: a
# verified independent catalog caught the deny-list at 8/20; these close disk /
# permission / runtime-delete / overwrite / encoded-exec). Patterns are scoped
# to the DANGEROUS form so benign look-alikes (dd to a file, chmod one file,
# python building a temp cache) do not false-block. ---

DISK_DESTROY = Policy(
    name="DISK_DESTROY",
    patterns=(
        # dd writing to a raw block device. Cover LVM/device-mapper/loop/md/
        # nbd/xen paths too - dd to /dev/mapper/* or /dev/dm-* destroys an
        # (often encrypted) volume just as fully as /dev/sda.
        r"\bdd\b[^\n|;&]*\bof=/dev/(sd|nvme|hd|disk|mmcblk|vd|xvd|mapper|dm-|md|loop|nbd)",
        # making a new filesystem on a device = wiping it
        r"\bmkfs(\.\w+)?\b[^\n|;&]*/dev/",
        # wiping filesystem signatures. Match combined short flags too
        # (-af, -fa): any short-flag cluster containing 'a', or --all. The
        # leading \s anchors on a flag token so device paths that happen to
        # contain '-a...' (e.g. /dev/disk/by-path/...-ata-1) do not false-block.
        r"\bwipefs\b[^\n|;&]*\s(?:-[a-zA-Z]*a[a-zA-Z]*|--all)\b",
        # low-level blk discard / secure erase of a device. No \b before
        # /dev/ (a space before the path is not a word boundary, which let
        # "blkdiscard /dev/sda" slip through) - match like the mkfs line.
        r"\bblkdiscard\b[^\n|;&]*/dev/",
        # GPT/MBR partition-table nuke: sgdisk -Z/--zap-all (both -z zap and -Z
        # zap-all are destructive), -o/--clear (new empty GPT), -g/--mbrtogpt.
        # The final class is case-PINNED to [Zzog] (?-i:...) because sgdisk flag
        # case is significant and the walls run IGNORECASE: a plain [Zog] would
        # also match the READ-ONLY -O/--print-mbr (benign twin - just dumps the
        # MBR) and -G/--randomize-guids, false-blocking a print. Read-only forms
        # (-p print, -i info, -l list, -O print-mbr) carry no z/Z/o/g and pass.
        r"\bsgdisk\b[^\n|;&]*(?:--zap-all|--clear|--mbrtogpt|\s-[a-zA-Z]*(?-i:[Zzog]))[^\n|;&]*/dev/",
        # NVMe secure-format erases the whole namespace ("nvme format /dev/..").
        # Read-only nvme (list, id-ctrl, smart-log) has no "format" verb.
        r"\bnvme\s+format\b[^\n|;&]*/dev/",
        # ATA secure erase via hdparm --security-erase[-enhanced]. Identify/read
        # forms (hdparm -I) don't carry --security-erase.
        r"\bhdparm\b[^\n|;&]*--security-erase",
        # cryptsetup luksErase / luksFormat destroys the LUKS header => the
        # volume's data is cryptographically unrecoverable. luksDump/status/open
        # do not match.
        r"\bcryptsetup\b[^\n|;&]*(?:luks(?:erase|format)|\berase\b)",
        # GENERIC raw-device write (free-hand red-team 2026-07-07): DISK_DESTROY
        # was TOOL-based (dd/wipefs/...) and missed the real invariant - ANY write
        # to a raw block device. A shell redirect to /dev/sd* (`cat /dev/urandom >
        # /dev/sda`, `echo x > /dev/sda`), `tee /dev/sda`, or `cp <src> /dev/sda`
        # (device as the destination arg) destroys the disk just the same.
        r">\s*/dev/(?:sd|nvme|hd|mmcblk|vd|xvd|mapper|dm-|md|loop|nbd)",
        r"\btee\b[^\n|;&]*\s/dev/(?:sd|nvme|hd|mmcblk|vd|xvd|mapper|dm-|md|loop|nbd)",
        r"\bcp\b[^\n|;&]*\s/dev/(?:sd|nvme|hd|mmcblk|vd|xvd|mapper|dm-|md|loop|nbd)\w*\s*$",
        # partition-table / LVM / RAID destroyers (parted mklabel/rm, lvremove,
        # vgremove, pvremove, mdadm --zero-superblock) - all irreversible.
        r"\bparted\b[^\n|;&]*\s(?:mklabel|mkpart|rm|resizepart|mkpartfs)\b",
        r"\b(?:lvremove|vgremove|pvremove)\b",
        r"\bmdadm\b[^\n|;&]*--zero-superblock",
    ),
    reason="writing to or formatting a raw disk device destroys all data - requires a human",
    description="Blocks dd/mkfs/wipefs/blkdiscard/sgdisk/nvme/hdparm/cryptsetup + any redirect/tee/cp to /dev/*, parted/lvremove/mdadm.",
)

PERMISSION_LOCKOUT = Policy(
    name="PERMISSION_LOCKOUT",
    patterns=(
        # recursive chmod to a no-access or world-writable mode on a real tree
        # (000/700-style lockout, 777 world-open); the -R makes it a tree-wide
        # irreversible access change. One-file chmod is not matched.
        # -R is left case-INSENSITIVE on purpose (unlike git branch -D/sgdisk -Z):
        # chmod/chown have no benign lowercase -r flag (lowercase r is a symbolic
        # MODE bit like a+r, never a flag token here - the pattern also requires
        # a following octal mode / system path), so both cases are equally the
        # recursive lockout. Deliberate, not a case-sensitivity gap.
        r"\bchmod\b[^\n|;&]*\s-\w*R\w*\s[^\n|;&]*\b(000|00[0-7]|777|666)\b",
        # recursive chown of a home/system tree away from the owner
        r"\bchown\b[^\n|;&]*\s-\w*R\w*\s[^\n|;&]*(/home/|/etc\b|/usr\b|/var\b|~|\$HOME)",
    ),
    reason="recursive permission/ownership change on a real tree can lock you out - requires a human",
    description="Blocks chmod -R 000/777 and chown -R on home/system trees.",
)

RUNTIME_DELETE = Policy(
    name="RUNTIME_DELETE",
    patterns=(
        # deleting via a language runtime instead of rm (shutil.rmtree, os.remove
        # of a real path, Path.unlink) - the classic rm-allowlist bypass
        r"shutil\.rmtree\s*\(",
        r"os\.(remove|unlink|rmdir)\s*\(",
        r"\bPath\([^)]*\)\.(unlink|rmdir)\s*\(",
        # perl / ruby / node / php delete of files. node: include rmdir (round-7
        # free-hand missed `fs.rmdirSync("/var",{recursive:true})` - the old
        # `(unlink|rm)Sync?` had no rmdir). ruby: FileUtils.rm_rf/rm_r/remove_* and
        # File.delete/unlink. php: unlink()/rmdir().
        r"\bperl\b[^\n]*\bunlink\b",
        # node: the `...Sync(` deleters (rmdirSync/rmSync/unlinkSync) by NAME so
        # `require("fs").rmdirSync(...)` matches regardless of how fs is referenced,
        # plus the async `fs.rm/unlink/rmdir(` form.
        r"\bnode\b[^\n]*\b(?:unlink|rmdir|rm)Sync\s*\(",
        r"\bnode\b[^\n]*\bfs(?:\.promises)?\.(?:unlink|rm|rmdir)\s*\(",
        r"\bruby\b[^\n]*\bFileUtils\.(?:rm_rf|rm_r|rm_f|rm|remove_dir|remove_entry(?:_secure)?)\b",
        r"\bruby\b[^\n]*\bFile\.(?:delete|unlink)\b",
        r"\bphp\b[^\n]*\b(?:unlink|rmdir)\s*\(",
        # runtime shell-out to rm via subprocess/os.system (Codex round-4: a python
        # heredoc `subprocess.run(['rm','-rf',...])` slipped past every wall).
        r"subprocess\.\w+\s*\(\s*\[[^\]]*['\"]rm['\"][^\]]*-[a-z]*[rf]",
        r"\bos\.(system|popen)\s*\(\s*['\"][^'\"]*\brm\b[^'\"]*\s-[a-z]*[rf]",
    ),
    reason="deleting through a language runtime - unchecked, review before running",
    description="Warns on shutil.rmtree / os.remove / Path.unlink / perl-node unlink.",
    level="warn",  # ambiguous: X may be a backup OR a build cache - surface to human
)

OVERWRITE_DESTROY = Policy(
    name="OVERWRITE_DESTROY",
    patterns=(
        # truncating a real data/config file in place (persistent path, not /tmp)
        r"\btruncate\b[^\n|;&]*-s\s*0\b[^\n|;&]*(/var/|/etc/|/home/|/opt/|/srv/|\.env\b|\.dat\b|\.db\b)",
        # emptying a persistent file via a redirect from /dev/null, `:`, or an
        # empty echo/printf (free-hand red-team: `echo '' > ...`/`printf '' > ...`
        # were missed - only cat/dev/null and `:` were covered).
        r"(?:cat\s+/dev/null|:|echo(\s+-n)?\s*(''|\"\")?|printf\s*(''|\"\")?)\s*>\s*[^\n|;&]*(/var/|/etc/|/home/|/opt/|/srv/|\.env\b)",
        # overwriting a CRITICAL system file via ANY single-`>` redirect bricks the
        # host (passwd/shadow/sudoers/fstab/hosts, bootloader). `>>` (append) and
        # reads are not matched.
        r"(?<!>)>\s*(?:/etc/(?:passwd|shadow|gshadow|sudoers|fstab|hosts|crontab)\b|/boot/)",
        # rsync --delete INTO a system/data dir from an empty/other source = wipe.
        # round-7 free-hand added /etc//boot//usr//opt (only /home//srv//var/ were
        # covered, so `rsync -a --delete /tmp/ /etc/` mirror-wiped /etc as allow).
        r"\brsync\b[^\n|;&]*--delete\b[^\n|;&]*(/home/|~|\$HOME|/srv/|/var/|/etc/|/boot/|/usr/|/opt/)",
        # moving a real path onto /dev/null (discard)
        r"\bmv\b[^\n|;&]*\s/dev/null\b",
        # in-place edit (sed -i / perl -i) of a CRITICAL system file rewrites/empties
        # it (round-7: `sed -i '1,$d' /etc/fstab` deletes every line). `>>`/reads
        # not matched; scoped to the auth/boot files, so ordinary `sed -i` edits
        # elsewhere stay allowed.
        r"\b(?:sed|perl)\b[^\n|;&]*\s-i\w*\b[^\n|;&]*"
        r"(?:/etc/(?:passwd|shadow|gshadow|sudoers|fstab|hosts|crontab)\b|/boot/)",
        # tee INTO a critical system file overwrites it (round-7: `cat /dev/null |
        # tee /etc/hostname`). Covers -a (append) too - both corrupt auth/boot files.
        r"\btee\b[^\n|;&]*\s(?:-a\s+)?/etc/(?:passwd|shadow|gshadow|sudoers|fstab|hosts|hostname|crontab)\b",
        # SYMLINK INDIRECTION (round-7 free-hand): `ln -sf /etc/shadow /tmp/x &&
        # shred /tmp/x` destroys the TARGET's contents through the link. Only verbs
        # that WRITE THROUGH a symlink count (shred/truncate/dd/tee/redirect); `rm`
        # on a symlink removes the LINK, not the target, so it is deliberately
        # excluded (not destructive to the protected file).
        r"\bln\b[^\n]*\s-s\w*\s[^\n]*"
        r"(?:/etc/(?:passwd|shadow|gshadow|sudoers|fstab|hosts|crontab)|/etc/ssh/|"
        r"/root/\.ssh/|\.ssh/authorized_keys|/boot/)"
        r"[\s\S]*(?:&&|;|\|)[\s\S]*\b(?:shred|truncate|dd|tee)\b",
    ),
    reason="overwriting or emptying a persistent file/dir destroys its contents - requires a human",
    description="Blocks truncate -s0, cat /dev/null > file, rsync --delete into system dirs, sed -i / tee on critical files, symlink-then-shred, mv to /dev/null.",
)

# Any interpreter that will EXECUTE piped code. Non-sh interpreters (python/perl/
# ruby/node/php/pwsh) are equally RCE when fed downloaded/decoded source, but were
# omitted — `curl ... | python` and `base64 -d | perl` bypassed ENCODED_EXEC. One
# shared alternation so the curl-pipe and base64-pipe sets cannot drift apart.
_INTERP = r"(?:sh|bash|zsh|dash|ash|fish|python\d?|perl|ruby|node|php|pwsh|powershell)"

ENCODED_EXEC = Policy(
    name="ENCODED_EXEC",
    patterns=(
        # decoding base64/hex and piping into an interpreter = opaque remote/hidden code
        r"\bbase64\b[^\n]*-d[^\n]*\|\s*(sudo\s+)?" + _INTERP + r"\b",
        r"\bxxd\b[^\n]*-r[^\n]*\|\s*(sudo\s+)?" + _INTERP + r"\b",
        # $(...) that base64-decodes then runs (bash -c "$(echo ...|base64 -d)")
        r"\$\(\s*(echo|printf)[^\n]*\|\s*base64\s+-d\s*\)",
        # curl/wget piped straight into an interpreter (remote code execution)
        r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?" + _INTERP + r"\b",
        # PowerShell encoded command: powershell -enc / -e / -EncodedCommand <b64>
        # runs a hidden script (classic Windows evasion). The long base64 arg
        # anchors it so "-ExecutionPolicy Bypass" alone does not match.
        r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n|;&]*\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{12,}",
    ),
    reason="executing decoded/downloaded content runs code you cannot see - requires a human",
    description="Blocks base64|interpreter, hex|sh, $(...|base64 -d), curl|interpreter, powershell -enc.",
)


def PAYMENTS(max_amount: float = 0.0, currency: str = "USD") -> Policy:
    """Payment guard. With the default ``max_amount=0`` every payment-shaped
    action is blocked; a higher ceiling is recorded in ``params`` for the
    engine's policy wall to enforce (duplicate-payment class, crewAI#5802).
    """
    return Policy(
        name="PAYMENTS",
        patterns=(
            # underscore-tolerant: real tool names look like create_payment,
            # payment.create, execute_transfer - \b alone misses those
            r"(charge|payment|payout|transfer|refund)s?[\s_.:-]*(create|execute|send|post)",
            r"(create|execute|send|post|make)[\s_.:-]*(charge|payment|payout|transfer|refund)",
            r"stripe\.(charges|paymentintents|transfers)",
        ),
        reason=f"payment above {max_amount:g} {currency} (or unparseable) requires a human",
        description="Blocks payment execution; ceiling enforced by the engine policy wall.",
        params={"max_amount": max_amount, "currency": currency},
    )


# B1a dogfooding set - mirrors the founder's own CLAUDE.md safety rules.
GIT_FORCE_PUSH = Policy(
    name="GIT_FORCE_PUSH",
    # `push` may follow global opts (`git -C /repo push --force`); require a
    # force flag that is not --force-with-lease. The short `-f` is matched
    # case-sensitively via (?-i:-f) so `git commit -F file && git push`
    # (message-from-file, a benign, common op) does NOT false-block.
    patterns=(r"\bgit\b(?=.*\bpush\b).*(--force(?!-with-lease)|(?<!\w)(?-i:-f)(?!\w))",),
    reason="git push --force (without --force-with-lease) requires a human",
    description="Blocks history-destroying force pushes.",
)

RM_RF = Policy(
    name="RM_RF",
    # Flags are matched as TOKENS: '-' preceded by start/whitespace/quote (the
    # quote keeps `rm "-rf" /` caught). The old any-substring lookahead
    # false-blocked '-fr'/'-rf' INSIDE filenames - `rm /tmp/pypirc-fresh`
    # vetoed live on 2026-07-09. [^\n|;&]* keeps the match inside one command
    # segment, so `rm x && tar -rf a.tar y` is not blamed on rm.
    patterns=(
        # one combined flag token: -rf, -fr, -rfv, -vrf, -Rfi, ...
        r"\brm\b[^\n|;&]*(?<![^\s'\"])-[a-z]*(?:r[a-z]*f|f[a-z]*r)[a-z]*",
        # split flag tokens, either order: -r ... -f / -f ... -r (incl. -rv -f)
        r"\brm\b[^\n|;&]*(?<![^\s'\"])-[a-z]*r[a-z]*[^\n|;&]*(?<![^\s'\"])-[a-z]*f",
        r"\brm\b[^\n|;&]*(?<![^\s'\"])-[a-z]*f[a-z]*[^\n|;&]*(?<![^\s'\"])-[a-z]*r",
        r"""\bgit\s+push\b[^\n]*\s\+[\w./-]+:[\w./-]+""",
    ),
    reason="recursive force delete requires a human",
    description="Blocks rm -rf and flag-order variants.",
)

# --- recall-gap classes (added 2026-07-05 after an adversarial pass found the
# gate PASSING 10 irreversible actions). The product's #1 metric is recall - a
# danger that slips through is the fatal error - so each of these is now caught.
# level="block" for the unambiguously catastrophic, "warn" (surface to a human)
# for classes that CAN be legitimate in context.

SECRET_DELETE = Policy(
    name="SECRET_DELETE",
    patterns=(
        # deleting SSH/GPG/cloud private keys or credential stores = irreversible
        # loss of identity/access. rm/shred/mv-to-null of a key or credential path.
        r"\b(rm|shred|unlink|mv)\b[^\n|;&]*(\.ssh/|/\.ssh\b|id_rsa|id_ed25519|id_ecdsa|"
        r"\.aws/credentials|\.gnupg|\.config/gcloud|\.kube/config|\.netrc|\.pgpass)",
        # gpg deleting a secret key
        r"\bgpg\b[^\n]*--delete-secret",
    ),
    reason="deleting an SSH/GPG/cloud private key or credential store is irreversible - requires a human",
    description="Blocks rm/shred/mv of private keys and credential files, gpg --delete-secret-keys.",
)

HISTORY_WIPE = Policy(
    name="HISTORY_WIPE",
    patterns=(
        # destroying git history (reflog expire/gc prune, filter-branch/repo)
        r"\bgit\b[^\n]*\b(reflog\s+expire|filter-branch|filter-repo)\b",
        r"\bgit\s+gc\b[^\n]*--prune=(now|all|=)",
        # shell/log history destruction
        r"\bhistory\s+-c\b",
        r">\s*~?/?\.(bash|zsh|sh)_history\b",
        r"\btruncate\b[^\n|;&]*-s\s*0\b[^\n|;&]*\.log\b",
    ),
    reason="wiping git/shell/log history destroys an audit trail irreversibly - requires a human",
    description="Blocks git reflog expire / gc --prune=now / filter-branch, history -c, log truncation.",
)

DATASTORE_FLUSH = Policy(
    name="DATASTORE_FLUSH",
    patterns=(
        # redis FLUSHALL/FLUSHDB - wipes a whole datastore
        r"\bFLUSHALL\b|\bFLUSHDB\b",
        r"\bredis-cli\b[^\n]*\bflush(all|db)?\b",
        # mongo drop collection / database
        r"\bdb\.[\w.]+\.drop\s*\(|\bdropDatabase\s*\(",
        # unbounded deleteMany({})/remove({}) wipes an entire collection (Codex
        # round-4 under-block). Empty filter only - a bounded {status:...} is fine.
        r"\bdb\.[\w.]+\.(?:deleteMany|remove)\s*\(\s*\{\s*\}\s*\)",
    ),
    reason="flushing/dropping a datastore erases all its data irreversibly - requires a human",
    description="Blocks redis FLUSHALL/FLUSHDB, mongo .drop()/dropDatabase()/deleteMany({}).",
)

SYSTEM_TAMPER = Policy(
    name="SYSTEM_TAMPER",
    # These CAN be legitimate ops (a real admin disables a service, removes a
    # user), so WARN (surface to a human) rather than hard-block - but they are
    # never silent-allow, which is the recall failure we are closing.
    level="warn",
    patterns=(
        r"\buserdel\b|\bdeluser\b",
        r"\bsystemctl\s+(disable|mask)\b",
        r"\bchattr\s+[-+][^\n]*i\b",       # +i locks a file, -i near a system path
        r"\bcrontab\s+-r\b",               # removes ALL cron jobs, no confirm
        # firewall teardown. iptables -F (uppercase) = flush ALL rules. Pin the
        # flag case-sensitively (?-i:-F): the walls run IGNORECASE, and lowercase
        # -f/--fragment is a BENIGN rule-matching option (`iptables -A INPUT -f
        # -j DROP`) - a different flag entirely, not a firewall teardown.
        r"\bufw\s+(disable|reset)\b|\biptables\s+(?-i:-F)\b",  # firewall teardown
        r"\bkill\b[^\n]*\s-9?\s*1\b|\bkill\s+-(KILL|9)\s+1\b",  # kill init (pid 1)
        r"""\bip\s+link\s+delete\b""",
        r"""\bip\s+route\s+flush\b""",
    ),
    reason="disabling a service / removing a user / firewall teardown / crontab -r may be irreversible - review",
    description="Warns on userdel, systemctl disable/mask, chattr +i, crontab -r, firewall flush.",
)

SECRET_READ = Policy(
    name="SECRET_READ",
    # READ-exfiltration: reading/piping a private key or credential store is not
    # a delete, but it discloses a secret irreversibly (once read/sent it's out).
    # warn (not block): `cat .env` is common in dev - but a private key / shadow /
    # cloud-creds read, or piping any of these to the network, must reach a human.
    level="warn",
    patterns=(
        # reading a private key / credential file with a display or encode tool
        r"\b(cat|less|more|head|tail|strings|xxd|od|base64|nc|ncat)\b[^\n|;&]*"
        r"(id_rsa|id_ed25519|id_ecdsa|\.ssh/[^\n]*key|\.aws/credentials|\.gnupg|"
        r"/etc/shadow|\.pem\b|\.p12\b|\.pfx\b|\.netrc|\.pgpass|/etc/passwd\b)",
        # piping ANY file to the network as a data body (curl -d @file, wget POST).
        # -T/--upload-file (uppercase) uploads a file. Pin (?-i:-T) - the walls run
        # IGNORECASE and lowercase -t/--telnet-option is a BENIGN twin (a different
        # curl flag), so a plain -T would false-warn on `curl -t ... telnet://`.
        r"\bcurl\b[^\n]*(-d\s*@|--data(-binary|-raw)?\s*@|(?-i:-T)\s|--upload-file\s)",
        # exfil of a secret-looking file over a raw socket / to a remote host
        r"\b(scp|rsync)\b[^\n]*(id_rsa|\.aws/credentials|\.env\b|\.pem\b)[^\n]*@",
    ),
    reason="reading/sending a private key or credential file discloses a secret - requires a human",
    description="Warns on cat/base64 of id_rsa/.aws/shadow/.pem, curl -d @file, scp of a key.",
)

PACKAGE_PURGE = Policy(
    name="PACKAGE_PURGE",
    level="warn",  # legitimate in dev; but --purge of a system pkg can break a host
    patterns=(
        r"\bapt(-get)?\b[^\n]*\bremove\b[^\n]*--purge|\bapt(-get)?\s+purge\b",
        r"\bdpkg\b[^\n]*\s-r\b|\bdpkg\b[^\n]*--purge",
        r"\byum\b[^\n]*\bremove\b|\bdnf\b[^\n]*\bremove\b",
        # docker wiping volumes = data loss (not just containers)
        r"\bdocker\b[^\n]*\b(volume\s+(rm|prune)|system\s+prune)\b[^\n]*(-f|--volumes)",
    ),
    reason="purging a system package or docker volumes can destroy data/host state - review",
    description="Warns on apt/dpkg/yum purge, docker volume prune/rm -f.",
)

# A write-shaped verb followed (same command segment) by an auto-exec target.
# Two forms feed this wall: the Claude Code hook flattens Write/Edit to
# "write <path>" / "edit <path>", and Bash writes go via redirect/tee/cp/mv/
# install. Read-shaped access (cat/grep/source/ls) deliberately does NOT match.
_WRITE_SHAPED = (
    r"(?:(?:^|[\n;&|]\s*)(?:write|edit)\s"      # hook form: "write <path>"
    r"|>>?\s*"                                   # shell redirect into the file
    r"|\btee\b[^\n;&|]*\s"                       # tee / tee -a
    r"|\b(?:cp|mv|install|ln)\b[^\n;&|]*\s)"     # copy/move/link into place
)

AUTOEXEC_WRITE = Policy(
    name="AUTOEXEC_WRITE",
    # warn, not block (content-vs-command, 0.4.0): writing a file is data - the
    # danger is a TARGET that gets executed later without any Bash step the gate
    # would see (git commit fires .git/hooks/*, a new shell sources rc files,
    # cron/systemd fire on schedule, Claude Code runs hooks from settings.json -
    # editing that last one can silently disarm this very gate). Authoring these
    # files is often legitimate (dotfiles repos, deploy units), so the ambiguous
    # class surfaces to the human instead of hard-blocking.
    level="warn",
    patterns=(
        _WRITE_SHAPED + r"[^\n;&|]*\.git[/\\]hooks[/\\]",
        _WRITE_SHAPED + r"[^\n;&|]*(?:\.bashrc|\.bash_profile|\.bash_login"
        r"|\.profile|\.zshrc|\.zshenv|\.zprofile|\.zlogin)\b",
        _WRITE_SHAPED + r"[^\n;&|]*(?:/etc/cron|/var/spool/cron)",
        _WRITE_SHAPED + r"[^\n;&|]*\bsystemd[/\\](?:system|user)[/\\]",
        _WRITE_SHAPED + r"[^\n;&|]*\.claude[/\\]settings(?:\.local)?\.json",
        # installing a crontab FROM A FILE replaces the schedule wholesale
        # (crontab -l/-e/-r excluded; -r is already SYSTEM_TAMPER)
        r"\bcrontab\b(?:\s+-u\s+\S+)?\s+(?!-)\S+",
    ),
    reason="writing to an auto-executed location (git hook / shell rc / cron / "
           "systemd / agent hook config) arms code that runs without review",
    description="Warns on writes into .git/hooks, shell rc files, cron, "
                "systemd units, .claude/settings*.json, crontab-from-file.",
)

CLOUD_STORAGE_WIPE = Policy(
    name="CLOUD_STORAGE_WIPE",
    patterns=(
        r"""\baws\s+s3\s+rm\b(?=.*(?:s3://|<))(?=.*--recursive)(?!.*(?:tmp|cache|scratch|/build\b|node_modules))(?!.*--dry-?run)""",
        r"""\b(?:gsutil\b(?=.*\brm\b)(?=.*(?:-[a-z]*r\b|--recursive))|gcloud\s+storage\s+rm\b(?=.*(?:-r\b|--recursive)))(?=.*gs://)""",
        r"""\brclone\b(?=.*\b(?:purge|delete)\b|.*\bsync\b(?=.*--delete))(?=.*\w+:)(?!.*--dry-?run)""",
        r"""(?:\bazcopy\s+remove\b(?=.*--recursive)|\bmc\s+rm\b(?=.*--recursive)|\baz\s+storage\s+blob\s+delete-batch\b)""",
        r"""\bgsutil\b(?=.*\brm\b)(?=.*\s-[a-z]*a\b)(?=.*gs://)""",
        r"""\bgsutil\b(?=.*\brsync\b)(?=.*\s-[a-z]*d\b)(?=.*gs://)""",
        r"""\bazcopy\s+sync\b(?=.*--delete-destination)""",
        r"""\bmc\s+(?:rb\b(?=.*--force)|mirror\b(?=.*--remove))""",
        r"""\bs3cmd\s+(?:del|rm)\b(?=.*--recursive)(?!.*(?:tmp|cache|scratch))""",
    ),
    reason="recursive/mirror deletion of cloud object storage (S3/GCS/Azure/rclone/minio) is irreversible on unversioned buckets",
    description="recursive/mirror deletion of cloud object storage (S3/GCS/Azure/rclone/minio) is irreversible on unversioned buckets",
)

CLOUD_STORAGE_SYNC_DELETE = Policy(
    name="CLOUD_STORAGE_SYNC_DELETE",
    patterns=(
        # `aws s3 sync <src> s3://... --delete` mirrors src ONTO the bucket and
        # deletes every bucket object NOT present in src - an empty or wrong src
        # wipes the bucket. But `sync ./build s3://site --delete` is ALSO the
        # single most common static-site deploy. The two are statically
        # indistinguishable (we cannot tell if <src> is empty), so this is WARN,
        # not block: surface it to a human, never hard-block a legitimate deploy.
        # Known build-output sources (build/dist/public/out/.next/node_modules/
        # .output) are the benign deploy case and PASS untouched; --dryrun PASSES.
        r"""\baws\s+s3\s+sync\b(?=[^\n]*\ss3://)(?=[^\n]*\s--delete\b)(?![^\n]*--dry-?run)(?![^\n]*(?:\bbuild\b|\bdist\b|\bpublic\b|/out\b|\.next\b|node_modules|\.output\b))""",
    ),
    level="warn",
    reason="`s3 sync --delete` deletes every bucket object absent from the source; an empty or wrong source wipes the bucket (ambiguous with a normal deploy - surfaced for a human, not hard-blocked)",
    description="Warns on `aws s3 sync <src> s3://bucket --delete` (mirror-delete wipe risk); build-output sources and --dryrun pass.",
)

STREAM_QUEUE_DESTROY = Policy(
    name="STREAM_QUEUE_DESTROY",
    patterns=(
        r"""\bkafka-topics\b(?=.*\s--delete\b)|\bkafka-delete-records\b""",
        r"""\bkafka-consumer-groups\b(?=.*\s--reset-offsets\b)(?=.*\s--execute\b)""",
        r"""\bsqs\s+purge-queue\b|\bpubsub\s+(?:topics|subscriptions)\s+delete\b""",
        r"""\brabbitmqctl\s+(?:reset|delete_queue|purge_queue)\b""",
        r"""\bnats\s+(?:stream|kv|consumer)\s+(?:rm|del|purge)\b""",
        r"""\bkafka-storage\b[^\n]*\bformat\b""",
        r"""\brabbitmqctl\s+forget_cluster_node\b""",
    ),
    reason="deleting/purging/resetting streaming topics, queues or consumer offsets drops in-flight and retained messages with no undo",
    description="deleting/purging/resetting streaming topics, queues or consumer offsets drops in-flight and retained messages with no un",
)

WINDOWS_DESTROY = Policy(
    name="WINDOWS_DESTROY",
    patterns=(
        r"""\b(?:remove-item|ri)\b(?=[^|\n]*?\s-f(?:o(?:rce)?)?\b)(?=[^|\n]*?\s-r(?:ec(?:urse)?)?\b)|\bclear-content\b(?=[^\n]*?\s-force\b)""",
        r"""\b(?:rd|rmdir)\b[^\n]*?\s/s\b|\b(?:del|erase)\b(?=[^\n]*?\s/q\b)(?=[^\n]*?\s/[sf]\b)""",
        r"""(?:^|[;&|]\s*)format(?:\.com)?\s+[a-z]:|\bcipher\b[^\n]*?\s/w:""",
        r"""\breg\b[^\n]*?\sdelete\b[^\n]*?\s/f\b|\bbcdedit\b[^\n]*?\s/delete\b""",
        r"""\bvssadmin\s+delete\s+shadows\b""",
        r"""\bClear-Disk\b[^\n]*-RemoveData\b""",
        r"""\bmanage-bde\b[^\n]*\s-off\b""",
        r"""\bwmic\s+shadowcopy\s+delete\b""",
        # .NET recursive directory delete: [System.IO.Directory]::Delete(path, $true)
        # - the $true 2nd arg is RECURSIVE, wiping the whole tree (semantically
        # identical to Remove-Item -Recurse -Force, already blocked above). Anchored
        # on the `, $true` recursive arg so the benign non-recursive single-arg form
        # [System.IO.Directory]::Delete("C:\temp\build") stays ALLOW.
        r"""\[(?:System\.)?IO\.Directory\]::Delete\s*\([^)]*,\s*\$?true\b""",
        # wbadmin delete backup/systemstatebackup/catalog wipes Windows Server Backup
        # recovery points (Inhibit System Recovery, MITRE T1490) - the Windows analogue
        # of restic forget --prune / zfs destroy. get versions/status (read) and start
        # backup (create) carry no `delete <backup>` verb and PASS.
        r"""\bwbadmin\s+delete\s+(?:backup|systemstatebackup|catalog)\b""",
    ),
    reason="Windows/PowerShell/cmd catastrophic op (recursive force delete, volume format, cipher wipe, registry hive delete, boot-config delete)",
    description="Windows/PowerShell/cmd catastrophic op (recursive force delete, volume format, cipher wipe, registry hive delete, boot-c",
)

MACOS_DISK_DESTROY = Policy(
    name="MACOS_DISK_DESTROY",
    patterns=(
        r"""\bdiskutil\s+(?:(?:ap)?fs\s+)?(?:erasedisk|erasevolume|erasecontainer|deletecontainer|deletevolume|secureerase|reformat|zerodisk|randomdisk)\b""",
        r"""\btmutil\s+deletelocalsnapshots\b""",
        r"""\bsecurity\s+delete-keychain\b""",
        r"""\bsrm\b(?=(?:.*\s)?-\S*[rf])""",
    ),
    reason="macOS disk/keychain/snapshot destruction (diskutil erase/deleteContainer/secureErase, tmutil snapshot delete, keychain delete)",
    description="macOS disk/keychain/snapshot destruction (diskutil erase/deleteContainer/secureErase, tmutil snapshot delete, keychain d",
)

DB_DESTRUCTIVE_EXTRA = Policy(
    name="DB_DESTRUCTIVE_EXTRA",
    patterns=(
        # mysqladmin OR the MariaDB fork binary `mariadb-admin` (the default admin
        # client on modern MariaDB; mysqladmin is now a legacy symlink) running the
        # destructive `drop <db>` verb. status/ping/create/reload/flush-logs PASS.
        r"""(?:^|[;&|]\s*|\s)(?:dropdb|dropuser)\b|\b(?:mysqladmin|mariadb-admin)\b(?:(?![;&|#]).)*\bdrop\s+\S""",
        r"""\bDROP\s+(?:TABLESPACE|USER|DATABASE|SCHEMA|KEYSPACE|COLUMN|REPLICATION\s+SLOT)\b|\bALTER\s+TABLE\b(?:(?![;'"]).)*\bDROP\s+COLUMN\b""",
        r"""\bRESET\s+MASTER\b|\bpg_drop_replication_slot\b|\bDROP\s+REPLICATION\s+SLOT\b|\bTRUNCATE\s+(?:TABLE\s+)?["'`\w]""",
        r"""\bpg_ctl\b(?:(?![;&|]).)*\bstop\b(?:(?![;&|]).)*(?:-m\s+immediate|--mode[ =]immediate)|(?:-m\s+immediate|--mode[ =]immediate)(?:(?![;&|]).)*\bstop\b""",
        # pg_resetwal/pg_resetxlog forcibly rewrites the WAL, discarding committed
        # transactions and often leaving the cluster logically corrupt (a last-resort
        # tool requiring a subsequent dump/reload) - strictly more destructive than
        # the immediate-stop above. The read-only dry-run (-n / --dry-run, which just
        # prints control values) is the benign twin and is EXCLUDED.
        r"""\b(?:pg_resetwal|pg_resetxlog)\b(?![^\n|;&]*\s(?:-n\b|--dry-run\b))""",
        r"""\bUPDATE\s+\S+\s+SET\b(?![^;]*\bWHERE\b)""",
        r"""\bflyway\b[^\n]*\bclean\b""",
    ),
    reason="database-destroying op beyond DROP TABLE (dropdb, mysqladmin drop, DROP USER/COLUMN/TABLESPACE/KEYSPACE, RESET MASTER, TRUNCATE, immediate stop, drop replication slot)",
    description="database-destroying op beyond DROP TABLE (dropdb, mysqladmin drop, DROP USER/COLUMN/TABLESPACE/KEYSPACE, RESET MASTER, T",
)

DATASTORE_FLUSH_EXTRA = Policy(
    name="DATASTORE_FLUSH_EXTRA",
    patterns=(
        r"""\betcdctl\b(?=[^\n]*\bdel(?:ete)?(?:-range)?\b)(?=[^\n]*--prefix\b)""",
        # `etcdctl del "" --from-key` deletes the entire keyspace from the empty key
        # onward (for a k8s cluster, the whole control-plane state) - the same full
        # wipe as `--prefix ""` but via the `--from-key` range flag the --prefix rule
        # missed. A single-key delete (`etcdctl del /myapp/config/flag`, no range
        # flag) is the benign twin and PASSES.
        r"""\betcdctl\b(?=[^\n]*\bdel(?:ete)?(?:-range)?\b)(?=[^\n]*--from-key\b)""",
        r"""(?:-X\s*(?:POST|DELETE)|--request\s*(?:POST|DELETE))[^\n]*://[^\n]*(?:/_delete_by_query\b|:9200/[A-Za-z0-9_.*-]+(?:/_doc)?\s*(?:['"]?\s*$|['"]?\s*[|;&]))""",
        r"""\bnodetool\b[^\n]*\bclearsnapshot\b""",
        r"""\bmongo(?:sh)?\b[^\n]*--eval\b[^\n]*\.(?:drop|dropDatabase)\s*\(|\bmongo(?:sh)?\b[^\n]*--eval\b[^\n]*\.deleteMany\s*\(\s*\{\s*\}\s*\)|\bredis-cli\b[^\n]*(?:--scan|\bscan\b|\bkeys\b)[^\n]*\|[^\n]*\bredis-cli\b[^\n]*\b(?:del|unlink|flushall|flushdb)\b""",
        r"""\bdropAllUsersFromDatabase\b""",
        r"""\betcdctl\b[^\n]*\bsnapshot\s+restore\b[^\n]*(?:/dev/null|/dev/zero)""",
    ),
    reason="datastore/search/etcd destruction (etcd prefix delete, ES delete-by-query/index, cassandra clearsnapshot, mongosh eval drop, redis scan+DEL)",
    description="datastore/search/etcd destruction (etcd prefix delete, ES delete-by-query/index, cassandra clearsnapshot, mongosh eval d",
)

DISK_DESTROY_EXTRA = Policy(
    name="DISK_DESTROY_EXTRA",
    patterns=(
        r"""\bsfdisk\b[^\n|;&]*\s--delete\b""",
        r"""\bcryptsetup\b[^\n|;&]*(?:luksremovekey|lukskillslot|lukserase|\berase\b)""",
        r"""\b(?:fdisk|cfdisk|gdisk)\b(?![^\n|;&]*\s(?:-l\b|--list\b|-u\b))[^\n|;&]*\s/dev/""",
        r"""\bwipe\b[^\n|;&]*\s-[a-zA-Z]*[rf][a-zA-Z]*\b""",
    ),
    reason="disk/partition/crypto destruction (sfdisk --delete, cryptsetup luksRemoveKey/luksErase/erase, fdisk/gdisk on a device, wipe -rf)",
    description="disk/partition/crypto destruction (sfdisk --delete, cryptsetup luksRemoveKey/luksErase/erase, fdisk/gdisk on a device, w",
)

K8S_DESTROY_EXTRA = Policy(
    name="K8S_DESTROY_EXTRA",
    patterns=(
        r"""\bkubectl\b(?:\s+(?!--dry-run)\S+)*?\s+delete\b(?:\s+(?!--dry-run)\S+)*?\s+-[fk]\b(?:\s+(?!--dry-run)\S+)*$""",
        r"""\bkubectl\b(?:\s+(?!--dry-run)\S+)*?\s+drain\b(?:\s+(?!--dry-run)\S+)*$""",
        r"""\bkubectl\b(?:\s+(?!--dry-run)\S+)*?\s+delete\s+(?:nodes?|no)\b(?:\s+(?!--dry-run)\S+)+$""",
        r"""\bkubectl\b(?:\s+(?!--dry-run)\S+)*?\s+delete\s+(?:pvc|pv|persistentvolumeclaims?|persistentvolumes?)\b(?:\s+(?!--dry-run)\S+)*?\s+--all\b(?:\s+(?!--dry-run)\S+)*$""",
    ),
    reason="kubectl destruction beyond a namespace (delete -f/-k manifests, drain, delete node, delete pvc/pv)",
    description="kubectl destruction beyond a namespace (delete -f/-k manifests, drain, delete node, delete pvc/pv)",
)

REGISTRY_IMAGE_DELETE = Policy(
    name="REGISTRY_IMAGE_DELETE",
    patterns=(
        r"""\b(?:crane|skopeo)\s+(?:[^\n]*\s)?delete\b""",
        r"""\boras\s+(?:manifest|blob|repo)\s+(?:delete|rm)\b""",
        r"""\baws\s+ecr\s+(?:batch-delete-image|delete-repository)\b""",
        r"""\bnpm\s+dist-tag\s+rm\b""",
        r"""\bgem\s+yank\b""",
    ),
    reason="deleting a published container image / release asset / dist-tag makes a deployed artifact un-pullable",
    description="deleting a published container image / release asset / dist-tag makes a deployed artifact un-pullable",
)

SECRET_STORE_DELETE_EXTRA = Policy(
    name="SECRET_STORE_DELETE_EXTRA",
    patterns=(
        r"""\bvault\s+secrets\s+disable\b""",
        r"""\bvault\s+(?:lease\s+revoke\b[^\n]*?-prefix\b|kv\s+metadata\s+delete\b|token\s+revoke\b[^\n]*?-mode[=\s]*path\b)""",
        r"""\bgcloud\s+secrets\s+delete\b""",
    ),
    reason="secret/identity store destruction (vault secrets disable / lease revoke -prefix / kv metadata delete / token revoke path, gcloud secrets delete)",
    description="secret/identity store destruction (vault secrets disable / lease revoke -prefix / kv metadata delete / token revoke path, gcloud secrets delete)",
)

CLOUD_PROTECTION_OFF = Policy(
    name="CLOUD_PROTECTION_OFF",
    patterns=(
        r"""\bgcloud\s+sql\s+instances\s+patch\b(?=.*(?:--no-deletion-protection|--no-backup))""",
        r"""\baws\s+rds\s+modify-db-instance\b(?=.*--no-deletion-protection)""",
        # 0.4.13: setting --backup-retention-period 0 DELETES all automated backups
        # and disables future ones (the AWS-native way to kill backups). A positive
        # retention (--backup-retention-period 7, ENABLING backups) is the benign twin.
        r"""\baws\s+rds\s+modify-db-(?:instance|cluster)\b(?=.*--backup-retention-period\s+0\b)""",
        # suspending bucket versioning removes the undo for every future overwrite/delete.
        # Status=Enabled (the benign twin) PASSES.
        r"""\baws\s+s3api\s+put-bucket-versioning\b(?=.*Status=Suspended)""",
        # gcloud compute instance deletion-protection off (arms a later delete).
        r"""\bgcloud\s+compute\s+instances\s+update\b(?=.*--no-deletion-protection)""",
        # 0.4.13 round-2: the CLUSTER form (asymmetric gap - the instance form was
        # covered). rds/docdb/neptune modify-db-cluster / modify-global-cluster off.
        r"""\baws\s+(?:rds|docdb|neptune)\s+modify-(?:db-cluster|global-cluster)\b(?=.*--no-deletion-protection)""",
        # CloudFormation stack termination-protection off arms a later delete-stack.
        r"""\baws\s+cloudformation\s+update-termination-protection\b(?=.*--no-enable-termination-protection)""",
        # Redshift auto-snapshot retention 0 deletes all automated snapshots.
        r"""\baws\s+redshift\s+modify-cluster\b(?=.*--automated-snapshot-retention-period\s+0\b)""",
        # Azure Key Vault purge-protection off allows a hard delete of the vault/secrets.
        r"""\baz\s+keyvault\s+update\b(?=.*--enable-purge-protection\s+false\b)""",
    ),
    reason="disabling deletion-protection or backups on a prod database sets it up for silent, irreversible destruction",
    description="disabling deletion-protection or backups on a prod database sets it up for silent, irreversible destruction",
)

IAC_STATE_DESTROY = Policy(
    name="IAC_STATE_DESTROY",
    patterns=(
        r"""\bpulumi\s+(?:stack\s+rm|destroy)\b(?=.*(?:--yes|-y|--force))""",
        r"""\bcdk\s+destroy\b(?=.*--force)""",
    ),
    reason="pulumi stack rm/destroy or cdk destroy --force tears down managed infrastructure and its state",
    description="pulumi stack rm/destroy or cdk destroy --force tears down managed infrastructure and its state",
)

# --- Structure-keyed close-153 policies (2026-07-11): 9 PLAIN_CORE shapes + the
# 2 keygen-overwrite cases + two residual-obfuscated shapes (etcd compaction,
# pubsub seek, batch gh delete-asset) an adversarial hunt found still ALLOWing
# through the live 0.4.12 gate. Each keys on verb+flag+resource (not the tool
# name alone) and has a benign twin that PASSES (see test_close153.py). Levels
# per the danger's reversibility: hard "block" for irreversible key/secret/queue
# loss and config-mgmt file removal on a real path; "warn" (surface to a human)
# for the ambiguous-but-serious classes (lifecycle nuke, deprecate-all, buildx
# --push, opaque SQL-from-file, key overwrite, etcd compaction, pubsub seek).

CLOUD_STORAGE_LIFECYCLE_NUKE = Policy(
    name="CLOUD_STORAGE_LIFECYCLE_NUKE",
    # warn: an S3 lifecycle rule with a tiny Expiration (Days 1..99) mass-EXPIRES
    # every matching object shortly after this call - a slow-motion bucket wipe
    # that CLOUD_STORAGE_WIPE (which keys on `s3 rm`) never sees. A long retention
    # (Days 365, the archival benign twin) does NOT match: only 1-2 digit day
    # counts (<=99) are a nuke. Surface to a human, since a legit short TTL exists.
    level="warn",
    patterns=(
        r"\baws\s+s3api\s+put-bucket-lifecycle-configuration\b[^\n]*"
        r"(?:\"Days\"\s*:\s*[1-9][0-9]?\b|\"NoncurrentDays\"\s*:\s*[1-9][0-9]?\b)",
    ),
    reason="an S3 lifecycle rule with a very short expiration mass-deletes bucket objects on a timer - review before running",
    description="Warns on aws s3api put-bucket-lifecycle-configuration with a short (<=99 day) Expiration/NoncurrentDays.",
)

CONFIG_MGMT_DESTROY = Policy(
    name="CONFIG_MGMT_DESTROY",
    # ansible removing a real path fleet-wide (`-m file -a 'path=... state=absent'`)
    # deletes it on every host at once; a destroy playbook or an explicit
    # terminate_instances=true tears down infra. Scoped tight: state=absent on a
    # throwaway path (/tmp, /var/tmp, /dev/shm) is the benign twin and PASSES.
    patterns=(
        r"\bansible(?:-playbook)?\b(?![^\n]*(?:/tmp/|/tmp\b|/var/tmp/|/dev/shm))"
        r"[^\n]*\bstate=absent\b",
        r"\bansible-playbook\b[^\n]*\bterminate_instances=true\b",
        r"\bansible-playbook\b[^\n]*\bdestroy[\w.-]*\.ya?ml\b",
    ),
    reason="ansible removing a real path fleet-wide, running a destroy playbook, or terminating instances is irreversible across every host - requires a human",
    description="Blocks ansible file state=absent on a non-tmp path, ansible-playbook destroy*.yml, and terminate_instances=true.",
)

STREAM_RETENTION_PURGE = Policy(
    name="STREAM_RETENTION_PURGE",
    # forcing a topic's retention to ~0 (retention.ms/bytes = 0/1/tiny) makes the
    # broker purge every retained message on the next cleanup - a silent data wipe
    # that STREAM_QUEUE_DESTROY (which keys on --delete) never catches. A real
    # retention (604800000 = 7 days, the benign twin) has many digits and PASSES.
    patterns=(
        r"\bkafka-configs\b(?=[^\n]*--alter\b)"
        r"(?=[^\n]*\bretention\.(?:ms|bytes)=(?:0|1|-?[0-9]{1,4})\b)",
    ),
    reason="forcing a Kafka topic retention to ~zero purges all retained messages irreversibly - requires a human",
    description="Blocks kafka-configs --alter --add-config retention.ms/bytes=0/1/tiny (forces purge).",
)

SOPS_KEY_ROTATE_RM = Policy(
    name="SOPS_KEY_ROTATE_RM",
    # `sops rotate --rm-pgp/--rm-kms/...` removes an OLD recipient key while
    # re-encrypting: anyone who only held that key permanently loses access to the
    # secrets. --add-* (the benign twin, grants access) PASSES.
    patterns=(
        r"\bsops\b[^\n]*\brotate\b[^\n]*--rm-(?:pgp|kms|gcp-kms|azure-kv|hc-vault)\b",
    ),
    reason="sops rotate --rm-pgp/--rm-kms drops an old key recipient - anyone holding only that key loses access to the secrets - requires a human",
    description="Blocks sops rotate with --rm-pgp/--rm-kms/--rm-gcp-kms/--rm-azure-kv/--rm-hc-vault.",
)

PACKAGE_DEPRECATE_ALL = Policy(
    name="PACKAGE_DEPRECATE_ALL",
    # `npm deprecate pkg@"*" ... --force` marks EVERY published version deprecated
    # at once - a public signal that breaks installs for all consumers. A targeted
    # single-version deprecate (`@1.2.3`, the benign twin) PASSES.
    level="warn",
    patterns=(
        r"\bnpm\s+deprecate\b[^\n]*(?:@[\"']?\*[\"']?|[\"']\*[\"'])(?=[^\n]*(?:--force|@))",
    ),
    reason="npm deprecate on the '*' version range flags every published version at once and breaks all consumers - review before running",
    description="Warns on npm deprecate pkg@\"*\" (all versions).",
)

REGISTRY_PUSH_EXTRA = Policy(
    name="REGISTRY_PUSH_EXTRA",
    # `docker buildx build --push` builds AND pushes to a registry in one step -
    # the same irreversible outward release as `docker push`, which REGISTRY_PUBLISH
    # catches, but buildx's combined form slipped past it. A `--load`/no-push build
    # (the benign twin) PASSES.
    level="warn",
    patterns=(
        r"\bdocker\s+buildx\s+build\b(?=[^\n]*\s--push\b)",
    ),
    reason="docker buildx build --push releases an image to a registry - an irreversible outward publish - requires a human",
    description="Warns on docker buildx build --push (combined build-and-publish).",
)

DB_FILE_REDIRECT_EXEC = Policy(
    name="DB_FILE_REDIRECT_EXEC",
    # warn: `yes | mysql ... < script.sql` auto-confirms and runs a SQL script from
    # a FILE the gate cannot read - the payload is invisible, so it may be a full
    # drop. Also catch a mysql redirect from a drop*/delete*/truncate* named .sql
    # even without `yes`. A plain `mysql prod < seed.sql` / `< schema.sql` (benign
    # twin, no auto-confirm, non-destructive name) PASSES.
    level="warn",
    patterns=(
        r"\byes\s*\|\s*mysql\b[^\n]*<\s*\S+\.sql\b",
        r"\bmysql\b[^\n]*<\s*[^\n]*(?:drop|delete|truncate|destroy|wipe|teardown|nuke)[\w.-]*\.sql\b",
    ),
    reason="auto-confirming (yes |) a SQL script from a file, or running a drop/delete-named .sql, executes unseen destructive SQL - review before running",
    description="Warns on `yes | mysql < *.sql` and mysql < drop*/delete*/truncate*.sql (opaque scripted SQL).",
)

KEY_OVERWRITE = Policy(
    name="KEY_OVERWRITE",
    # warn: auto-answering the overwrite prompt (`ssh-keygen ... -f <path> <<< y`)
    # regenerates a key AT AN EXISTING PATH, silently destroying the old private
    # key (you only get the prompt when the file exists). `age-keygen -o <file>`
    # writes a fresh identity file, clobbering any file already there. Generating a
    # NEW key (no `<<<y`, or age-keygen with -y/convert, the benign twins) PASSES.
    level="warn",
    patterns=(
        # ssh-keygen with -f AND the interactive overwrite auto-confirmed via a
        # here-string `<<< y` / `<<<y` (the only reason to feed `y` is to accept
        # "Overwrite (y/n)?" - a brand-new path never prompts).
        r"\bssh-keygen\b(?=[^\n]*\s-f\b)[^\n]*<<<\s*[\"']?y(?:es)?[\"']?(?:\s|$)",
        # age-keygen writing to an output file (-o) WITHOUT -y (convert-to-pubkey):
        # -o overwrites the target identity file if it exists.
        r"\bage-keygen\b(?=[^\n]*\s-o\b)(?![^\n]*\s-y\b)",
    ),
    reason="regenerating a key over an existing path (ssh-keygen -f ... <<<y) or age-keygen -o <file> silently overwrites a private key - review before running",
    description="Warns on ssh-keygen -f <path> with auto-yes overwrite, and age-keygen -o <file> without -y.",
)

STREAM_SEEK_PURGE = Policy(
    name="STREAM_SEEK_PURGE",
    # warn: `gcloud pubsub subscriptions seek` moves the ack cursor to a time or
    # snapshot - it can discard un-acked messages (seek forward) or force a mass
    # re-delivery (seek back). Legit for controlled replay, so surface to a human.
    # pull/list/describe/create (benign twins) PASS.
    level="warn",
    patterns=(
        r"\bgcloud\s+pubsub\s+subscriptions\s+seek\b",
    ),
    reason="pubsub subscriptions seek moves the ack cursor - it can drop un-acked messages or force mass redelivery - review before running",
    description="Warns on gcloud pubsub subscriptions seek (cursor move / message purge or replay).",
)

ETCD_COMPACT = Policy(
    name="ETCD_COMPACT",
    # warn: `etcdctl compaction <rev>` permanently discards all key revisions
    # before <rev> (you can no longer read or watch from earlier history);
    # `etcdctl defrag` rewrites the backend. Both are legit maintenance, but the
    # compaction is an irreversible history drop - surface to a human. get/put/
    # member/endpoint/snapshot (benign twins) PASS.
    level="warn",
    patterns=(
        r"\betcdctl\b[^\n]*\b(?:compaction|defrag)\b",
    ),
    reason="etcdctl compaction permanently drops key history before a revision (defrag rewrites the store) - review before running",
    description="Warns on etcdctl compaction/defrag (irreversible history compaction).",
)

RELEASE_ASSET_MASS_DELETE = Policy(
    name="RELEASE_ASSET_MASS_DELETE",
    # warn: a loop that enumerates a release's assets and deletes each
    # (`gh release view ... --json assets ... | ... gh release delete-asset`) wipes
    # ALL assets of a release at once - a batch destruction distinct from the
    # single, recoverable `gh release delete-asset one.dmg` (which stays allowed).
    level="warn",
    patterns=(
        r"\bgh\s+release\s+view\b[^\n]*\bassets\b[\s\S]*?\bgh\s+release\s+delete-asset\b",
    ),
    reason="a batch loop deleting every asset of a release (view --json assets -> delete-asset) is a mass destruction - review before running",
    description="Warns on the gh release view --json assets -> gh release delete-asset batch loop (deletes all assets).",
)

# --- 0.4.13 adversarial gap-closers (2026-07-12): a 9-category adversarial hunt
# (770 engine-tested commands) found 77 irreversible shapes still ALLOWing through
# the live 0.4.12 gate. Each rule below fires on an engine-confirmed miss and has a
# benign twin that PASSES (see test_v0413_gaps.py). Levels per reversibility: hard
# "block" for whole-disk/data/secret/infra loss; "warn" (surface to a human) for the
# dev-routine-but-destructive classes (ORM db reset, cert-file delete). The
# deliberately-LEFT set (too common to block without false positives): git working-
# tree discards (checkout -- ., restore ., checkout -f), git stash clear, redis
# SWAPDB, rsync --delete into a /mnt//media/ backup mount. And two residual obfuscation
# shapes stay KNOWN-OPEN like $'\x72m': bash parameter-expansion evasion
# (${V/X/ }, ${V^^}) - deliberate hand-obfuscation, not real agent output.

DISK_ERASE_EXTRA = Policy(
    name="DISK_ERASE_EXTRA",
    patterns=(
        # badblocks WRITE-mode (-w / -wsv) overwrites every sector. Read-only
        # badblocks (-sv, no 'w') is the benign twin and PASSES.
        r"\bbadblocks\b[^\n|;&]*\s-[a-zA-Z]*w[a-zA-Z]*\b[^\n|;&]*/dev/",
        # the mkfs FAMILY beyond the literal `mkfs` (DISK_DESTROY covers mkfs/mkfs.*):
        # mke2fs/mkntfs/mkdosfs/mkexfatfs/mkreiserfs/mkswap/mkudffs all lay a new
        # filesystem on a device = wipe. mkdir/mkfifo/mktemp/make do NOT match.
        r"\b(?:mke2fs|mkntfs|mkdosfs|mkexfatfs|mkreiserfs|mkswap|mkudffs)\b[^\n|;&]*/dev/",
        # NVMe controller erase beyond `nvme format` (sanitize / write-zeroes) wipes
        # the whole namespace. Read-only nvme (list/id-ctrl/smart-log) PASSES.
        r"\bnvme\s+(?:sanitize|write-zeroes)\b[^\n|;&]*/dev/",
        # SCSI low-level format of a whole disk. sg_format WITHOUT --format (reports
        # the current format) is the benign twin and PASSES.
        r"\bsg_format\b[^\n|;&]*--format\b",
        # dd writing to the mounted-root device alias /dev/root destroys the live
        # root filesystem (DISK_DESTROY's dd device family omitted `root`).
        r"\bdd\b[^\n|;&]*\bof=/dev/root\b",
        # dd zero/null/random-filling a persistent DATA/secret file irreversibly
        # destroys it. Order-INDEPENDENT (if= before or after of=, round-2 edge) via
        # lookaheads. A copy `dd if=<real> of=x` and a scratch `of=/tmp/..`/`of=*.img`
        # are benign twins and PASS.
        # of= path branch: persistent dirs (added /var/lib/ + /var/ so the default
        # DB datadirs - /var/lib/mysql/ibdata1, /var/lib/postgresql/.../pg_control,
        # base relfiles - are covered; ~ and $HOME for the tilde/home form), OR a
        # secret/data-file by extension, OR an extensionless private-key BASENAME
        # (id_rsa/id_ed25519/id_ecdsa) so `dd if=/dev/zero of=~/.ssh/id_rsa`
        # (irreversible key loss) is caught. A copy `dd if=<real> of=x`, a scratch
        # `of=/tmp/..`/`of=*.img`, and a device backup `dd if=/dev/sda of=~/x.img`
        # (real-device source, excluded by the if=/dev/zero|random|null guard) PASS.
        r"\bdd\b(?=[^\n|;&]*\bif=/dev/(?:zero|u?random|null)\b)"
        r"(?=[^\n|;&]*\bof=(?:[^\n|;&]*(?:/root/|/home/|/etc/|/srv/|/opt/|/var/lib/|/var/|~/|\$HOME/)"
        r"|[^\n|;&]*(?:\.(?:db|sqlite3?|sql|env|pem|key|kdbx|gpg|jks|keystore)\b"
        r"|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b)))",
    ),
    reason="whole-disk/namespace erase or zero-filling a persistent data/DB/secret file destroys all data - requires a human",
    description="Blocks badblocks -w, mke2fs/mkntfs/mkswap on a device, nvme sanitize/write-zeroes, sg_format, dd of=/dev/root, dd zero-fill of a data/DB-datadir/private-key file.",
)

OVERWRITE_DESTROY_EXTRA = Policy(
    name="OVERWRITE_DESTROY_EXTRA",
    patterns=(
        # emptying a persistent file via a null/`:`/empty-echo redirect, EXTENDED to
        # ~ and /root and to data-file extensions (.db/.sqlite/.kdbx) that
        # OVERWRITE_DESTROY's root list omitted. Scratch (`: > /tmp/lock`,
        # `echo x > out.txt`) PASSES.
        r"(?:cat\s+/dev/null|:|echo(?:\s+-n)?\s*(?:''|\"\")?|printf\s*(?:''|\"\")?)\s*>\s*"
        r"[^\n|;&]*(?:/root/|~/|\.db\b|\.sqlite3?\b|\.kdbx\b)",
        # cp /dev/null OR /dev/zero over a key/secret/data file empties (or zero-fills)
        # it. round-2: added /dev/zero source and .db/.sqlite data extensions.
        r"\bcp\b[^\n|;&]*\s/dev/(?:null|zero)\s+[^\n|;&]*"
        r"(?:/etc/ssl/private/|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.kdbx\b|\.db\b|\.sqlite3?\b)",
        # find -exec (truncate -s0/--size 0 | unlink | dd of= | cp /dev/null|zero |
        # tee) mass-empties/deletes matched files. round-2: added the truncate
        # long-form flag, cp, and tee to the earlier truncate/unlink/dd set.
        r"\bfind\b[^\n]*-exec(?:dir)?\s+(?:truncate\b[^\n]*(?:-s\s*0|--size[=\s]+0)"
        r"|unlink\b|dd\b[^\n]*\bof=|cp\s+/dev/(?:null|zero)|tee\b)",
        # a BARE `>` / `true >` redirect (no cat/:/echo/printf prefix) truncating a
        # persistent data file. round-2: OVERWRITE_DESTROY needed a command prefix.
        r"(?:^|[;&|]\s*|\btrue\s*)>\s*[^\n|;&]*(?:/root/|/home/|~/|\.db\b|\.sqlite3?\b|\.kdbx\b)",
        # rsync mirror-wipe: the --del ALIAS of --delete, and the /root protected
        # root, both missed by OVERWRITE_DESTROY. A --delete into a non-protected
        # backup mount (/mnt//media/) stays allowed (common backup idiom).
        r"\brsync\b[^\n|;&]*\s--del(?:ete)?[a-z-]*\b[^\n|;&]*"
        r"(?:/home/|~/|/srv/|/var/|/etc/|/boot/|/usr/|/opt/|/root/)",
    ),
    reason="emptying/overwriting a persistent file or a mass find-exec truncation destroys data - requires a human",
    description="Blocks null-redirect to ~ /root /*.db, cp /dev/null over a key, find -exec truncate/unlink/dd, rsync --del into a protected root.",
)

CLOUD_DESTROY_EXTRA = Policy(
    name="CLOUD_DESTROY_EXTRA",
    patterns=(
        # gsutil rb removes an entire GCS bucket (CLOUD_DESTROY has aws s3 rb + gcloud
        # storage buckets delete, not gsutil's `rb`). ls/cp/rsync/rm PASS.
        r"\bgsutil\b(?:\s+-\w+)*\s+rb\b",
        # aws ec2 modify-instance-attribute --no-disable-api-termination REMOVES
        # termination protection. The protecting --disable-api-termination PASSES.
        r"\baws\s+ec2\s+modify-instance-attribute\b(?=[^\n]*--no-disable-api-termination)",
    ),
    reason="removing a GCS bucket or disarming EC2 termination protection sets up irreversible loss - requires a human",
    description="Blocks gsutil rb (bucket removal) and aws ec2 --no-disable-api-termination.",
)

IAC_STATE_DESTROY_EXTRA = Policy(
    name="IAC_STATE_DESTROY_EXTRA",
    patterns=(
        # terraform/tofu state surgery orphans real infra from its state. state
        # list/show/pull (read/export) PASS.
        r"\b(?:terraform|tofu)\s+state\s+rm\b",
        # `state push` OVERWRITES the authoritative remote state; a garbage/empty
        # state orphans every managed resource so the next apply destroys+recreates
        # the whole estate. -force just skips the lineage/serial safety check. Keyed
        # on the WRITE subcommand only, so read/inspect (state pull/list/show/mv) PASS.
        r"\b(?:terraform|tofu)\s+state\s+push\b",
        r"\bterraform\s+workspace\s+delete\b(?=[^\n]*(?:-force|--force))",
        r"\bpulumi\s+(?:down|state\s+delete)\b",
        # terragrunt run-all destroy (every module) or a NON-INTERACTIVE/auto-approve
        # destroy tears down infra with no human in the loop - matching the gate's
        # terraform stance (plain interactive `terragrunt destroy`, which PROMPTS, is
        # the benign twin and PASSES, exactly like plain `terraform destroy`).
        r"\bterragrunt\b[^\n]*\b(?:run-all\s+destroy|destroy\b[^\n]*(?:--terragrunt-non-interactive|-auto-approve))",
        # helmfile destroy removes every release with no prompt (same class as the
        # already-blocked `helm uninstall`).
        r"\bhelmfile\b[^\n]*\bdestroy\b",
    ),
    reason="IaC state removal or a fleet-wide destroy tears down managed infrastructure irreversibly - requires a human",
    description="Blocks terraform state rm, terraform workspace delete -force, pulumi down/state delete, terragrunt destroy, helmfile destroy.",
)

DB_DESTRUCTIVE_EXTRA2 = Policy(
    name="DB_DESTRUCTIVE_EXTRA2",
    patterns=(
        # DROP OWNED BY <role> drops every object a role owns (a whole app schema).
        r"\bDROP\s+OWNED\s+BY\b",
        # mongosh adminCommand({dropDatabase}) / runCommand({drop:...}) - the eval
        # forms DATASTORE_FLUSH_EXTRA's `.drop(`/`.dropDatabase(` regex missed.
        r"\bmongo(?:sh)?\b[^\n]*(?:adminCommand\s*\(\s*\{\s*dropDatabase|runCommand\s*\(\s*\{\s*drop\b)",
        # redis-cli shutdown nosave stops the server discarding unsaved data.
        r"\bredis-cli\b[^\n]*\bshutdown\b[^\n]*\bnosave\b",
        # cypher DETACH DELETE across a bare match wipes the whole graph.
        r"\bDETACH\s+DELETE\b",
        # elasticsearch delete ALL indices (DELETE /_all or /*).
        r"(?:-X\s*DELETE|--request\s+DELETE)[^\n]*://[^\n]*/(?:_all|\*)(?:\b|$)",
        r":9200/(?:_all|\*)(?:\b|/|$)",
        # influx bucket delete removes a whole bucket's series.
        r"\binflux\s+bucket\s+delete\b",
    ),
    reason="datastore-wide destruction (DROP OWNED, mongosh drop, redis shutdown nosave, DETACH DELETE, ES delete _all, influx bucket delete) - requires a human",
    description="Blocks DROP OWNED BY, mongosh adminCommand/runCommand drop, redis shutdown nosave, cypher DETACH DELETE, ES DELETE _all, influx bucket delete.",
)

DB_FRAMEWORK_RESET = Policy(
    name="DB_FRAMEWORK_RESET",
    # WARN: ORM/migration "reset the whole database" commands DROP+recreate every
    # table (all data gone). Routine in dev, catastrophic in prod - surface to a
    # human, don't hard-block. FORWARD twins (migrate dev/deploy, db push,
    # migrate:latest, upgrade head, db:migrate, goose up) carry no reset token and PASS.
    level="warn",
    patterns=(
        r"\bprisma\s+migrate\s+reset\b",
        r"\bprisma\s+db\s+push\b[^\n]*--force-reset\b",
        r"\bartisan\s+migrate:(?:fresh|reset)\b",
        r"\b(?:rake|rails)\s+db:(?:reset|drop)\b",
        r"\btypeorm(?:-ts-node-\S+)?\s+schema:drop\b",
        r"\bsequelize(?:-cli)?\s+db:drop\b",
        r"\bmanage\.py\s+flush\b",
        r"\bliquibase\b[^\n]*\bdropAll\b",
        r"\bknex\s+migrate:rollback\b[^\n]*--all\b",
        r"\balembic\s+downgrade\s+base\b",
        r"\bgoose\b[^\n]*\bdown-to\s+0\b",
        # mongorestore --drop drops each collection before restoring.
        r"\bmongorestore\b[^\n]*--drop\b",
    ),
    reason="an ORM/migration reset drops and recreates the whole database (all data lost) - review before running",
    description="Warns on prisma migrate reset, artisan migrate:fresh, rails db:reset, typeorm schema:drop, sequelize db:drop, django flush, liquibase dropAll, knex rollback --all, alembic downgrade base, goose down-to 0, mongorestore --drop.",
)

GIT_DESTRUCTIVE_EXTRA = Policy(
    name="GIT_DESTRUCTIVE_EXTRA",
    patterns=(
        # reset --hard with a `-C <dir>` global option and/or a <commit> before the
        # flag - GIT_DESTRUCTIVE needed them adjacent. reset --soft / reset HEAD
        # <file> (no --hard) are benign twins and PASS.
        r"\bgit\b(?:\s+-C\s+\S+)?\s+reset\b[^\n]*--hard\b",
        # branch force-delete in COMBINED (-fD) / reordered (--force -D) / -C forms.
        # Case-PINNED capital D (?-i:D) so benign `git branch -d merged` PASSES.
        r"\bgit\b(?:\s+-C\s+\S+)?\s+branch\b[^\n]*\s-[a-zA-Z]*(?-i:D)[a-zA-Z]*\b",
        # GitHub GraphQL destructive mutations via `gh api graphql` (the -X DELETE
        # wall never sees a POST graphql mutation). Read queries PASS.
        r"\bgh\s+api\b[^\n]*graphql[^\n]*\b(?:deleteRepository|deleteRef|deleteBranch|deleteIssue|deleteProject|deletePackageVersion)\b",
    ),
    reason="hard-resetting, force-deleting a branch, or a GitHub GraphQL delete mutation destroys work/history - requires a human",
    description="Blocks git -C/ref reset --hard, git branch -fD/--force -D, gh api graphql delete* mutations.",
)

K8S_NODE_DELETE_EXTRA = Policy(
    name="K8S_NODE_DELETE_EXTRA",
    patterns=(
        # kubectl/k delete node in the slash form (node/worker-1) or via the `k`
        # alias - K8S_DESTROY_EXTRA required `kubectl` + space-separated args. get
        # nodes / delete pod (not node) / a --dry-run are benign twins and PASS.
        r"\b(?:kubectl|k)\s+(?!(?:[^\n]*\s)?--dry-run)(?:[^\n]*\s)?delete\s+(?:nodes?|no)[/\s]",
    ),
    reason="deleting a Kubernetes node evicts all its pods and removes it from the cluster - requires a human",
    description="Blocks kubectl/k delete node (slash form and the k alias).",
)

K8S_CRI_DESTROY = Policy(
    name="K8S_CRI_DESTROY",
    # The containerd/CRI-O runtime CLIs (crictl/ctr/nerdctl) operate BENEATH the
    # kubectl-anchored walls: `crictl rmp -a -f` force-removes every pod at the
    # runtime layer with no k8s-level record - same severity class as
    # `kubectl delete pod --all`. Anchored on the remove SUBCOMMANDS (rmp/rmi/rm),
    # so read verbs (crictl ps/pods/images/inspect/logs/stats/info,
    # ctr containers/images list, nerdctl ps) carry none and PASS.
    patterns=(
        # crictl remove-pod / remove-image (any flags), and crictl rm with a mass
        # -a/--all flag. `crictl ps -a` is a READ (ps subcommand) and does NOT match.
        r"\bcrictl\b[^\n]*\b(?:rmp|rmi)\b",
        r"\bcrictl\b[^\n]*\brm\b[^\n]*(?:-[a-zA-Z]*a[a-zA-Z]*|--all)\b",
        # nerdctl force/mass remove of containers or images.
        r"\bnerdctl\b[^\n]*\b(?:rm|rmi)\b[^\n]*(?:-[a-zA-Z]*[af][a-zA-Z]*|--all|--force)\b",
        # containerd `ctr` container/image/task destruction.
        r"\bctr\b[^\n]*\b(?:containers?|images?|task|snapshots?)\b[^\n]*\b(?:rm|delete|del|kill)\b",
    ),
    reason="removing pods/containers/images at the container-runtime layer (crictl/ctr/nerdctl) destroys live workloads beneath the control plane - requires a human",
    description="Blocks crictl rmp/rmi and mass rm, nerdctl rm/rmi -f/-a, ctr containers/images/task rm.",
)

SECRET_STORE_DELETE_EXTRA2 = Policy(
    name="SECRET_STORE_DELETE_EXTRA2",
    patterns=(
        # gpg2 (not just gpg) deleting a secret key.
        r"\bgpg2?\b[^\n]*--delete-secret-keys?\b",
        # deleting an entry from a running secret store. get/put/lookup/find PASS.
        r"\bconsul\s+kv\s+delete\b",
        r"\bsecret-tool\s+clear\b",
        r"\bsecurity\s+delete-(?:generic|internet)-password\b",
        r"\bpass\s+(?:rm|remove)\b",
    ),
    reason="deleting a stored secret/credential entry is irreversible and can break running services - requires a human",
    description="Blocks gpg2 --delete-secret-keys, consul kv delete, secret-tool clear, security delete-*-password, pass rm.",
)

SECRET_FILE_DELETE = Policy(
    name="SECRET_FILE_DELETE",
    # WARN: rm/shred of a cert/key/prod-env file by extension (beyond the id_rsa/.ssh
    # paths SECRET_DELETE covers). Could be a stale cert cleanup or a real prod secret.
    # .env.example/.sample/.template (benign twins) do NOT match.
    level="warn",
    patterns=(
        r"\b(?:rm|shred|unlink)\b[^\n|;&]*\s[^\n|;&]*"
        r"(?:\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.kdbx\b|\.jks\b|\.keystore\b|"
        r"\.env\.(?!example\b|sample\b|template\b)\w+)",
    ),
    reason="deleting a certificate/key/production-env file may be irreversible loss of a secret - review before running",
    description="Warns on rm/shred of *.pem/*.key/*.p12/*.pfx/*.kdbx/.env.production files.",
)

# A persistent SECRET/credential destination path: a private-key basename, an
# .ssh/ file, a home/root credential store (.aws/credentials, .netrc, .pgpass,
# .kube/config, .gnupg), or a key/cert file by extension. Shared by the overwrite
# rules below so they all agree on WHAT counts as a protected secret target. NOT
# a whole-dir match (so `~/.ssh/known_hosts` / `~/.ssh/config`, regenerable, are
# NOT protected - only the key basenames and the named credential stores are).
_SECRET_DEST = (
    r"(?:\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\bidentity\b"
    r"|/\.ssh/[^\n|;&/]*(?:_key|id_[a-z0-9]+)\b"
    r"|\.aws/credentials\b|\.netrc\b|\.pgpass\b|\.kube/config\b|\.gnupg\b"
    r"|/etc/ssl/private/|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.kdbx\b|\.gpg\b|\.jks\b|\.keystore\b)"
)

SECRET_FILE_OVERWRITE = Policy(
    name="SECRET_FILE_OVERWRITE",
    # In-place OVERWRITE of a persistent private key / credential file with an
    # empty or random source - irreversible identity/access loss (no trash, no VCS
    # for a dotfile secret). SECRET_DELETE covers rm/shred/mv of these paths;
    # KEY_DELETE-class walls miss the CONTENT-overwrite verbs (cp/install/tee/
    # openssl). Each rule keys on the empty/zero/random SOURCE + a secret DEST, so
    # the benign twins stay ALLOW: `cp /dev/null ~/scratch/empty.txt` (non-secret
    # dest), `echo '[default]' | tee ~/.aws/credentials` (REAL content, not
    # </dev/null), `openssl rand -out /tmp/nonce.bin` (non-secret dest),
    # `install -m 0755 build/mybin /usr/local/bin/mybin` (real source),
    # `install -d ~/.ssh` (dir create), appending to authorized_keys (>>).
    patterns=(
        # cp /dev/null | /dev/zero  ->  a secret file (empties/zero-fills it).
        r"\bcp\b[^\n|;&]*\s/dev/(?:null|zero)\s+[^\n|;&]*" + _SECRET_DEST,
        # install /dev/null | /dev/zero  ->  a secret file (0-byte copy over key).
        # `install -d` (dir create, no source file) is excluded.
        r"\binstall\b(?![^\n|;&]*\s-d\b)[^\n|;&]*\s/dev/(?:null|zero)\s+[^\n|;&]*" + _SECRET_DEST,
        # tee <secret> < /dev/null  (O_TRUNC + empty stdin = blank the file), and
        # the `cat /dev/null | tee <secret>` pipe form. The `< /dev/null` / `cat
        # /dev/null |` empty-input signature is REQUIRED, so a real-content
        # `echo ... | tee <secret>` (writing actual creds) is NOT matched. -a
        # (append) tee is also not this truncating form.
        r"\btee\b(?![^\n|;&]*\s-a\b)[^\n|;&]*" + _SECRET_DEST + r"[^\n|;&]*<\s*/dev/null\b",
        r"\bcat\s+/dev/null\s*\|\s*tee\b(?![^\n|;&]*\s-a\b)[^\n|;&]*" + _SECRET_DEST,
        # openssl rand -out <secret>  truncates the file and writes random bytes,
        # clobbering the key with garbage. -out to a non-secret path (a nonce/token
        # file) is the benign twin and PASSES.
        r"\bopenssl\s+rand\b[^\n|;&]*\s-out\s+[^\n|;&]*" + _SECRET_DEST,
    ),
    reason="overwriting a private key / credential file in place with an empty or random source is irreversible identity/access loss - requires a human",
    description="Blocks cp/install /dev/null over a key, tee <key> </dev/null, cat /dev/null | tee <key>, openssl rand -out <key>.",
)

WINDOWS_DESTROY_EXTRA = Policy(
    name="WINDOWS_DESTROY_EXTRA",
    patterns=(
        # Format-Volume / Remove-Partition wipe a volume or partition. Anchored at a
        # COMMAND position (start / after ; & | newline) so `Get-Help Format-Volume`
        # and `Get-Command Format-Volume` (introspection, cmdlet as an ARGUMENT) PASS;
        # Get-Volume/Get-Partition (read) and a `-WhatIf` dry-run also PASS.
        r"(?:^|[\n;&|(]\s*)Format-Volume\b(?![^\n]*-WhatIf\b)",
        r"(?:^|[\n;&|(]\s*)Remove-Partition\b(?![^\n]*-WhatIf\b)",
        # deleting VSS shadow copies via CIM (Get-CimInstance Win32_ShadowCopy |
        # Remove-CimInstance) drops the recovery snapshots.
        r"\bWin32_ShadowCopy\b[^\n]*\|\s*Remove-CimInstance\b|\bRemove-CimInstance\b[^\n]*\bWin32_ShadowCopy\b",
        # diskpart `clean` wipes the partition table of the selected disk.
        r"\bdiskpart\b[^\n]*\bclean\b|\bclean\b[^\n]*\|\s*diskpart\b",
        # Clear-Content on a data file empties it in place.
        r"\bClear-Content\b[^\n]*\.(?:db|sqlite3?|mdf|ldf|env|config)\b",
    ),
    reason="Windows volume/partition/shadow-copy/content destruction is irreversible - requires a human",
    description="Blocks Format-Volume, Remove-Partition, Win32_ShadowCopy|Remove-CimInstance, diskpart clean, Clear-Content on a data file.",
)

# System-path token (case-insensitive) for the ownership/ACL lockout rules below.
_WIN_SYSTEM_PATH = (
    r"(?:C:\\Windows|C:\\Program\s?Files|%SystemRoot%|%WinDir%|\\Windows\\System32|\\System32)"
)

WINDOWS_PERMISSION_LOCKOUT = Policy(
    name="WINDOWS_PERMISSION_LOCKOUT",
    # Recursively seizing ownership of / rewriting ACLs on a SYSTEM tree
    # (C:\Windows, Program Files, System32) strips SYSTEM/TrustedInstaller/
    # Administrators access across the OS - offline-repair territory, the Windows
    # analogue of `chmod -R 000 /etc` / `chown -R nobody /` (PERMISSION_LOCKOUT).
    # SCOPED TO SYSTEM PATHS so the benign twin - takeown/icacls on the user's OWN
    # project folder (`takeown /f C:\Users\me\myproject /r`) - stays ALLOW.
    patterns=(
        # recursive takeown (/r or /R) of a system tree.
        r"\btakeown\b(?=[^\n]*\s/[rR]\b)(?=[^\n]*" + _WIN_SYSTEM_PATH + r")",
        # icacls ACL rewrite (grant/deny/inheritance:r/setowner/reset) on a system
        # tree with the recurse flag (/t or /T) - the actually-irreversible lockout.
        r"\bicacls\b[^\n]*" + _WIN_SYSTEM_PATH + r"[^\n]*"
        r"(?:/grant|/deny|/inheritance:r|/setowner|/reset)[^\n]*\s/[tT]\b",
        r"\bicacls\b[^\n]*(?:/grant|/deny|/inheritance:r|/setowner|/reset)[^\n]*"
        + _WIN_SYSTEM_PATH + r"[^\n]*\s/[tT]\b",
    ),
    reason="recursively seizing ownership or rewriting ACLs on a Windows system tree (C:\\Windows/System32/Program Files) locks the OS out of servicing/boot - requires a human",
    description="Blocks recursive takeown and icacls grant/deny/inheritance:r/setowner/reset /t on system paths; own-project takeown/icacls PASS.",
)

# ---------------------------------------------------------------------------
# FREE-CORE self-defense family (2026-07-12): the guard must not be killable /
# removable / disarmable by the very agent it guards, and the agent must not be
# able to blind the HOST's own security controls (MAC, firewall, audit, EDR).
# ADD-ONLY. Two policies:
#   GUARD_TAMPER              - attacks on gate.cat itself (its process, its
#                               package/entrypoint, its enforcement env-toggles).
#   SECURITY_CONTROL_DISABLE  - disabling host MAC/firewall/audit/EDR/log agents
#                               and shell-session track-hiding / gate disarm.
# Design: tight NAME allowlists, never broad verbs. A benign twin that reuses
# the same verb on a DIFFERENT name (pkill node, systemctl stop myapp, pip
# uninstall requests, iptables -L) matches NOTHING here (0-FP is the product).
#
# The guard-name token below matches the two product spellings (gatecat /
# gate.cat) with the optional component suffixes (-hook / -shell / -proxy), and
# tolerates the bracket-regex obfuscation g[a]tecat. Variable-indirection
# (N=gate; pkill -f ${N}cat) is handled UPSTREAM by the engine's de-obfuscation
# escalation, which resolves ${N}cat -> gatecat before these walls run - so the
# base `pkill -f gatecat` pattern covers it too.
_GUARD_NAME = r"g\[?a\]?t\[?e\]?[.\[\]]*c\[?a\]?t"          # gatecat | gate.cat | g[a]tecat
_GUARD = r"(?:%s)(?:-(?:hook|shell|proxy))?" % _GUARD_NAME  # + optional component suffix

# Security-critical unit / process NAMES a host relies on for confinement,
# perimeter, forensics, and EDR. ONLY these names are protected; stopping/killing
# any OTHER unit or process (myapp, nginx, postgresql, gunicorn) is untouched.
_SECURITY_UNIT = (
    r"(?:apparmor|firewalld|auditd|ufw|nftables|osqueryd|osquery|"
    r"falcon-sensor|falcon|crowdstrike|clamav|clamd|wazuh-agent|wazuh|"
    r"amazon-ssm-agent|google-cloud-ops-agent|azuremonitoragent|filebeat|"
    r"rsyslog|sshd|gatecat)"
)

GUARD_TAMPER = Policy(
    name="GUARD_TAMPER",
    # BLOCK, not warn: an agent killing/removing/disarming the guard that gates
    # it is never a legitimate action for the guarded agent to take. The name
    # allowlist makes it unambiguous - the developer's own `pkill node` / `pip
    # uninstall requests` / `rm ~/.venv/bin/mytool` reuse the same verbs on a
    # DIFFERENT name and are not matched.
    patterns=(
        # 1) kill the guard PROCESS by name: pkill/killall (any signal/-f/--signal).
        r"\b(?:pkill|killall)\b[^\n]*" + _GUARD,
        # kill chains that resolve the guard PID indirectly then SIGKILL it -
        # the guard name is in the pgrep/pidof/ps pattern or a *.pid path, not the
        # kill argv. Match `kill` co-occurring with the guard name via any of them.
        r"\bkill\b[^\n]*(?:pgrep|pidof|ps\b|" + _GUARD_NAME + r"[^\n]*\.pid)[^\n]*" + _GUARD,
        r"\bkill\b[^\n]*" + _GUARD_NAME + r"[^\n]*\.pid",
        # pgrep/ps ... gatecat ... | ... kill  (pipe form; guard name at pgrep stage)
        r"\b(?:pgrep|pidof|ps)\b[^\n]*" + _GUARD + r"[^\n]*\|[^\n]*\bkill\b",
        # 2) uninstall the guard PACKAGE (pip / uv / python -m pip).
        r"\b(?:pip\d?|uv)\b[^\n]*\buninstall\b[^\n]*" + _GUARD,
        r"\bpython\d?\b[^\n]*\bpip\b[^\n]*\buninstall\b[^\n]*" + _GUARD,
        # 3) delete / move / strip-exec the guard console-script or package dir.
        r"\b(?:rm|unlink)\b[^\n]*" + _GUARD + r"\b",
        r"\bmv\b[^\n]*" + _GUARD + r"\b",
        r"\bchmod\b[^\n]*(?:which\s+)?" + _GUARD + r"\b",
        # 4) GATECAT_* enforcement toggles: export/unset/inline-prefix/plain assign.
        #    Any manipulation of a GATECAT_* var (disable, enforce=0, blanking or
        #    unsetting GATECAT_EXTRA_POLICIES, repointing GATECAT_REAL_SHELL) can
        #    silently weaken or bypass the gate for the session.
        r"\b(?:export|unset)\s+GATECAT_\w*",
        r"(?:^|[\s;&|])GATECAT_\w+\s*=",
        # 5) disarm the Claude Code hook REGISTRATION: deleting or surgically
        #    editing .claude/settings(.local).json removes the pre-action hook so
        #    the next run is unguarded. (AUTOEXEC_WRITE already WARNs on WRITES to
        #    this file; rm/sed-delete of it is the hard self-defense case.) The
        #    path is pinned to .claude/settings*.json - deleting any OTHER config
        #    (~/.config/myapp/config.json) is untouched.
        r"\b(?:rm|unlink|shred)\b[^\n]*\.claude[/\\]settings(?:\.local)?\.json\b",
        r"\bsed\b[^\n]*-i[^\n]*\.claude[/\\]settings(?:\.local)?\.json\b",
        # 6) delete the guard's extra-policy state file (~/.gatecat/*): rm slips
        #    past the truncation walls that cover `echo '' >`/`:>` on the same file.
        #    (The _GUARD rm pattern above already covers ~/.gatecat/ via the name,
        #    this is kept explicit for the policies.yaml / state case.)
        r"\b(?:rm|unlink|shred)\b[^\n]*[/\\]\.gatecat[/\\]",
    ),
    reason="killing/removing/disarming the gate.cat guard (its process, package, "
           "entrypoint, or GATECAT_* enforcement env) disables the veto that guards "
           "this agent - requires a human",
    description="Blocks pkill/killall/kill of gatecat|gate.cat|gatecat-hook/shell/proxy, "
                "pip/uv uninstall of the guard, rm/mv/chmod of its entrypoint, and "
                "GATECAT_* enforcement toggles. Benign same-verb ops on other names PASS.",
)

SECURITY_CONTROL_DISABLE = Policy(
    name="SECURITY_CONTROL_DISABLE",
    # BLOCK: turning off the host's mandatory-access-control (SELinux/AppArmor),
    # firewall, audit daemon, EDR sensor, or log-shipping agent blinds the primary
    # host defenses. The unit/name allowlist keeps `systemctl stop myapp`,
    # `systemctl restart nginx`, `iptables -L`, `ufw status` fully allowed.
    patterns=(
        # -- SELinux --
        #    Only DISABLING enforcement is dangerous. Writing 0/Permissive/disabled
        #    to the enforce node (or `setenforce 0`) turns MAC off; writing
        #    1/Enforcing HARDENS the host and MUST pass, mirroring setenforce 0 vs 1.
        #    The value sits BEFORE the redirect/pipe (`echo 0 > node`,
        #    `echo 0 | tee node`), so match the off-value up to the `>`/`| tee`.
        r"\bsetenforce\b\s+(?:0|Permissive)\b",           # permissive mode NOW
        # redirect form: echo/printf <off-value> > /sys/fs/selinux/enforce
        r"\b(?:0|Permissive|disabled)\b[^\n>]*>\s*/sys/fs/selinux/enforce\b",
        # tee, value BEFORE the pipe: echo <off-value> | [sudo] tee <node>
        r"\b(?:0|Permissive|disabled)\b[^\n|]*\|[^\n|]*\btee\b[^\n]*/sys/fs/selinux/enforce\b",
        # tee, value AFTER the node via herestring: tee <node> <<< 0
        r"\btee\b[^\n]*/sys/fs/selinux/enforce\b[^\n]*<<<\s*(?:0|Permissive|disabled)\b",
        r"SELINUX\s*=\s*disabled",                        # persistent config rewrite
        # -- AppArmor --
        r"\baa-teardown\b",                               # unload ALL profiles
        r"\baa-complain\b[^\n]*/etc/apparmor\.d",         # all profiles -> complain
        r"\baa-disable\b",
        # -- systemctl / service stop|kill|disable|mask of a SECURITY unit --
        #    (covers --user / --now and the mask/disable variants uniformly).
        r"\bsystemctl\b(?:\s+--\S+)*\s+(?:stop|kill|disable|mask)\b[^\n]*\b"
        + _SECURITY_UNIT + r"\b",
        r"\bservice\b\s+" + _SECURITY_UNIT + r"\s+stop\b",
        # -- firewall teardown (long-flag & trust-all forms SYSTEM_TAMPER misses) --
        r"\bufw\s+disable\b",
        r"\bfirewall-cmd\b[^\n]*--set-default-zone=trusted\b",
        r"\biptables\b[^\n]*(?:--flush\b|-P\s+\w+\s+ACCEPT)",
        r"\bnft\b[^\n]*\bflush\s+ruleset\b",
        # -- audit daemon disable --
        r"\bauditctl\b[^\n]*(?:-e\s*0\b|--enable\s*0\b|-D\b)",
        # -- EDR control binary --
        r"\bfalconctl\b[^\n]*\s-d\b",
        # -- kill a security daemon by NAME (pkill/killall or pgrep/pidof->kill) --
        r"\b(?:pkill|killall)\b[^\n]*\b" + _SECURITY_UNIT + r"\b",
        r"\bkill\b[^\n]*(?:pgrep|pidof)[^\n]*\b" + _SECURITY_UNIT + r"\b",
        # -- systemd journal purge (erases the host's primary log/audit trail) --
        r"\bjournalctl\b[^\n]*(?:--vacuum-\w+|--rotate)\b",
        # -- shell-session track-hiding the HISTORY_WIPE wall misses (env/rm forms) --
        r"\bunset\s+HISTFILE\b",
        r"(?:^|[\s;&|])(?:export\s+)?HISTFILE\s*=\s*/dev/null\b",
        r"\bset\s+\+o\s+history\b",
        r"(?:^|[\s;&|])(?:export\s+)?HISTSIZE\s*=\s*0\b",
        r"\brm\b[^\n]*(?:~|/\.)?/?\.bash_history\b",
        # -- in-session gate disarm: the --install-bash DEBUG trap / precmd / extdebug --
        r"\btrap\b\s+-\s+DEBUG\b",
        r"\bunset\s+-f\s+__gatecat\w*",
        r"\bshopt\s+-u\s+extdebug\b",
        # -- clear immutable/append-only flags on the audit/log trail so it can be
        #    rewritten (chattr -ia /var/log/audit/audit.log). The combined -ia and
        #    single -i/-a forms are covered on a /var/log target; SYSTEM_TAMPER only
        #    reaches WARN and misses the combined flag form. A benign `chattr +i
        #    ./myfile` (adding protection to a project file) is NOT matched.
        r"\bchattr\b[^\n]*-\w*[ia]\w*\b[^\n]*(?:/var/log/audit|audit\.log|/var/log/)",
        # -- kill the wrapper PARENT shell to escape the gate: kill $PPID / $$.
        #    Killing a specific numeric PID or a child stays allowed - only the
        #    self/parent escape (which drops the enforcing wrapper) is blocked.
        r"\bkill\b[^\n]*(?:\$PPID\b|\$\$(?!\w))",
    ),
    reason="disabling a host security control (SELinux/AppArmor MAC, firewall, "
           "auditd, EDR/CrowdStrike/osquery, log shipping) or hiding shell/session "
           "tracks blinds the host's defenses - requires a human",
    description="Blocks setenforce 0 / selinux enforce-node write / SELINUX=disabled, "
                "apparmor teardown, systemctl|service stop/kill/disable/mask of "
                "apparmor|firewalld|auditd|ufw|osquery|falcon|crowdstrike|clamav|sshd, "
                "ufw disable, iptables/nft flush, killing security daemons, journal "
                "purge, and HISTFILE/trap-DEBUG track-hiding. Benign stop of a "
                "non-security app / iptables -L / ufw status PASS.",
)

# ---------------------------------------------------------------------------
# FREE-CORE state-file self-defense (2026-07-12): the on/off toggle
# (~/.gatecat/protection.json) and the per-command override store
# (~/.gatecat/overrides.json) are the new attack surface introduced by the
# local-control layer. An agent that WRITES either file through a shell -
# `echo off > ...protection.json`, `tee`, `sed -i`, `cp`, `python
# open('...','w')`, a redirect/append - could flip its OWN guard off or
# self-approve a blocked command, defeating the whole free-core promise. BLOCK
# every such write; it is a NEVER_DISARM class (protection.py:NEVER_DISARM), so
# even with protection OFF or an override present it still hard-blocks.
#
# The LEGIT path is untouched: the human uses `gate.cat on/off/allow`, whose
# writer (protection.py) writes the file with the Python stdlib DIRECTLY - not
# by shelling out - so it never passes through this wall. Reading the files
# (`cat`/`less`/`python open('...','r')`) is allowed - only WRITES are blocked.
# Tight path allowlist: only ~/.gatecat/protection.json and overrides.json;
# any other .gatecat file or any other config path is untouched (0-FP).
# ---------------------------------------------------------------------------
_STATE_FILE = r"[/\\]\.gatecat[/\\](?:protection|overrides)\.json\b"

STATE_FILE_TAMPER = Policy(
    name="STATE_FILE_TAMPER",
    patterns=(
        # single/append redirect INTO a state file: `echo off > ...protection.json`,
        # `printf ... >> ...overrides.json`, `... > $HOME/.gatecat/protection.json`.
        r">>?[^\n|;&]*" + _STATE_FILE,
        # tee (with/without -a, sudo prefix) writing a state file.
        r"\btee\b[^\n]*" + _STATE_FILE,
        # in-place stream edit: `sed -i ...protection.json`, perl -i, ex, `dd of=`.
        r"\bsed\b[^\n]*-i[^\n]*" + _STATE_FILE,
        r"\bperl\b[^\n]*-i[^\n]*" + _STATE_FILE,
        r"\bdd\b[^\n]*\bof=[^\n]*" + _STATE_FILE,
        # copy / move / install / link ONTO a state file: the DESTINATION is the
        # LAST operand, so the state file must sit at the END of the command (a
        # `>`/`;`/`|`/`&` may follow). Anchoring to the tail keeps `cp
        # ...protection.json /tmp/backup.json` (reading FROM the file to a backup)
        # ALLOWED - only writing INTO the state file is blocked.
        r"\b(?:cp|mv|install|ln)\b[^\n]*" + _STATE_FILE + r"\s*(?:$|[;&|])",
        # truncate always names the file it shrinks, wherever it sits.
        r"\btruncate\b[^\n]*" + _STATE_FILE,
        r"\b:\s*>[^\n]*" + _STATE_FILE,           # `: > file` truncate idiom
        # a Python/interpreter open(...,'w'|'a'|...)/write_text/Path.write on the file.
        r"open\([^\n)]*\.gatecat[/\\](?:protection|overrides)\.json[^\n)]*['\"][wax]",
        r"write_text\([^\n)]*" + _STATE_FILE,
        # shell/python that names the state file with a write-y verb nearby.
        r"\b(?:chmod|chown)\b[^\n]*" + _STATE_FILE,
    ),
    reason="writing/editing gate.cat's own state files "
           "(~/.gatecat/protection.json or overrides.json) via a shell would let "
           "an agent flip its guard off or self-approve a blocked command - "
           "requires a human (use the `gate.cat on/off/allow` CLI, not a shell write)",
    description="Blocks shell WRITES (>, >>, tee, sed -i, cp/mv/install, dd of=, "
                "python open('w')/write_text) to ~/.gatecat/protection.json and "
                "overrides.json. Reads (cat/less/open('r')) and the gate.cat CLI "
                "path PASS. NEVER_DISARM: still blocks with protection OFF.",
)

DOGFOOD_DEFAULTS: tuple[Policy, ...] = (
    STATE_FILE_TAMPER,
    TERRAFORM_PROD,
    DB_DESTRUCTIVE,
    CLOUD_DESTROY,
    KMS_KEY_DESTROY,
    AUDIT_LOG_TAMPER,
    SECRET_STORE_DELETE,
    # coverage-audit promotions (2026-07-09): universal + catastrophic classes the
    # audit found passing the gate. NON-delete shapes CLOUD_DESTROY misses. The HTTP
    # block MUST precede the HTTP warn so a core-host DELETE resolves as a hard block.
    IAM_PRIVILEGE_ESCALATION,
    IAM_IDENTITY_TAMPER,
    BACKUP_DESTROY,
    HTTP_API_IDENTITY_DNS_DESTROY,
    HTTP_API_DELETE_GENERIC,
    GIT_FORCE_PUSH,
    RM_RF,
    # coverage-gap classes (added 2026-07-05 after an independent catalog
    # measured the deny-list at 8/20): disk, permissions, runtime-delete,
    # overwrite, encoded-exec.
    DISK_DESTROY,
    PERMISSION_LOCKOUT,
    RUNTIME_DELETE,
    OVERWRITE_DESTROY,
    ENCODED_EXEC,
    # recall-gap classes (added 2026-07-05 after an adversarial pass found 10
    # irreversible actions passing): secret/key deletion, history/audit wipe,
    # datastore flush, system tamper (warn), package/volume purge (warn).
    SECRET_DELETE,
    HISTORY_WIPE,
    DATASTORE_FLUSH,
    SYSTEM_TAMPER,
    PACKAGE_PURGE,
    SECRET_READ,
    # CSO recall-gaps: destructive subcommands of allow-listed front-ends.
    GIT_DESTRUCTIVE,
    GH_DESTRUCTIVE,
    CONTAINER_DESTROY,
    REGISTRY_PUBLISH,
    # content-vs-command (0.4.0): Write/Edit content is data; the residual risk
    # is the TARGET PATH being auto-executed later. Warn on both pathways.
    AUTOEXEC_WRITE,
    CLOUD_STORAGE_WIPE,
    CLOUD_STORAGE_SYNC_DELETE,
    STREAM_QUEUE_DESTROY,
    WINDOWS_DESTROY,
    MACOS_DISK_DESTROY,
    DB_DESTRUCTIVE_EXTRA,
    DATASTORE_FLUSH_EXTRA,
    DISK_DESTROY_EXTRA,
    K8S_DESTROY_EXTRA,
    REGISTRY_IMAGE_DELETE,
    SECRET_STORE_DELETE_EXTRA,
    CLOUD_PROTECTION_OFF,
    IAC_STATE_DESTROY,
    # close-153 structure-keyed additions (2026-07-11): plain-core shapes +
    # keygen-overwrite + residual-obfuscated (etcd/pubsub/gh-batch) the hunt found
    # still ALLOWing. Blocks for irreversible key/queue/config loss; warns for the
    # ambiguous-but-serious. Each has a passing benign twin (test_close153.py).
    CLOUD_STORAGE_LIFECYCLE_NUKE,
    CONFIG_MGMT_DESTROY,
    STREAM_RETENTION_PURGE,
    SOPS_KEY_ROTATE_RM,
    PACKAGE_DEPRECATE_ALL,
    REGISTRY_PUSH_EXTRA,
    DB_FILE_REDIRECT_EXEC,
    KEY_OVERWRITE,
    STREAM_SEEK_PURGE,
    ETCD_COMPACT,
    RELEASE_ASSET_MASS_DELETE,
    # 0.4.13 adversarial gap-closers (2026-07-12): 77 engine-confirmed misses from a
    # 9-category hunt. Blocks for whole-disk/data/secret/infra loss; warns for the
    # dev-routine-destructive (ORM reset, cert-file delete). Benign twins pass
    # (test_v0413_gaps.py). CLOUD_PROTECTION_OFF extended in place (rds retention 0,
    # s3 versioning suspend, gcloud compute deletion-protection off).
    DISK_ERASE_EXTRA,
    OVERWRITE_DESTROY_EXTRA,
    CLOUD_DESTROY_EXTRA,
    IAC_STATE_DESTROY_EXTRA,
    DB_DESTRUCTIVE_EXTRA2,
    DB_FRAMEWORK_RESET,
    GIT_DESTRUCTIVE_EXTRA,
    K8S_NODE_DELETE_EXTRA,
    K8S_CRI_DESTROY,
    SECRET_STORE_DELETE_EXTRA2,
    SECRET_FILE_DELETE,
    SECRET_FILE_OVERWRITE,
    WINDOWS_DESTROY_EXTRA,
    WINDOWS_PERMISSION_LOCKOUT,
    # FREE-CORE self-defense (2026-07-12): the guard protects its OWN process/
    # package/entrypoint/env and the HOST's security controls. Block-tier, tight
    # name allowlists; benign same-verb ops on other names PASS (test_self_defense.py).
    GUARD_TAMPER,
    SECURITY_CONTROL_DISABLE,
)

# Default payment policy instance (blocks every payment-shaped action).
# For a real ceiling call the PAYMENTS(max_amount=...) factory directly.
PAYMENTS_DEFAULT = PAYMENTS()

# Every value is a Policy INSTANCE (uniform shape - safe to iterate and
# .to_dict() without isinstance guards). PAYMENTS the factory lives beside
# this dict, not inside it.
ALL_PRESETS: dict[str, Policy] = {
    "STATE_FILE_TAMPER": STATE_FILE_TAMPER,
    "TERRAFORM_PROD": TERRAFORM_PROD,
    "DB_DESTRUCTIVE": DB_DESTRUCTIVE,
    "EMAIL_SEND": EMAIL_SEND,
    "CLOUD_DESTROY": CLOUD_DESTROY,
    "KMS_KEY_DESTROY": KMS_KEY_DESTROY,
    "AUDIT_LOG_TAMPER": AUDIT_LOG_TAMPER,
    "SECRET_STORE_DELETE": SECRET_STORE_DELETE,
    "IAM_PRIVILEGE_ESCALATION": IAM_PRIVILEGE_ESCALATION,
    "IAM_IDENTITY_TAMPER": IAM_IDENTITY_TAMPER,
    "BACKUP_DESTROY": BACKUP_DESTROY,
    "HTTP_API_IDENTITY_DNS_DESTROY": HTTP_API_IDENTITY_DNS_DESTROY,
    "HTTP_API_DELETE_GENERIC": HTTP_API_DELETE_GENERIC,
    "PAYMENTS": PAYMENTS_DEFAULT,
    "GIT_FORCE_PUSH": GIT_FORCE_PUSH,
    "RM_RF": RM_RF,
    "DISK_DESTROY": DISK_DESTROY,
    "PERMISSION_LOCKOUT": PERMISSION_LOCKOUT,
    "RUNTIME_DELETE": RUNTIME_DELETE,
    "OVERWRITE_DESTROY": OVERWRITE_DESTROY,
    "ENCODED_EXEC": ENCODED_EXEC,
    "SECRET_DELETE": SECRET_DELETE,
    "HISTORY_WIPE": HISTORY_WIPE,
    "DATASTORE_FLUSH": DATASTORE_FLUSH,
    "SYSTEM_TAMPER": SYSTEM_TAMPER,
    "PACKAGE_PURGE": PACKAGE_PURGE,
    "SECRET_READ": SECRET_READ,
    "GIT_DESTRUCTIVE": GIT_DESTRUCTIVE,
    "GH_DESTRUCTIVE": GH_DESTRUCTIVE,
    "CONTAINER_DESTROY": CONTAINER_DESTROY,
    "REGISTRY_PUBLISH": REGISTRY_PUBLISH,
    "AUTOEXEC_WRITE": AUTOEXEC_WRITE,
    "CLOUD_STORAGE_WIPE": CLOUD_STORAGE_WIPE,
    "CLOUD_STORAGE_SYNC_DELETE": CLOUD_STORAGE_SYNC_DELETE,
    "STREAM_QUEUE_DESTROY": STREAM_QUEUE_DESTROY,
    "WINDOWS_DESTROY": WINDOWS_DESTROY,
    "MACOS_DISK_DESTROY": MACOS_DISK_DESTROY,
    "DB_DESTRUCTIVE_EXTRA": DB_DESTRUCTIVE_EXTRA,
    "DATASTORE_FLUSH_EXTRA": DATASTORE_FLUSH_EXTRA,
    "DISK_DESTROY_EXTRA": DISK_DESTROY_EXTRA,
    "K8S_DESTROY_EXTRA": K8S_DESTROY_EXTRA,
    "REGISTRY_IMAGE_DELETE": REGISTRY_IMAGE_DELETE,
    "SECRET_STORE_DELETE_EXTRA": SECRET_STORE_DELETE_EXTRA,
    "CLOUD_PROTECTION_OFF": CLOUD_PROTECTION_OFF,
    "IAC_STATE_DESTROY": IAC_STATE_DESTROY,
    "CLOUD_STORAGE_LIFECYCLE_NUKE": CLOUD_STORAGE_LIFECYCLE_NUKE,
    "CONFIG_MGMT_DESTROY": CONFIG_MGMT_DESTROY,
    "STREAM_RETENTION_PURGE": STREAM_RETENTION_PURGE,
    "SOPS_KEY_ROTATE_RM": SOPS_KEY_ROTATE_RM,
    "PACKAGE_DEPRECATE_ALL": PACKAGE_DEPRECATE_ALL,
    "REGISTRY_PUSH_EXTRA": REGISTRY_PUSH_EXTRA,
    "DB_FILE_REDIRECT_EXEC": DB_FILE_REDIRECT_EXEC,
    "KEY_OVERWRITE": KEY_OVERWRITE,
    "STREAM_SEEK_PURGE": STREAM_SEEK_PURGE,
    "ETCD_COMPACT": ETCD_COMPACT,
    "RELEASE_ASSET_MASS_DELETE": RELEASE_ASSET_MASS_DELETE,
    "DISK_ERASE_EXTRA": DISK_ERASE_EXTRA,
    "OVERWRITE_DESTROY_EXTRA": OVERWRITE_DESTROY_EXTRA,
    "CLOUD_DESTROY_EXTRA": CLOUD_DESTROY_EXTRA,
    "IAC_STATE_DESTROY_EXTRA": IAC_STATE_DESTROY_EXTRA,
    "DB_DESTRUCTIVE_EXTRA2": DB_DESTRUCTIVE_EXTRA2,
    "DB_FRAMEWORK_RESET": DB_FRAMEWORK_RESET,
    "GIT_DESTRUCTIVE_EXTRA": GIT_DESTRUCTIVE_EXTRA,
    "K8S_NODE_DELETE_EXTRA": K8S_NODE_DELETE_EXTRA,
    "K8S_CRI_DESTROY": K8S_CRI_DESTROY,
    "SECRET_STORE_DELETE_EXTRA2": SECRET_STORE_DELETE_EXTRA2,
    "SECRET_FILE_DELETE": SECRET_FILE_DELETE,
    "SECRET_FILE_OVERWRITE": SECRET_FILE_OVERWRITE,
    "WINDOWS_DESTROY_EXTRA": WINDOWS_DESTROY_EXTRA,
    "WINDOWS_PERMISSION_LOCKOUT": WINDOWS_PERMISSION_LOCKOUT,
    "GUARD_TAMPER": GUARD_TAMPER,
    "SECURITY_CONTROL_DISABLE": SECURITY_CONTROL_DISABLE,
}
