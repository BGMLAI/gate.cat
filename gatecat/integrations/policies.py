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
        r"\baws\b.*(?<![\w/-])(delete-|terminate-|remove-)\w+",
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
        r"\bkubectl\b(?=[^\n]*\bdelete\b)[^\n]*\b(ns|namespace|deploy|deployment|"
        r"pvc|pv|pod|pods|secret|secrets|statefulset|sts|configmap|cm|job|cronjob|"
        r"service|svc|replicaset|rs|ingress|daemonset|ds|all)\b",
        r"\bhelm\s+(uninstall|delete)\b",
    ),
    reason="cloud resource deletion requires a human",
    description="Blocks delete/terminate calls to AWS/GCP/Azure/vast.ai/k8s/helm.",
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
        r"\bgit\s+branch\s+-D\b|\bgit\s+branch\s+(-d|--delete)\s+[^\n]*--force",
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
        # GPT/MBR partition-table nuke: sgdisk -Z/--zap-all, -o/--clear (new
        # empty GPT), -g/--mbrtogpt. Read-only forms (-p print, -i info) have
        # no Z/o/g flag and stay allowed.
        r"\bsgdisk\b[^\n|;&]*(?:--zap-all|--clear|--mbrtogpt|\s-[a-zA-Z]*[Zog])[^\n|;&]*/dev/",
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
        r"\bufw\s+(disable|reset)\b|\biptables\s+-F\b",  # firewall teardown
        r"\bkill\b[^\n]*\s-9?\s*1\b|\bkill\s+-(KILL|9)\s+1\b",  # kill init (pid 1)
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
        # piping ANY file to the network as a data body (curl -d @file, wget POST)
        r"\bcurl\b[^\n]*(-d\s*@|--data(-binary|-raw)?\s*@|-T\s|--upload-file\s)",
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
    ),
    reason="recursive/mirror deletion of cloud object storage (S3/GCS/Azure/rclone/minio) is irreversible on unversioned buckets",
    description="recursive/mirror deletion of cloud object storage (S3/GCS/Azure/rclone/minio) is irreversible on unversioned buckets",
)

STREAM_QUEUE_DESTROY = Policy(
    name="STREAM_QUEUE_DESTROY",
    patterns=(
        r"""\bkafka-topics\b(?=.*\s--delete\b)|\bkafka-delete-records\b""",
        r"""\bkafka-consumer-groups\b(?=.*\s--reset-offsets\b)(?=.*\s--execute\b)""",
        r"""\bsqs\s+purge-queue\b|\bpubsub\s+(?:topics|subscriptions)\s+delete\b""",
        r"""\brabbitmqctl\s+(?:reset|delete_queue|purge_queue)\b""",
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
        r"""(?:^|[;&|]\s*|\s)(?:dropdb|dropuser)\b|\bmysqladmin\b(?:(?![;&|#]).)*\bdrop\s+\S""",
        r"""\bDROP\s+(?:TABLESPACE|USER|DATABASE|SCHEMA|KEYSPACE|COLUMN|REPLICATION\s+SLOT)\b|\bALTER\s+TABLE\b(?:(?![;'"]).)*\bDROP\s+COLUMN\b""",
        r"""\bRESET\s+MASTER\b|\bpg_drop_replication_slot\b|\bDROP\s+REPLICATION\s+SLOT\b|\bTRUNCATE\s+(?:TABLE\s+)?["'`\w]""",
        r"""\bpg_ctl\b(?:(?![;&|]).)*\bstop\b(?:(?![;&|]).)*(?:-m\s+immediate|--mode[ =]immediate)|(?:-m\s+immediate|--mode[ =]immediate)(?:(?![;&|]).)*\bstop\b""",
    ),
    reason="database-destroying op beyond DROP TABLE (dropdb, mysqladmin drop, DROP USER/COLUMN/TABLESPACE/KEYSPACE, RESET MASTER, TRUNCATE, immediate stop, drop replication slot)",
    description="database-destroying op beyond DROP TABLE (dropdb, mysqladmin drop, DROP USER/COLUMN/TABLESPACE/KEYSPACE, RESET MASTER, T",
)

DATASTORE_FLUSH_EXTRA = Policy(
    name="DATASTORE_FLUSH_EXTRA",
    patterns=(
        r"""\betcdctl\b(?=[^\n]*\bdel(?:ete)?(?:-range)?\b)(?=[^\n]*--prefix\b)""",
        r"""(?:-X\s*(?:POST|DELETE)|--request\s*(?:POST|DELETE))[^\n]*://[^\n]*(?:/_delete_by_query\b|:9200/[A-Za-z0-9_.*-]+(?:/_doc)?\s*(?:['"]?\s*$|['"]?\s*[|;&]))""",
        r"""\bnodetool\b[^\n]*\bclearsnapshot\b""",
        r"""\bmongo(?:sh)?\b[^\n]*--eval\b[^\n]*\.(?:drop|dropDatabase)\s*\(|\bmongo(?:sh)?\b[^\n]*--eval\b[^\n]*\.deleteMany\s*\(\s*\{\s*\}\s*\)|\bredis-cli\b[^\n]*(?:--scan|\bscan\b|\bkeys\b)[^\n]*\|[^\n]*\bredis-cli\b[^\n]*\b(?:del|unlink|flushall|flushdb)\b""",
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

DOGFOOD_DEFAULTS: tuple[Policy, ...] = (
    TERRAFORM_PROD,
    DB_DESTRUCTIVE,
    CLOUD_DESTROY,
    KMS_KEY_DESTROY,
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
    STREAM_QUEUE_DESTROY,
    WINDOWS_DESTROY,
    MACOS_DISK_DESTROY,
    DB_DESTRUCTIVE_EXTRA,
    DATASTORE_FLUSH_EXTRA,
    DISK_DESTROY_EXTRA,
    K8S_DESTROY_EXTRA,
    REGISTRY_IMAGE_DELETE,
    SECRET_STORE_DELETE_EXTRA,
)

# Default payment policy instance (blocks every payment-shaped action).
# For a real ceiling call the PAYMENTS(max_amount=...) factory directly.
PAYMENTS_DEFAULT = PAYMENTS()

# Every value is a Policy INSTANCE (uniform shape - safe to iterate and
# .to_dict() without isinstance guards). PAYMENTS the factory lives beside
# this dict, not inside it.
ALL_PRESETS: dict[str, Policy] = {
    "TERRAFORM_PROD": TERRAFORM_PROD,
    "DB_DESTRUCTIVE": DB_DESTRUCTIVE,
    "EMAIL_SEND": EMAIL_SEND,
    "CLOUD_DESTROY": CLOUD_DESTROY,
    "KMS_KEY_DESTROY": KMS_KEY_DESTROY,
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
    "STREAM_QUEUE_DESTROY": STREAM_QUEUE_DESTROY,
    "WINDOWS_DESTROY": WINDOWS_DESTROY,
    "MACOS_DISK_DESTROY": MACOS_DISK_DESTROY,
    "DB_DESTRUCTIVE_EXTRA": DB_DESTRUCTIVE_EXTRA,
    "DATASTORE_FLUSH_EXTRA": DATASTORE_FLUSH_EXTRA,
    "DISK_DESTROY_EXTRA": DISK_DESTROY_EXTRA,
    "K8S_DESTROY_EXTRA": K8S_DESTROY_EXTRA,
    "REGISTRY_IMAGE_DELETE": REGISTRY_IMAGE_DELETE,
    "SECRET_STORE_DELETE_EXTRA": SECRET_STORE_DELETE_EXTRA,
}
