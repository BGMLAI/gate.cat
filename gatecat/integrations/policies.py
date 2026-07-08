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
        # destroy`); lookahead requires the verb, then match prod or -auto-approve
        r"\b(terraform|tofu)\b(?=.*\b(apply|destroy)\b).*(\bprod|-auto-approve)",
    ),
    reason="terraform apply/destroy against production requires a human",
    description="Blocks Terraform/OpenTofu apply/destroy touching prod or auto-approved.",
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
        r"\bgh\s+(release|secret|ssh-key|gpg-key|label)\s+delete\b",
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
    # force flag that is not --force-with-lease
    patterns=(r"\bgit\b(?=.*\bpush\b).*(--force(?!-with-lease)|(?<!\w)-f(?!\w))",),
    reason="git push --force (without --force-with-lease) requires a human",
    description="Blocks history-destroying force pushes.",
)

RM_RF = Policy(
    name="RM_RF",
    # combined flags in any order incl. extra letters (-rf, -rfv, -Rfi, -fr) and
    # split flags (-r -f); the old trailing \\b let `-rfv` slip through
    patterns=(r"\brm\b(?=.*(-\w*r\w*f|-\w*f\w*r|-r\b.*-f\b|-f\b.*-r\b))",),
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

DOGFOOD_DEFAULTS: tuple[Policy, ...] = (
    TERRAFORM_PROD,
    DB_DESTRUCTIVE,
    CLOUD_DESTROY,
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
}
