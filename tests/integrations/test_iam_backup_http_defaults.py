"""Regression: IAM privilege-escalation, backup destruction, and HTTP-API
identity/DNS destruction are handled by the CORE defaults.

The 2026-07-09 coverage audit (COVERAGE_AUDIT_2026-07-09) found three UNIVERSAL +
catastrophic classes PASSING the default gate: CLOUD_DESTROY keys on the
`delete-`/`terminate-`/`remove-` VERBS, so IAM escalation (attach/put/add-binding),
backup destruction (restic/borg forget|prune, zfs destroy), and the HTTP-API DELETE
modality (`curl -X DELETE https://api.<provider>/...`) all slipped past. Promoted from
the opt-in packs into DOGFOOD_DEFAULTS per the binding business-model rule
(universal + catastrophic -> free core), exactly as KMS/Vault were.

Each danger must be NEUTRALIZED (block, or warn for the ambiguous tamper/generic
classes); each benign twin must PASS. The benign twins are the exact look-alikes
each source pack's docstring promises still pass (attach ReadOnly, add roles/viewer
binding, restic snapshots, `curl -X GET`, a build-cache recursive delete) - a
false-block here is the adoption-killer metric.

`env={}` forces the gate ARMED (no CI ephemeral-disarm) so the assertions are
deterministic regardless of the runner's environment.
"""
import pytest

from gatecat.integrations import ActionVetoed, check_action
from gatecat.integrations.policies import (
    DOGFOOD_DEFAULTS,
    BACKUP_DESTROY,
    HTTP_API_DELETE_GENERIC,
    HTTP_API_IDENTITY_DNS_DESTROY,
    IAM_IDENTITY_TAMPER,
    IAM_PRIVILEGE_ESCALATION,
)

# --- dangers that must HARD-BLOCK (non-delete shapes CLOUD_DESTROY misses) ---
DANGER_BLOCK = [
    # IAM privilege escalation
    "aws iam attach-user-policy --user-name c --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    'aws iam put-user-policy --user-name a --policy-name e --policy-document \'{"Action":"*"}\'',
    "gcloud projects add-iam-policy-binding p --member=serviceAccount:x --role=roles/owner",
    "az role assignment create --assignee c@x.com --role Owner --scope /subscriptions/1",
    # backup / snapshot destruction
    "restic -r /srv/repo forget --keep-last 1 --prune",
    "borg prune --keep-daily 0 /srv/borgrepo",
    "zfs destroy tank/backups@daily-2026-07-01",
    "btrfs subvolume delete /mnt/snapshots/2026-07-01",
    "velero backup delete nightly-2026-07-01",
    "aws ec2 delete-snapshot --snapshot-id snap-0abc",
    "gcloud compute snapshots delete daily-snap",
    # HTTP-API identity / DNS / domain destruction
    "curl -X DELETE https://api.cloudflare.com/client/v4/zones/z/dns_records/r -H 'Authorization: Bearer t'",
    "curl -X DELETE https://dev-x.okta.com/api/v1/users/00u1 -H 'Authorization: SSWS t'",
    "curl -X POST https://graph.microsoft.com/v1.0/directoryRoles/roleId/members/$ref -d '{}'",
]

# --- dangers that must at least WARN (ambiguous: real admins do these too) ---
DANGER_WARN = [
    "aws iam deactivate-mfa-device --user-name admin --serial-number x",
    "aws iam detach-user-policy --user-name svc --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess",
    "gcloud projects remove-iam-policy-binding p --member=user:x --role=roles/owner",
    "curl -X DELETE https://api.example.com/v1/widgets/42",
]

# --- benign twins the docstrings promise still PASS (0 false-blocks) ---
BENIGN = [
    # IAM: attach a ReadOnly policy / grant viewer / read-only queries
    "aws iam attach-user-policy --user-name svc --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "gcloud projects add-iam-policy-binding p --member=user:x --role=roles/viewer",
    "gcloud projects get-iam-policy p",
    "aws iam list-users",
    "aws iam list-mfa-devices --user-name admin",
    # backup: list / describe / check still pass; build-cache recursive delete passes
    "restic -r /srv/repo snapshots",
    "borg list /srv/borgrepo",
    "velero backup get",
    "zfs list -t snapshot",
    "aws ec2 describe-snapshots",
    "aws s3 rm s3://build-cache/tmp/ --recursive",
    # HTTP: curl GET / POST to a non-core host / localhost DELETE pass
    "curl -X GET 'https://api.cloudflare.com/client/v4/zones'",
    "curl -X POST 'https://api.example.com/v1/users' -d '{}'",
    "curl -X DELETE http://localhost:8080/cache/tmp",
    "curl -X DELETE http://127.0.0.1:3000/session/a",
    "wget https://example.com/file.tar.gz",
]


@pytest.mark.parametrize("cmd", DANGER_BLOCK)
def test_escalation_backup_identity_destruction_blocks(cmd):
    with pytest.raises(ActionVetoed):
        check_action("agent", cmd, DOGFOOD_DEFAULTS, env={})


@pytest.mark.parametrize("cmd", DANGER_WARN)
def test_ambiguous_tamper_and_generic_delete_warn(cmd):
    # must NOT hard-block (no raise) but must be surfaced, never a silent allow
    decision = check_action("agent", cmd, DOGFOOD_DEFAULTS, env={})
    assert decision.level == "warn", f"{cmd!r} -> {decision.level} (expected warn)"


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_docstring_twins_pass(cmd):
    # reads/lists and the promised look-alikes must be fully allowed (not warn)
    decision = check_action("agent", cmd, DOGFOOD_DEFAULTS, env={})
    assert decision.level == "allow", f"{cmd!r} false-blocked/warned -> {decision.level}"


def test_new_policies_are_in_core_defaults():
    for policy in (
        IAM_PRIVILEGE_ESCALATION,
        IAM_IDENTITY_TAMPER,
        BACKUP_DESTROY,
        HTTP_API_IDENTITY_DNS_DESTROY,
        HTTP_API_DELETE_GENERIC,
    ):
        assert policy in DOGFOOD_DEFAULTS


def test_http_block_precedes_http_warn():
    """A core-host DELETE must resolve as a hard block, so the block policy has to
    sit before the generic-warn policy in the default ordering."""
    names = [p.name for p in DOGFOOD_DEFAULTS]
    assert names.index("HTTP_API_IDENTITY_DNS_DESTROY") < names.index("HTTP_API_DELETE_GENERIC")
