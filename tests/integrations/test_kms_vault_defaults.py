"""Regression: cloud key/secret destruction is blocked by the CORE defaults.

The `destroy`/`disable`/`purge` verbs (and vault/doppler) key off shapes that
CLOUD_DESTROY (which matches `delete`/`terminate`) does not catch, so these
irreversible ops passed the gate on 0.4.7. Promoted from the opt-in
cloud_secrets pack into DOGFOOD_DEFAULTS on 2026-07-09. Each danger must BLOCK;
each benign twin must PASS (false-blocks are the adoption-killer metric).
"""
import pytest

from gatecat.integrations import ActionVetoed, check_action
from gatecat.integrations.policies import (
    DOGFOOD_DEFAULTS,
    KMS_KEY_DESTROY,
    SECRET_STORE_DELETE,
)

DANGER = [
    "aws kms schedule-key-deletion --key-id abcd",
    "aws kms disable-key --key-id abcd",
    "gcloud kms keys versions destroy 1 --key k --keyring r --location l",
    "vault kv delete secret/prod/db",
    "vault kv metadata delete secret/prod/db",
    "az keyvault secret purge --name apikey --vault-name v",
    "az keyvault key purge --name k --vault-name v",
    "doppler secrets delete API_KEY",
    "aws secretsmanager delete-secret --secret-id x --force-delete-without-recovery",
]

BENIGN = [
    "aws kms list-keys",
    "aws kms describe-key --key-id abcd",
    "vault kv get secret/prod/db",
    "vault kv list secret/prod",
    "az keyvault secret show --name apikey --vault-name v",
    "gcloud kms keys list --keyring r --location l",
    "doppler secrets download",
]


@pytest.mark.parametrize("cmd", DANGER)
def test_key_secret_destruction_blocks(cmd):
    with pytest.raises(ActionVetoed):
        check_action("agent", cmd, DOGFOOD_DEFAULTS)


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_key_secret_ops_pass(cmd):
    # must NOT raise (reading/listing keys and secrets is fine)
    check_action("agent", cmd, DOGFOOD_DEFAULTS)


def test_new_policies_are_in_core_defaults():
    assert KMS_KEY_DESTROY in DOGFOOD_DEFAULTS
    assert SECRET_STORE_DELETE in DOGFOOD_DEFAULTS
