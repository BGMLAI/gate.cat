"""Stop an agent from applying Terraform to prod before it happens.

Real incident this mirrors: microsoft/autogen#7770 — an agent destroyed a
production AWS account, $106k loss, because nothing checked the tool call
before it ran. `before_action` runs a policy check BEFORE the wrapped
function executes; a vetoed call raises `ActionVetoed` (or, with
`on_veto`, returns a fallback instead of executing).

Run: python examples/veto_terraform.py
"""

from gatecat import ActionPolicy, ActionVetoed, before_action


# deny: hard block, no override. require_human: needs an approve callback.
policy = ActionPolicy(
    deny=[r"terraform\s+(destroy|apply).*\bprod\b"],
    require_human=[r"terraform\s+apply.*\bstaging\b"],
)


def ask_human(call_repr: str) -> bool:
    # Replace with a real approval channel (Slack, CLI prompt, ticket system).
    # Returning False here means "not approved" -> veto stands.
    print(f"  [human-in-loop] would ask a person to approve: {call_repr}")
    return False


@before_action(policy, human_approve=ask_human)
def run_terraform(command: str) -> str:
    print(f"  [EXECUTING] {command}")
    return f"ran: {command}"


def demo(command: str) -> None:
    print(f"\n> run_terraform({command!r})")
    try:
        result = run_terraform(command)
        print(f"  PASS -> {result}")
    except ActionVetoed as exc:
        # ASCII-safe: exc.reason may contain non-ASCII text (Windows console default
        # encoding is cp1252, not UTF-8, and crashes on print() otherwise).
        reason = exc.reason.encode("ascii", "replace").decode("ascii")
        print(f"  BLOCKED -> [{exc.mur}] {reason}")


if __name__ == "__main__":
    demo("terraform apply dev")               # pass: no rule matches
    demo("terraform destroy prod")            # block: hard deny
    demo("terraform apply staging")           # human-in-loop: ask_human() returns False -> veto
