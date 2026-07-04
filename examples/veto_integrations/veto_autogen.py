"""A5 example: veto gate on an AutoGen tool - EXAMPLE ONLY, no adapter.

AutoGen's API is mid-rebuild (0.2 -> 0.4); per VETO_PIPELINE_PLAN.md we ship
an example and build an adapter only if someone asks (issue-driven). The
$106k runaway (autogen#7770) is exactly the class of action a veto gate
exists for.

Requires: pip install cacheback-ai autogen-agentchat  (engine >= 0.3.0)

No AutoGen-specific glue is needed: AutoGen tools are plain callables, so
the generic ``guard_callable`` is enough.
"""

from cacheback.integrations import ActionVetoed, guard_callable  # framework-agnostic
from cacheback.integrations.policies import CLOUD_DESTROY, PAYMENTS


def provision(cmd: str) -> str:
    """Pretend cloud tool an AutoGen agent can call."""
    return f"executed: {cmd}"


guarded_provision = guard_callable(
    provision,
    policies=[CLOUD_DESTROY, PAYMENTS(max_amount=50)],
    source="autogen",
)


def main() -> None:
    # Register ``guarded_provision`` as the tool in your AutoGen agent, e.g.
    #   AssistantAgent(..., tools=[guarded_provision])
    # Direct calls for the demo:
    print(guarded_provision("aws ec2 describe-instances"))
    try:
        guarded_provision("aws ec2 terminate-instances --instance-ids i-123")
    except ActionVetoed as exc:
        print(f"blocked as expected -> {exc}")


if __name__ == "__main__":
    main()
