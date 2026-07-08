"""A2 example: veto gate on a crewAI payment tool (duplicate-payment class,
crewAI#5802).

Requires: pip install gate.cat[crewai]   (engine >= 0.3.0 + crewAI)

The crew below has one tool that can move money. Wrapped in the veto gate
with ``PAYMENTS(max_amount=100)``, any payment-shaped call is blocked and
raises ``ActionVetoed`` - the crew surfaces it to a human instead of paying
twice. The gate is only certain about what it BLOCKS; calls it does not
match are unchecked, not "verified safe".
"""

from gatecat.integrations import ActionVetoed
from gatecat.integrations.crewai import wrap_tool
from gatecat.integrations.policies import PAYMENTS


def main() -> None:
    try:
        from crewai.tools import BaseTool
    except ImportError:
        print("This adapter demo needs crewAI: pip install 'gate-cat[crewai]'\n"
              "(the veto gate itself is zero-dependency and needs none of it — "
              "see veto_autogen.py for a framework-free run.)")
        return

    class ExecutePayment(BaseTool):
        # the tool NAME is part of the evaluated action text - payment-shaped
        # names are what the PAYMENTS deny patterns key on
        name: str = "execute_payment"
        description: str = "Execute a payment for an approved invoice."

        def _run(self, invoice_id: str, amount: float) -> str:
            return f"paid {invoice_id}: {amount}"  # imagine a Stripe call here

    guarded = wrap_tool(ExecutePayment(), policies=[PAYMENTS(max_amount=100)])

    # In a real crew: Agent(tools=[guarded], ...). Direct call for the demo:
    try:
        guarded._run(invoice_id="INV-42", amount=350.0)
    except ActionVetoed as exc:
        print(f"blocked as expected -> {exc}")


if __name__ == "__main__":
    main()
