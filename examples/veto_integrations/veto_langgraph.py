"""A3 example: veto gate in front of a LangGraph tool node, routed into
human-in-the-loop on block (langgraph#7895 class of problems).

Requires: pip install gate.cat[langgraph]   (engine >= 0.3.0 + LangGraph)

``guard_tools`` wraps each tool so the gate runs before execution.
``ActionVetoed`` is caught in the node and turned into a LangGraph
``interrupt`` - a human approves or rejects, the graph resumes.
"""

from gatecat.integrations import ActionVetoed
from gatecat.integrations.langgraph import guard_tools
from gatecat.integrations.policies import CLOUD_DESTROY, TERRAFORM_PROD


def deploy(cmd: str) -> str:
    """Pretend infra tool an agent can call."""
    return f"executed: {cmd}"


def main() -> None:
    try:
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import interrupt
    except ImportError:
        print("This adapter demo needs LangGraph: pip install 'gate-cat[langgraph]'\n"
              "(the veto gate itself is zero-dependency and needs none of it — "
              "see veto_autogen.py for a framework-free run.)")
        return

    [guarded_deploy] = guard_tools([deploy], policies=[TERRAFORM_PROD, CLOUD_DESTROY])

    def tool_node(state: dict) -> dict:
        try:
            return {"result": guarded_deploy(state["cmd"])}
        except ActionVetoed as exc:
            # gate said no -> hand to a human instead of executing
            answer = interrupt({"veto": str(exc), "cmd": state["cmd"]})
            if answer == "approve":
                return {"result": deploy(state["cmd"])}  # human took responsibility
            return {"result": f"rejected by human after veto: {exc}"}

    graph = StateGraph(dict)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile()

    print(app.invoke({"cmd": "terraform plan"}))  # passes the gate


if __name__ == "__main__":
    main()
