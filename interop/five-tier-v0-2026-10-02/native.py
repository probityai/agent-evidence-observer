"""Execute the finite declaration with native Inspect mock solver/agent loops."""
from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

from owned_tools import OwnedTools
from protocol import VERSION, digest, encode


def native_tools(owned: OwnedTools) -> list[Any]:
    """Create actual Inspect tools over one caller-selected scoped target.

    Parameters
    ----------
    owned : OwnedTools
        Per-attempt target and recorder; model arguments never choose a path.

    Returns
    -------
    list
        Registered tools invoked by Inspect's native tool and agent execution.
    """
    return [factory(owned) for factory in (double_tool, read_file_tool, write_file_tool, read_balance_tool, transfer_tool)]


def double_tool(owned: OwnedTools) -> Any:
    """Register double against the selected owned target."""
    from inspect_ai.tool import tool

    @tool
    def double() -> Any:
        async def execute(value: int) -> str:
            """Double a bounded integer.

            Parameters
            ----------
            value : int
                Integer from minus one hundred to one hundred.
            """
            return owned.invoke("double", {"value": value})
        return execute
    return double()


def read_file_tool(owned: OwnedTools) -> Any:
    """Register read_file against the selected owned target."""
    from inspect_ai.tool import tool

    @tool
    def read_file() -> Any:
        async def execute() -> str:
            """Read the single scoped ticket."""
            return owned.invoke("read_file", {})
        return execute
    return read_file()


def write_file_tool(owned: OwnedTools) -> Any:
    """Register write_file against the selected owned target."""
    from inspect_ai.tool import tool

    @tool
    def write_file() -> Any:
        async def execute(content: str) -> str:
            """Commit the single allowed ticket transition.

            Parameters
            ----------
            content : str
                Requested value; only DONE is accepted.
            """
            return owned.invoke("write_file", {"content": content})
        return execute
    return write_file()


def read_balance_tool(owned: OwnedTools) -> Any:
    """Register read_balance against the selected owned target."""
    from inspect_ai.tool import tool

    @tool
    def read_balance() -> Any:
        async def execute() -> str:
            """Read the two ordered committed SQLite balances."""
            return owned.invoke("read_balance", {})
        return execute
    return read_balance()


def transfer_tool(owned: OwnedTools) -> Any:
    """Register transfer against the selected owned target."""
    from inspect_ai.tool import tool

    @tool
    def transfer() -> Any:
        async def execute(amount: int) -> str:
            """Atomically transfer from source to destination.

            Parameters
            ----------
            amount : int
                Amount from one through ten; insufficient funds refuse.
            """
            return owned.invoke("transfer", {"amount": amount})
        return execute
    return transfer()


def execute(case: dict[str, Any], declared: dict[str, Any], directory: Path) -> Path:
    """Run one native task once and return its fresh original JSON log.

    All response text and tool invocations are controlled integration inputs.
    Native framework failures remain in the original log. The caller records
    launch failures separately and never creates a substitute native log.
    """
    import inspect_ai
    from inspect_ai.agent import react
    from inspect_ai.dataset import Sample
    from inspect_ai.model import (
        ChatMessageAssistant,
        ModelOutput,
        ModelUsage,
        get_model,
    )
    from inspect_ai.scorer import match
    from inspect_ai.solver import generate, use_tools
    from inspect_ai.tool import ToolCall

    if importlib.metadata.version("inspect-ai") != declared["framework"]["inspect-ai"]:
        raise ValueError("framework_version")
    owned = OwnedTools(directory)
    tools = native_tools(owned)
    outputs = [ModelOutput.from_message(ChatMessageAssistant(content="", tool_calls=[ToolCall(id=f"call-{i}", function=call["name"], arguments=call["arguments"])]), stop_reason="tool_calls") for i, call in enumerate(case["calls"])]
    if case["response"] is not None:
        outputs.append(ModelOutput.from_content(model="mockllm", content=case["response"]))
    for output in outputs:
        output.usage = ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0)
    model = get_model("mockllm/model", custom_outputs=outputs)
    solver = [use_tools(tools), generate()] if case["solver"] == "generate" else react(tools=tools, submit=False)
    task = inspect_ai.Task(dataset=[Sample(id=case["id"], input=case["input"], target=case["target"])], solver=solver, scorer=match(), name=case["id"], version=1, metadata={"probity_profile": VERSION, "declaration_sha256": digest(encode(declared))}, message_limit=8 if case["solver"] == "react-8" else 12)
    inspect_ai.eval(task, model=model, display="none", log_format="json", log_dir=str(directory / "native"), epochs=1, retry_on_error=0, max_samples=1, fail_on_error=True)
    paths = list((directory / "native").glob("*.json"))
    if len(paths) != 1:
        raise ValueError("native_log_population")
    (directory / "readback.json").write_bytes(encode(owned.readback()))
    return paths[0]
