"""Pydantic models for OpenAI-compatible API request/response."""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field


# --- Request models ---

class ChatMessage(BaseModel):
    role: str
    content: str | list[Any] = ""
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    n: Optional[int] = None
    stream: Optional[bool] = False
    stop: Optional[str | list[str]] = None
    max_tokens: Optional[int] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    user: Optional[str] = None
    # Tool use — passthrough (no caching for tool calls)
    tools: Optional[list[Any]] = None
    tool_choice: Optional[Any] = None
    # KORYTO-exec — jawny szczelny kanał: klient świadomie podaje wykonywalny kod
    # do weryfikacji odpowiedzi. {"lang":"python","stmts":[...]} lub {"lang":"node","code":"..."}.
    # Przechodzi przez pełny sandbox. Niezależny od auto-wyłuskania z ruchu (które jest UNSAFE).
    koryto_exec: Optional[dict] = None
    # Any other params → passthrough
    model_config = {"extra": "allow"}


# --- Response models ---

class ChatCompletionMessage(BaseModel):
    role: str = "assistant"
    content: Optional[str] = None


class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatCompletionMessage
    finish_reason: Optional[str] = "stop"


class CompletionUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid.uuid4().hex[:24]}")
    object: str = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str = ""
    choices: list[ChatCompletionChoice] = []
    usage: CompletionUsage = Field(default_factory=CompletionUsage)
    # gatecat metadata
    gatecat_hit: bool = False
    gatecat_synthesized: bool = False


# --- Streaming chunk models ---

class DeltaContent(BaseModel):
    role: Optional[str] = None
    content: Optional[str] = None


class StreamChoice(BaseModel):
    index: int = 0
    delta: DeltaContent
    finish_reason: Optional[str] = None


class ChatCompletionChunk(BaseModel):
    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid.uuid4().hex[:24]}")
    object: str = "chat.completion.chunk"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str = ""
    choices: list[StreamChoice] = []
