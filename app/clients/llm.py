"""OpenAI-compatible chat client (Groq) with multi-model fallback."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Protocol

from openai import OpenAI

from app.config import Settings

logger = logging.getLogger(__name__)


class LLMClient(Protocol):
    def complete(
        self,
        *,
        system: str,
        user: str,
        temperature: float = 0.0,
        response_json: bool = False,
        max_tokens: int | None = None,
    ) -> str: ...

    def complete_with_tools(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        max_tokens: int | None = None,
        tool_choice: str | dict[str, Any] = "auto",
    ) -> Any:
        """Optional tool-calling turn. Returns the raw assistant message object."""
        ...


class OpenAICompatibleLLM:
    """OpenAI-compatible chat client (ModelScope Hy3, Groq, etc.).

    Only message.content is returned — never chain-of-thought / reasoning_content.
    """

    def __init__(self, settings: Settings) -> None:
        api_key = settings.resolve_llm_api_key()
        if not api_key:
            raise ValueError(
                "No LLM API key. Set LLM_API_KEY (Cerebras), MODELSCOPE_API_KEY, "
                "or GROQ_API_KEY. See .env.example."
            )
        self._client = OpenAI(
            base_url=settings.llm_base_url.rstrip("/"),
            api_key=api_key,
            max_retries=2,
            timeout=120.0,
        )
        self._models = settings.llm_model_chain()
        self._tool_models = settings.tool_llm_model_chain()
        self._reasoning_effort = (settings.llm_reasoning_effort or "none").strip()
        self._default_max_tokens = settings.llm_max_tokens
        self.last_model_used: str | None = None
        self.last_tool_model_used: str | None = None
        logger.info(
            "LLM client ready base=%s models=%s tool_models=%s reasoning_effort=%s",
            settings.llm_base_url,
            self._models,
            self._tool_models,
            self._reasoning_effort,
        )

    @property
    def model(self) -> str:
        return self._models[0]

    @property
    def models(self) -> list[str]:
        return list(self._models)

    def complete(
        self,
        *,
        system: str,
        user: str,
        temperature: float = 0.0,
        response_json: bool = False,
        max_tokens: int | None = None,
    ) -> str:
        last_err: Exception | None = None
        for model in self._models:
            try:
                content = self._complete_one(
                    model=model,
                    system=system,
                    user=user,
                    temperature=temperature,
                    response_json=response_json,
                    max_tokens=max_tokens,
                )
                self.last_model_used = model
                return content
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if _is_retryable_provider_error(exc):
                    logger.warning(
                        "Model %s failed (%s); trying next fallback if any",
                        model,
                        exc,
                    )
                    continue
                # Non-retryable on this model: still try fallbacks for rate limits only
                if _is_rate_limit(exc):
                    logger.warning("Rate limit on %s; trying next model", model)
                    continue
                logger.warning("Model %s error (trying next): %s", model, exc)
                continue
        raise RuntimeError(
            f"All LLM models failed ({self._models}): {last_err}"
        ) from last_err

    def _complete_one(
        self,
        *,
        model: str,
        system: str,
        user: str,
        temperature: float,
        response_json: bool,
        max_tokens: int | None,
    ) -> str:
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens or self._default_max_tokens,
        }
        ml = model.lower()
        # Only attach reasoning_effort when the host is known to accept it
        if self._reasoning_effort and any(
            x in ml for x in ("qwen", "hy3", "hunyuan", "gpt-oss", "glm")
        ):
            effort = self._reasoning_effort
            if "hy3" in ml or "hunyuan" in ml:
                if effort in {"none", "off", "false"}:
                    effort = "no_think"
            kwargs["reasoning_effort"] = effort

        # Prefer non-stream for Cerebras (fast + simple); stream for ModelScope quirks
        base = str(getattr(self._client, "base_url", "") or "")
        use_stream = "modelscope" in base.lower()

        supports_json_object = not any(
            x in ml for x in ("hy3", "hunyuan", "tencent-hunyuan")
        )
        if response_json and supports_json_object:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            if use_stream:
                kwargs["stream"] = True
                content = self._stream_content(kwargs)
            else:
                kwargs.pop("stream", None)
                response = self._client.chat.completions.create(**kwargs)
                if not response.choices:
                    raise ValueError(f"Empty choices from model {model}")
                content = (response.choices[0].message.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            stripped = False
            if "reasoning" in msg or "reasoning_effort" in msg:
                kwargs.pop("reasoning_effort", None)
                stripped = True
            if "response_format" in msg or "json_object" in msg:
                kwargs.pop("response_format", None)
                stripped = True
            if stripped:
                if use_stream or kwargs.get("stream"):
                    kwargs["stream"] = True
                    content = self._stream_content(kwargs)
                else:
                    kwargs.pop("stream", None)
                    response = self._client.chat.completions.create(**kwargs)
                    content = (response.choices[0].message.content or "").strip()
            else:
                raise

        content = (content or "").strip()
        if not content:
            raise ValueError(f"Empty content from model {model}")
        logger.info("LLM complete model=%s chars=%s", model, len(content))
        return content

    def _stream_content(self, kwargs: dict[str, Any]) -> str:
        """Accumulate assistant content from a chat completion stream."""
        stream = self._client.chat.completions.create(**kwargs)
        parts: list[str] = []
        for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            piece = getattr(delta, "content", None)
            if piece:
                parts.append(piece)
        return "".join(parts)

    def complete_with_tools(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        max_tokens: int | None = None,
        tool_choice: str | dict[str, Any] = "auto",
    ) -> Any:
        """One chat turn that may return tool_calls (uses dedicated tool model chain)."""
        last_err: Exception | None = None
        for model in self._tool_models:
            try:
                kwargs: dict[str, Any] = {
                    "model": model,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": tool_choice,
                    "temperature": temperature,
                    "max_tokens": max_tokens or self._default_max_tokens,
                }
                # Keep tool calls deterministic when possible
                if "qwen" in model.lower() and self._reasoning_effort:
                    kwargs["reasoning_effort"] = self._reasoning_effort
                try:
                    response = self._client.chat.completions.create(**kwargs)
                except Exception as exc:  # noqa: BLE001
                    msg = str(exc).lower()
                    if "reasoning" in msg:
                        kwargs.pop("reasoning_effort", None)
                        response = self._client.chat.completions.create(**kwargs)
                    else:
                        raise
                message = response.choices[0].message
                self.last_tool_model_used = model
                self.last_model_used = model
                return message
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if _is_rate_limit(exc) or _is_retryable_provider_error(exc):
                    logger.warning(
                        "Tool model %s failed (%s); trying next", model, exc
                    )
                    continue
                logger.warning("Tool model %s error: %s", model, exc)
                continue
        raise RuntimeError(
            f"All tool LLM models failed ({self._tool_models}): {last_err}"
        ) from last_err


def _is_rate_limit(exc: Exception) -> bool:
    s = str(exc).lower()
    return "429" in s or "rate limit" in s or "rate_limit" in s or "tokens per day" in s or "tpd" in s


def _is_retryable_provider_error(exc: Exception) -> bool:
    s = str(exc).lower()
    return _is_rate_limit(exc) or "503" in s or "502" in s or "timeout" in s or "overloaded" in s


def parse_json_response(text: str) -> dict[str, Any]:
    """Extract JSON object from model output (handles fences / preamble / truncation)."""
    text = text.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.I).strip()

    candidates: list[str] = [text]
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        candidates.insert(0, fence.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidates.append(text[start : end + 1])
    if start != -1:
        candidates.append(text[start:])

    last_err: Exception | None = None
    for cand in candidates:
        try:
            return json.loads(cand)
        except json.JSONDecodeError as exc:
            last_err = exc
            repaired = _repair_truncated_json(cand)
            if repaired is not None:
                return repaired
    raise ValueError(
        f"Could not parse JSON from LLM response: {text[:200]!r} ({last_err})"
    )


def _repair_truncated_json(text: str) -> dict[str, Any] | None:
    """Best-effort recovery when max_tokens cuts mid-JSON."""
    if "{" not in text:
        return None
    m = re.search(r'"answer"\s*:\s*"((?:\\.|[^"\\])*)"', text, re.DOTALL)
    answer = None
    if m:
        try:
            answer = json.loads(f'"{m.group(1)}"')
        except json.JSONDecodeError:
            answer = m.group(1)
    else:
        m2 = re.search(r'"answer"\s*:\s*"(.*)$', text, re.DOTALL)
        if m2:
            answer = m2.group(1).rstrip('"\\ \n\r\t,')

    findings = re.findall(r"FINDING-\d+", text, flags=re.I)
    findings = list(dict.fromkeys(f.upper() for f in findings))
    refs = re.findall(r'"(?:guide|cwe|owasp)[^"]*"', text, flags=re.I)
    ref_ids = [r.strip('"') for r in refs]

    if answer and len(answer.strip()) > 20:
        return {
            "answer": answer.strip(),
            "findings_referenced": findings,
            "reference_ids": ref_ids,
            "abstained": False,
        }
    return None


class _FakeToolMessage:
    def __init__(
        self,
        content: str | None = None,
        tool_calls: list[Any] | None = None,
    ) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _FakeToolCall:
    def __init__(self, id: str, name: str, arguments: str) -> None:
        self.id = id
        self.type = "function"
        self.function = type("F", (), {"name": name, "arguments": arguments})()


class FakeLLM:
    """Scripted LLM for unit tests (optional tool-call script)."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_script: list[Any] | None = None,
    ) -> None:
        self.responses = list(responses or [])
        # Each entry: either final content str, or list of (name, args_dict) tool calls
        self.tool_script = list(tool_script or [])
        self.calls: list[dict[str, Any]] = []
        self.tool_calls_log: list[Any] = []
        self.last_model_used: str | None = "fake"
        self.last_tool_model_used: str | None = "fake-tool"
        self.models = ["fake"]

    def complete(
        self,
        *,
        system: str,
        user: str,
        temperature: float = 0.0,
        response_json: bool = False,
        max_tokens: int | None = None,
    ) -> str:
        self.calls.append(
            {
                "system": system,
                "user": user,
                "temperature": temperature,
                "response_json": response_json,
                "max_tokens": max_tokens,
            }
        )
        sys_l = system.lower()
        user_l = (user or "").lower()
        # Scope gate ALWAYS handled here so scripted answer responses are not consumed
        if response_json and (
            "scope gate" in sys_l
            or "in-scope for a security scan" in sys_l
            or ("related" in sys_l and "off-topic" in sys_l)
        ):
            off = any(
                x in user_l
                for x in (
                    "weather",
                    "joke",
                    "poem",
                    "recipe",
                    "president",
                    "horoscope",
                    "netflix",
                    "bitcoin price",
                    "capital of",
                )
            )
            q_part = user_l.split("question:", 1)[-1].split("sample endpoints", 1)[0]
            securityish = bool(
                re.search(
                    r"finding|vulnerab|cwe|idor|bola|ssrf|sql|jwt|xss|rce|"
                    r"severity|critical|endpoint|remediat|fix|scan|auth|"
                    r"password|rate limit|access control|privilege|account",
                    q_part,
                )
            )
            chitchat = bool(
                re.search(r"\b(hi|hello|hey|thanks|thank you)\b", q_part)
            ) and not securityish
            related = (not off and not chitchat) and (securityish or len(q_part.strip()) > 40)
            return json.dumps(
                {
                    "related": bool(related),
                    "confidence": 0.9,
                    "reason": "fake-scope-gate",
                }
            )
        if self.responses:
            return self.responses.pop(0)
        # Semantic planner: return low-confidence empty plan so tests use rules
        if response_json and "query planner" in sys_l:
            return json.dumps(
                {
                    "intent": "general",
                    "answer_mode": None,
                    "include_severities": [],
                    "cwe_ids": [],
                    "confidence": 0.0,
                    "rationale": "fake-llm-skip",
                }
            )
        if response_json and (
            "classify the user question" in sys_l
            or ("intent" in sys_l and "query planner" not in sys_l and "findings" not in sys_l)
        ):
            return json.dumps(
                {
                    "intent": "summary",
                    "severity": None,
                    "cwe_id": None,
                    "owasp": None,
                    "endpoint": None,
                    "finding_id": None,
                    "keywords": [],
                }
            )
        return json.dumps(
            {
                "answer": "Based on the provided findings context only.",
                "findings_referenced": [],
                "reference_ids": [],
                "abstained": False,
            }
        )

    def complete_with_tools(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        max_tokens: int | None = None,
        tool_choice: str | dict[str, Any] = "auto",
    ) -> Any:
        self.tool_calls_log.append({"messages": messages, "tools": [t.get("function", {}).get("name") for t in tools]})
        if self.tool_script:
            step = self.tool_script.pop(0)
            if isinstance(step, str):
                return _FakeToolMessage(content=step)
            # list of (name, args)
            calls = []
            for i, item in enumerate(step):
                name, args = item[0], item[1]
                calls.append(
                    _FakeToolCall(
                        id=f"call_{i}",
                        name=name,
                        arguments=json.dumps(args),
                    )
                )
            return _FakeToolMessage(content=None, tool_calls=calls)
        # Default: no tools, final JSON answer
        return _FakeToolMessage(
            content=json.dumps(
                {
                    "answer": "Tool-agent answer from findings only.",
                    "findings_referenced": [],
                    "reference_ids": [],
                    "abstained": False,
                }
            )
        )
