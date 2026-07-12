"""Application configuration via environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Embeddings (ModelScope)
    embedding_base_url: str = "https://api-inference.modelscope.ai/v1"
    modelscope_api_key: str = ""
    embedding_model: str = "Qwen/Qwen3-Embedding-8B"

    # LLM (OpenAI-compatible) — default Cerebras Gemma 4
    llm_base_url: str = "https://api.cerebras.ai/v1"
    groq_api_key: str = ""  # legacy fallback
    llm_api_key: str = ""  # preferred: LLM_API_KEY (Cerebras csk-… / etc.)
    llm_model: str = "gemma-4-31b"
    llm_fallback_models: str = ""
    llm_reasoning_effort: str = "none"
    llm_max_tokens: int = 1200

    # Tool-calling cascade (optional; default off)
    tool_llm_model: str = "gemma-4-31b"
    tool_llm_fallback_models: str = ""
    use_tool_agent: bool = False
    tool_agent_max_rounds: int = 3

    # V2 semantic planner + dynamic synthesis
    use_semantic_planner: bool = True
    planner_model: str = ""  # empty = llm_model
    use_dynamic_synthesis: bool = True
    # Scope gate LLM off by default — rules + planner in_scope handle product boundary
    use_llm_scope_gate: bool = False
    citation_gate_strict: bool = True
    citation_regen_on_fail: bool = True

    # Storage
    data_dir: Path = Path("./data")
    sqlite_path: Path = Path("./data/app.db")
    chroma_path: Path = Path("./data/chroma")
    knowledge_dir: Path = Path("./data/knowledge")

    # Retrieval defaults (RRF light path; CE optional via env)
    default_top_k_knowledge: int = 6
    default_top_k_findings_semantic: int = 12
    bm25_top_k: int = 40
    rrf_k: int = 60
    rerank_mode: str = "light"
    cross_encoder_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    cross_encoder_enabled: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    @property
    def embedding_api_key(self) -> str:
        return self.modelscope_api_key

    def resolve_llm_api_key(self) -> str:
        # Prefer LLM_API_KEY, then ModelScope, then legacy Groq
        return (
            (self.llm_api_key or "").strip()
            or (self.modelscope_api_key or "").strip()
            or (self.groq_api_key or "").strip()
        )

    def llm_model_chain(self) -> list[str]:
        models = [self.llm_model.strip()] if self.llm_model.strip() else []
        for part in (self.llm_fallback_models or "").split(","):
            m = part.strip()
            if m and m not in models:
                models.append(m)
        return models or ["gemma-4-31b"]

    def tool_llm_model_chain(self) -> list[str]:
        models = [self.tool_llm_model.strip()] if self.tool_llm_model.strip() else []
        for part in (self.tool_llm_fallback_models or "").split(","):
            m = part.strip()
            if m and m not in models:
                models.append(m)
        return models or self.llm_model_chain()

    def planner_model_id(self) -> str:
        return (self.planner_model or self.llm_model or "gemma-4-31b").strip()


@lru_cache
def get_settings() -> Settings:
    return Settings()
