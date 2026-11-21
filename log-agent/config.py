"""LOGN Agent Configuration

Loads configuration settings from environment variables with safe defaults.
Does not contain or commit hardcoded credentials or tokens.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    """Agent runtime configuration settings."""

    # Backend API settings
    backend_url: str = field(
        default_factory=lambda: os.getenv("LOGN_BACKEND_URL", "http://localhost:5000").rstrip("/")
    )
    ingest_endpoint: str = field(
        default_factory=lambda: os.getenv("LOGN_INGEST_ENDPOINT", "/api/v1/logs/ingest")
    )
    heartbeat_endpoint: str = field(
        default_factory=lambda: os.getenv("LOGN_HEARTBEAT_ENDPOINT", "/api/v1/collectors/heartbeat")
    )
    api_key: str = field(
        default_factory=lambda: os.getenv("LOGN_API_KEY", "")
    )

    # Identification
    source_id: str = field(
        default_factory=lambda: os.getenv("LOGN_SOURCE_ID", socket.gethostname())
    )
    collector_id: str = field(
        default_factory=lambda: os.getenv("LOGN_COLLECTOR_ID", f"{socket.gethostname()}-agent")
    )

    # Transmission & Queue Settings
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("LOGN_BATCH_SIZE", "50"))
    )
    request_timeout: float = field(
        default_factory=lambda: float(os.getenv("LOGN_REQUEST_TIMEOUT", "10.0"))
    )
    max_retries: int = field(
        default_factory=lambda: int(os.getenv("LOGN_MAX_RETRIES", "5"))
    )
    db_path: str = field(
        default_factory=lambda: os.getenv("LOGN_DB_PATH", "offline_queue.db")
    )
    heartbeat_interval: float = field(
        default_factory=lambda: float(os.getenv("LOGN_HEARTBEAT_INTERVAL", "30.0"))
    )

    @property
    def ingest_url(self) -> str:
        """Fully resolved ingest URL."""
        return f"{self.backend_url}{self.ingest_endpoint}"

    @property
    def heartbeat_url(self) -> str:
        """Fully resolved heartbeat URL."""
        return f"{self.backend_url}{self.heartbeat_endpoint}"


def load_config() -> AgentConfig:
    """Load configuration from environment variables."""
    return AgentConfig()
