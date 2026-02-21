"""
Base connector class for all API integrations.

All connectors inherit from this and implement the abstract methods.
Community contributors: Create a new file in the appropriate folder
and implement these methods for your system.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional
from dataclasses import dataclass
from enum import Enum


class ConnectorStatus(Enum):
    """Connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"


@dataclass
class ConnectionConfig:
    """Base configuration for connectors."""
    base_url: str
    verify_ssl: bool = True
    timeout: int = 30
    max_retries: int = 3


@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: str  # "api_key", "basic", "oauth2", "token"
    credentials: Dict[str, str]  # {"api_key": "xxx"} or {"username": "x", "password": "y"}


class BaseConnector(ABC):
    """
    Abstract base class for all connectors.
    
    Implement this class to add support for a new system.
    
    Example:
        class MySystemConnector(BaseConnector):
            name = "mysystem"
            vendor = "MyVendor"
            
            def connect(self) -> bool:
                # Your connection logic
                pass
    """
    
    # Override these in subclasses
    name: str = "base"
    vendor: str = "Unknown"
    description: str = "Base connector"
    auth_types: List[str] = ["api_key"]  # Supported auth methods
    
    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ):
        self.connection = connection
        self.auth = auth
        self.status = ConnectorStatus.DISCONNECTED
        self._client: Any = None
    
    @abstractmethod
    def connect(self) -> bool:
        """
        Establish connection to the system.
        
        Returns:
            True if connection successful
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close connection and cleanup."""
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test if connection is valid.
        
        Returns:
            True if connection works
        """
        pass
    
    @abstractmethod
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """
        Get current rate limit status.
        
        Returns:
            Dict with remaining calls, reset time, etc.
        """
        pass
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
