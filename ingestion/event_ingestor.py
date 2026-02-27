"""Event ingestor with strict validation and sanitization."""
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict
from datetime import datetime
from ingestion.log_parser import LogParser
from security.sanitizer import Sanitizer
from utils.logger import get_logger

logger = get_logger(__name__)


class AuthLogEvent(BaseModel):
    """Validated auth log event."""
    
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    
    log_type: str = Field(default="auth", description="Log type")
    timestamp: str = Field(..., max_length=50, description="Log timestamp")
    hostname: str = Field(..., max_length=100, description="Server hostname")
    process: str = Field(..., max_length=50, description="Process name")
    username: Optional[str] = Field(None, max_length=100, description="Username")
    source_ip: Optional[str] = Field(None, max_length=45, description="Source IP")
    success: bool = Field(..., description="Authentication success")
    message: str = Field(..., max_length=500, description="Log message")
    
    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP address format."""
        if v is None:
            return v
        # Basic IP validation
        import re
        if not re.match(r'^[\d\.]+$', v):
            raise ValueError("Invalid IP address format")
        return v


class NginxLogEvent(BaseModel):
    """Validated nginx log event."""
    
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    
    log_type: str = Field(default="nginx", description="Log type")
    client_ip: str = Field(..., max_length=45, description="Client IP")
    timestamp: str = Field(..., max_length=50, description="Request timestamp")
    method: str = Field(..., max_length=10, description="HTTP method")
    path: str = Field(..., max_length=500, description="Request path")
    protocol: str = Field(..., max_length=20, description="HTTP protocol")
    status: int = Field(..., ge=0, le=999, description="HTTP status code")
    size: int = Field(..., ge=0, description="Response size")
    referrer: str = Field(default="", max_length=500, description="Referrer")
    user_agent: str = Field(default="", max_length=500, description="User agent")
    
    @field_validator("client_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        import re
        if not re.match(r'^[\d\.]+$', v):
            raise ValueError("Invalid IP address format")
        return v


class DnsLogEvent(BaseModel):
    """Validated DNS log event."""
    
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    
    log_type: str = Field(default="dns", description="Log type")
    timestamp: str = Field(..., max_length=50, description="Query timestamp")
    client_ip: str = Field(..., max_length=45, description="Client IP")
    domain: str = Field(..., max_length=255, description="Queried domain")
    query: str = Field(..., max_length=255, description="DNS query")
    query_type: str = Field(..., max_length=10, description="Query type")
    
    @field_validator("client_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        import re
        if not re.match(r'^[\d\.]+$', v):
            raise ValueError("Invalid IP address format")
        return v
    
    @field_validator("domain", "query")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Basic domain validation."""
        if not v or len(v) > 255:
            raise ValueError("Invalid domain")
        return v


class EventIngestor:
    """Ingest and validate log events."""
    
    @staticmethod
    def validate_auth_log(parsed_log: Dict[str, Any]) -> AuthLogEvent:
        """
        Validate auth log against strict schema.
        OWASP A03: Strip parser-internal fields before passing to Pydantic
        to prevent injection via unexpected keys.
        """
        # Strip internal / unknown fields before strict validation (OWASP A03)
        _INTERNAL_KEYS = {"raw", "log_line", "_parser_meta"}
        parsed_log = {k: v for k, v in parsed_log.items() if k not in _INTERNAL_KEYS}

        sanitized = {}
        for key, value in parsed_log.items():
            if isinstance(value, str):
                try:
                    sanitized[key] = Sanitizer.sanitize_string(value, max_length=500)
                except ValueError as e:
                    logger.error("sanitization_failed", field=key, error=str(e))
                    raise ValueError(f"Invalid input in field '{key}': {str(e)}")
            else:
                sanitized[key] = value
        return AuthLogEvent(**sanitized)
    
    @staticmethod
    def validate_nginx_log(parsed_log: Dict[str, Any]) -> NginxLogEvent:
        """
        Validate nginx log against strict schema.
        OWASP A03: Strip parser-internal fields before passing to Pydantic.
        """
        _INTERNAL_KEYS = {"raw", "log_line", "_parser_meta"}
        parsed_log = {k: v for k, v in parsed_log.items() if k not in _INTERNAL_KEYS}

        sanitized = {}
        for key, value in parsed_log.items():
            if isinstance(value, str):
                try:
                    sanitized[key] = Sanitizer.sanitize_string(value, max_length=500)
                except ValueError as e:
                    logger.error("sanitization_failed", field=key, error=str(e))
                    raise ValueError(f"Invalid input in field '{key}': {str(e)}")
            else:
                sanitized[key] = value
        return NginxLogEvent(**sanitized)
    
    @staticmethod
    def validate_dns_log(parsed_log: Dict[str, Any]) -> DnsLogEvent:
        """
        Validate DNS log against strict schema.
        OWASP A03: Strip parser-internal fields before passing to Pydantic.
        """
        _INTERNAL_KEYS = {"raw", "log_line", "_parser_meta"}
        parsed_log = {k: v for k, v in parsed_log.items() if k not in _INTERNAL_KEYS}

        sanitized = {}
        for key, value in parsed_log.items():
            if isinstance(value, str):
                try:
                    sanitized[key] = Sanitizer.sanitize_string(value, max_length=500)
                except ValueError as e:
                    logger.error("sanitization_failed", field=key, error=str(e))
                    raise ValueError(f"Invalid input in field '{key}': {str(e)}")
            else:
                sanitized[key] = value
        return DnsLogEvent(**sanitized)
    
    @classmethod
    def ingest(cls, raw_log: str, log_type: Optional[str] = None) -> Optional[BaseModel]:
        """
        Ingest and validate a raw log.
        
        Args:
            raw_log: Raw log string
            log_type: Optional log type hint
            
        Returns:
            Validated log event or None if parsing/validation fails
            
        Raises:
            ValueError: If log is malformed or validation fails
        """
        # Parse log
        parsed = LogParser.parse(raw_log, log_type=log_type)
        
        if not parsed:
            raise ValueError("Failed to parse log - malformed or unsupported format")
        
        # Determine log type
        detected_type = parsed.get("log_type")
        
        # Validate based on type
        try:
            if detected_type == "auth":
                validated = cls.validate_auth_log(parsed)
            elif detected_type == "nginx":
                validated = cls.validate_nginx_log(parsed)
            elif detected_type == "dns":
                validated = cls.validate_dns_log(parsed)
            else:
                raise ValueError(f"Unknown log type: {detected_type}")
            
            logger.info("log_ingested", log_type=detected_type)
            return validated
            
        except Exception as e:
            logger.error("log_validation_failed", error=str(e), log_type=detected_type)
            raise ValueError(f"Log validation failed: {str(e)}")
