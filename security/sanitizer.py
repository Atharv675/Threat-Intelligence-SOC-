"""Input sanitization utilities to prevent injection attacks."""
import re
from typing import Any


class Sanitizer:
    """Input sanitization for security."""
    
    # Patterns for detecting malicious input
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|;|\/\*|\*\/)",
        r"(\bOR\b.*=.*)",
        r"(\bAND\b.*=.*)",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$(){}[\]<>]",
        r"(\.\./)",
        r"(~\/)",
    ]
    
    HTML_SCRIPT_PATTERN = r"<script[^>]*>.*?</script>"
    HTML_TAG_PATTERN = r"<[^>]+>"
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input by defusing patterns rather than crashing.
        
        This allows the SOC tool to collect real threat data (which often 
        contains these characters) without compromising system stability.
        """
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Check length
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        
        # Defuse SQL injection patterns (e.g., SELECT -> [DEFUSED_SELECT])
        for pattern in Sanitizer.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                value = re.sub(pattern, r"[DEFUSED_\1]", value, flags=re.IGNORECASE)
        
        # Defuse command injection patterns (e.g., ; -> [;])
        # This keeps the data readable but makes it non-executable
        for pattern in Sanitizer.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                # We wrap dangerous characters in brackets
                value = re.sub(r"([;&|`$(){}[\]<>])", r"[\1]", value)
                # We also handle path traversal patterns
                value = value.replace("../", "[dot-dot-slash]")
                value = value.replace("~/", "[home-slash]")
        
        # Remove HTML/script tags
        sanitized = re.sub(Sanitizer.HTML_SCRIPT_PATTERN, "", value, flags=re.IGNORECASE)
        sanitized = re.sub(Sanitizer.HTML_TAG_PATTERN, "", sanitized)
        
        # Remove null bytes
        sanitized = sanitized.replace("\x00", "")
        
        return sanitized.strip()
    
    @staticmethod
    def sanitize_dict(data: dict, max_depth: int = 5, current_depth: int = 0) -> dict:
        """Recursively sanitize dictionary values."""
        if current_depth >= max_depth:
            raise ValueError("Maximum nesting depth exceeded")
        
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = Sanitizer.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = Sanitizer.sanitize_dict(value, max_depth, current_depth + 1)
            elif isinstance(value, list):
                sanitized[key] = [
                    Sanitizer.sanitize_string(item) if isinstance(item, str)
                    else Sanitizer.sanitize_dict(item, max_depth, current_depth + 1) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized