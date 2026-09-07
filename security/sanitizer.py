"""Input sanitization utilities to prevent injection attacks."""
import re
from typing import Any


class Sanitizer:
    """Input sanitization for security."""
    
    # Patterns for detecting malicious input (defused without breaking punctuation/markdown)
    SQL_INJECTION_PATTERNS = [
        r"(\b(UNION\s+SELECT|DROP\s+TABLE|ALTER\s+TABLE|EXEC\s+xp_)\b)",
        r"(\/\*.*?\*\/)",
    ]
    
    # Only defuse true shell execution subshells and traversal, never normal punctuation
    PATH_TRAVERSAL_PATTERN = r"(\.\./)"
    
    HTML_SCRIPT_PATTERN = r"<script[^>]*>.*?</script>"
    HTML_TAG_PATTERN = r"<[^>]+>"
    
    @staticmethod
    def clean_artifacts(value: str) -> str:
        """Helper to reverse corrupted bracket artifacts from earlier sanitization."""
        if not isinstance(value, str):
            return value
        cleaned = value
        # Clean double-wrapped brackets and parentheses
        cleaned = re.sub(r"\[\s*\(\s*\]\s*", "(", cleaned)
        cleaned = re.sub(r"\s*\[\s*\)\s*\]", ")", cleaned)
        cleaned = cleaned.replace("[()]", "()")
        cleaned = cleaned.replace("[()s()]", "(s)")
        cleaned = cleaned.replace("[()s]", "(s)")
        cleaned = cleaned.replace("[&]", "&")
        cleaned = cleaned.replace("[[]", "[")
        cleaned = cleaned.replace("[]]", "]")
        cleaned = re.sub(r"\[DEFUSED_([^\]]+)\]", r"\1", cleaned)
        cleaned = cleaned.replace("[dot-dot-slash]", "../")
        cleaned = cleaned.replace("[home-slash]", "~/")
        return cleaned

    @staticmethod
    def sanitize_string(value: str, max_length: int = 2000) -> str:
        """
        Sanitize string input safely without destroying normal text,
        parentheses, brackets, or markdown formatting.
        """
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Clean any preexisting bracket artifacts
        value = Sanitizer.clean_artifacts(value)
        
        # Check length
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        
        # Strip null bytes
        value = value.replace("\x00", "")
        
        # Remove HTML/script tags
        value = re.sub(Sanitizer.HTML_SCRIPT_PATTERN, "", value, flags=re.IGNORECASE)
        value = re.sub(Sanitizer.HTML_TAG_PATTERN, "", value)
        
        # Safely defuse destructive SQL patterns
        for pattern in Sanitizer.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                value = re.sub(pattern, r"[DEFUSED_\1]", value, flags=re.IGNORECASE)
        
        # Defuse path traversal
        value = re.sub(Sanitizer.PATH_TRAVERSAL_PATTERN, "[dot-dot-slash]", value)
        
        return value.strip()
    
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