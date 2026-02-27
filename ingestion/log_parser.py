"""Log parser for auth, nginx, and DNS logs."""
import re
from typing import Dict, Any, Optional
from datetime import datetime
from utils.logger import get_logger

logger = get_logger(__name__)


class LogParser:
    """Parse structured logs from different sources."""
    
    # Auth log patterns (SSH/login style)
    AUTH_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\w+)(\[\d+\])?: '
        r'(?P<message>.*)'
    )
    
    # SSH specific patterns
    SSH_FAILED = re.compile(r'Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>[\d\.]+)')
    SSH_ACCEPTED = re.compile(r'Accepted \w+ for (?P<username>\S+) from (?P<ip>[\d\.]+)')
    
    # Nginx access log pattern (common log format)
    NGINX_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )
    
    # DNS query log pattern
    DNS_PATTERN = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'client\s+(?P<client_ip>[\d\.]+)#\d+\s+'
        r'\((?P<domain>[^\)]+)\):\s+'
        r'query:\s+(?P<query>[^\s]+)\s+'
        r'IN\s+(?P<query_type>\w+)'
    )
    
    @classmethod
    def detect_log_type(cls, raw_log: str) -> Optional[str]:
        """
        Auto-detect log type from raw log line.
        
        Args:
            raw_log: Raw log string
            
        Returns:
            Log type ("auth", "nginx", "dns") or None
        """
        if cls.NGINX_PATTERN.match(raw_log):
            return "nginx"
        elif cls.DNS_PATTERN.search(raw_log):
            return "dns"
        elif cls.AUTH_PATTERN.match(raw_log):
            return "auth"
        return None
    
    @classmethod
    def parse_auth_log(cls, raw_log: str) -> Optional[Dict[str, Any]]:
        """
        Parse auth/SSH log.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            Parsed log dict or None if parsing fails
        """
        try:
            match = cls.AUTH_PATTERN.match(raw_log)
            if not match:
                return None
            
            groups = match.groupdict()
            message = groups.get("message", "")
            
            # Try to extract username and IP from message
            username = None
            source_ip = None
            success = False
            
            failed_match = cls.SSH_FAILED.search(message)
            if failed_match:
                username = failed_match.group("username")
                source_ip = failed_match.group("ip")
                success = False
            
            accepted_match = cls.SSH_ACCEPTED.search(message)
            if accepted_match:
                username = accepted_match.group("username")
                source_ip = accepted_match.group("ip")
                success = True
            
            return {
                "log_type": "auth",
                "timestamp": groups.get("timestamp"),
                "hostname": groups.get("hostname"),
                "process": groups.get("process"),
                "username": username,
                "source_ip": source_ip,
                "success": success,
                "message": message,
                "raw": raw_log
            }
            
        except Exception as e:
            logger.error("auth_log_parse_failed", error=str(e), raw_log=raw_log[:100])
            return None
    
    @classmethod
    def parse_nginx_log(cls, raw_log: str) -> Optional[Dict[str, Any]]:
        """
        Parse nginx access log.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            Parsed log dict or None if parsing fails
        """
        try:
            match = cls.NGINX_PATTERN.match(raw_log)
            if not match:
                return None
            
            groups = match.groupdict()
            
            return {
                "log_type": "nginx",
                "client_ip": groups.get("ip"),
                "timestamp": groups.get("timestamp"),
                "method": groups.get("method"),
                "path": groups.get("path"),
                "protocol": groups.get("protocol"),
                "status": int(groups.get("status", 0)),
                "size": int(groups.get("size", 0)),
                "referrer": groups.get("referrer"),
                "user_agent": groups.get("user_agent"),
                "raw": raw_log
            }
            
        except Exception as e:
            logger.error("nginx_log_parse_failed", error=str(e), raw_log=raw_log[:100])
            return None
    
    @classmethod
    def parse_dns_log(cls, raw_log: str) -> Optional[Dict[str, Any]]:
        """
        Parse DNS query log.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            Parsed log dict or None if parsing fails
        """
        try:
            match = cls.DNS_PATTERN.search(raw_log)
            if not match:
                return None
            
            groups = match.groupdict()
            
            return {
                "log_type": "dns",
                "timestamp": groups.get("timestamp"),
                "client_ip": groups.get("client_ip"),
                "domain": groups.get("domain"),
                "query": groups.get("query"),
                "query_type": groups.get("query_type"),
                "raw": raw_log
            }
            
        except Exception as e:
            logger.error("dns_log_parse_failed", error=str(e), raw_log=raw_log[:100])
            return None
    
    @classmethod
    def parse(cls, raw_log: str, log_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Parse log with optional type hint.
        
        Args:
            raw_log: Raw log string
            log_type: Optional log type hint ("auth", "nginx", "dns")
            
        Returns:
            Parsed log dict or None
        """
        if not raw_log or not raw_log.strip():
            return None
        
        # Auto-detect if not specified
        if not log_type:
            log_type = cls.detect_log_type(raw_log)
        
        if log_type == "auth":
            return cls.parse_auth_log(raw_log)
        elif log_type == "nginx":
            return cls.parse_nginx_log(raw_log)
        elif log_type == "dns":
            return cls.parse_dns_log(raw_log)
        
        logger.warning("unknown_log_type", log_type=log_type, raw_log=raw_log[:100])
        return None
