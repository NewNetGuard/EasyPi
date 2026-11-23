"""
Environment Validation Module

Validates environment configuration at application startup.
Checks for required variables, correct formats, and security best practices.
"""

import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from pydantic import ValidationError


class ValidationLevel(str, Enum):
    """Validation message severity levels."""
    ERROR = "error"      # Critical - app should not start
    WARNING = "warning"  # Non-critical but should be fixed
    INFO = "info"        # Informational message


@dataclass
class ValidationMessage:
    """A single validation message."""
    level: ValidationLevel
    variable: str
    message: str
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of environment validation."""
    valid: bool = True
    messages: list[ValidationMessage] = field(default_factory=list)
    
    def add_error(self, variable: str, message: str, suggestion: Optional[str] = None):
        """Add an error message."""
        self.valid = False
        self.messages.append(ValidationMessage(
            level=ValidationLevel.ERROR,
            variable=variable,
            message=message,
            suggestion=suggestion
        ))
    
    def add_warning(self, variable: str, message: str, suggestion: Optional[str] = None):
        """Add a warning message."""
        self.messages.append(ValidationMessage(
            level=ValidationLevel.WARNING,
            variable=variable,
            message=message,
            suggestion=suggestion
        ))
    
    def add_info(self, variable: str, message: str, suggestion: Optional[str] = None):
        """Add an info message."""
        self.messages.append(ValidationMessage(
            level=ValidationLevel.INFO,
            variable=variable,
            message=message,
            suggestion=suggestion
        ))
    
    @property
    def errors(self) -> list[ValidationMessage]:
        """Get all error messages."""
        return [m for m in self.messages if m.level == ValidationLevel.ERROR]
    
    @property
    def warnings(self) -> list[ValidationMessage]:
        """Get all warning messages."""
        return [m for m in self.messages if m.level == ValidationLevel.WARNING]
    
    @property
    def infos(self) -> list[ValidationMessage]:
        """Get all info messages."""
        return [m for m in self.messages if m.level == ValidationLevel.INFO]


class EnvironmentValidator:
    """
    Validates environment configuration at startup.
    
    Checks:
    - Required variables are present
    - Variables have correct format
    - Security best practices are followed
    - Paths exist and are accessible
    """
    
    # Required variables that must be set
    REQUIRED_VARS = [
        "DATABASE_URL",
    ]
    
    # Variables that should be set in production
    PRODUCTION_REQUIRED = [
        "SECRET_KEY",
    ]
    
    # Variables with format validation
    FORMAT_VALIDATORS: dict[str, tuple[str, Callable[[str], bool]]] = {
        "DATABASE_URL": (
            "Database URL format",
            lambda v: v.startswith(("sqlite", "postgresql", "mysql"))
        ),
        "LOG_LEVEL": (
            "Valid log level",
            lambda v: v.lower() in ("debug", "info", "warning", "error", "critical")
        ),
        "ENV": (
            "Valid environment",
            lambda v: v.lower() in ("development", "dev", "production", "prod", "staging", "test")
        ),
    }
    
    # Security sensitive variables
    SECURITY_VARS = {
        "SECRET_KEY": {
            "min_length": 32,
            "pattern": None,
            "message": "Should be at least 32 characters"
        },
        "NETPROTECTION_PASSWORD": {
            "min_length": 8,
            "pattern": None,
            "message": "Should be at least 8 characters"
        },
    }
    
    def __init__(self, env_path: Optional[Path] = None):
        """
        Initialize validator.
        
        Args:
            env_path: Path to .env file. If None, uses default location.
        """
        self.env_path = env_path or self._find_env_file()
        self.result = ValidationResult()
        self._env_vars: dict[str, str] = {}
    
    def _find_env_file(self) -> Path:
        """Find the .env file."""
        from app.core.paths import get_easypi_root, get_backend_dir
        # Try common locations
        locations = [
            get_easypi_root() / ".env",  # Project root
            get_backend_dir() / ".env",  # Backend root
            Path.cwd() / ".env",
        ]
        
        for loc in locations:
            if loc.exists():
                return loc
        
        return locations[0]  # Return default even if not exists
    
    def _load_env_file(self) -> dict[str, str]:
        """Load and parse .env file."""
        env_vars = {}
        
        if not self.env_path.exists():
            return env_vars
        
        try:
            with open(self.env_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse KEY=value
                    if '=' not in line:
                        self.result.add_warning(
                            f"Line {line_num}",
                            f"Invalid line format: '{line[:50]}...'",
                            "Use KEY=value format"
                        )
                        continue
                    
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    
                    env_vars[key] = value
        
        except Exception as e:
            self.result.add_error(
                ".env",
                f"Failed to read .env file: {e}",
                "Check file permissions and encoding"
            )
        
        return env_vars
    
    def validate(self) -> ValidationResult:
        """
        Run all validation checks.
        
        Returns:
            ValidationResult with all messages
        """
        self.result = ValidationResult()
        
        # Check .env file exists
        self._check_env_file_exists()
        
        # Load env vars (from file + environment)
        self._env_vars = self._load_env_file()
        
        # Also include system environment variables
        for key in os.environ:
            if key not in self._env_vars:
                self._env_vars[key] = os.environ[key]
        
        # Run checks
        self._check_required_vars()
        self._check_production_vars()
        self._check_format_validators()
        self._check_security_vars()
        self._check_paths()
        self._check_urls()
        self._check_deprecated_vars()
        
        return self.result
    
    def _check_env_file_exists(self):
        """Check if .env file exists."""
        if not self.env_path.exists():
            self.result.add_warning(
                ".env",
                f".env file not found at {self.env_path}",
                "Create .env file from .env.example or set environment variables directly"
            )
    
    def _check_required_vars(self):
        """Check that required variables are present."""
        for var in self.REQUIRED_VARS:
            if var not in self._env_vars or not self._env_vars[var]:
                self.result.add_error(
                    var,
                    f"Required variable {var} is not set",
                    f"Add {var}=<value> to your .env file"
                )
    
    def _check_production_vars(self):
        """Check production-required variables."""
        env = self._env_vars.get("ENV", "production").lower()
        is_production = env in ("production", "prod")
        
        if is_production:
            for var in self.PRODUCTION_REQUIRED:
                if var not in self._env_vars or not self._env_vars[var]:
                    self.result.add_error(
                        var,
                        f"Variable {var} is required in production",
                        f"Set {var} in your .env file"
                    )
                elif var == "SECRET_KEY":
                    # Check if using default secret
                    value = self._env_vars[var]
                    if len(value) < 32:
                        self.result.add_error(
                            var,
                            "SECRET_KEY is too short for production",
                            'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
                        )
    
    def _check_format_validators(self):
        """Check variable formats."""
        for var, (description, validator) in self.FORMAT_VALIDATORS.items():
            if var in self._env_vars and self._env_vars[var]:
                value = self._env_vars[var]
                try:
                    if not validator(value):
                        self.result.add_warning(
                            var,
                            f"Invalid format for {var}: '{value}'",
                            f"Expected: {description}"
                        )
                except Exception:
                    self.result.add_warning(
                        var,
                        f"Could not validate {var}",
                        f"Expected: {description}"
                    )
    
    def _check_security_vars(self):
        """Check security-sensitive variables."""
        env = self._env_vars.get("ENV", "production").lower()
        is_production = env in ("production", "prod")
        
        for var, rules in self.SECURITY_VARS.items():
            if var in self._env_vars and self._env_vars[var]:
                value = self._env_vars[var]
                
                # Check minimum length
                min_len = rules.get("min_length", 0)
                if len(value) < min_len:
                    level = "error" if is_production else "warning"
                    msg = ValidationMessage(
                        level=ValidationLevel.ERROR if is_production else ValidationLevel.WARNING,
                        variable=var,
                        message=f"{var} is too short ({len(value)} < {min_len} characters)",
                        suggestion=rules.get("message")
                    )
                    if level == "error":
                        self.result.valid = False
                    self.result.messages.append(msg)
                
                # Check pattern if defined
                pattern = rules.get("pattern")
                if pattern and not re.match(pattern, value):
                    self.result.add_warning(
                        var,
                        f"{var} does not match expected pattern",
                        rules.get("message")
                    )
    
    def _check_paths(self):
        """Check that configured paths exist or are creatable."""
        path_vars = ["SCRIPTS_ROOT", "RUNNER_PATH", "TASK_LOG_DIR", "LOG_DIR"]
        
        for var in path_vars:
            if var in self._env_vars and self._env_vars[var]:
                path = Path(self._env_vars[var])
                
                if var.endswith("_PATH"):
                    # File path - check parent directory
                    parent = path.parent
                    if not parent.exists():
                        self.result.add_info(
                            var,
                            f"Parent directory for {var} does not exist: {parent}",
                            "Directory will be created if possible"
                        )
                else:
                    # Directory path
                    if not path.exists():
                        self.result.add_info(
                            var,
                            f"Directory {var} does not exist: {path}",
                            "Directory will be created if possible"
                        )
    
    def _check_urls(self):
        """Check URL format for URL variables."""
        url_vars = ["NETPROTECTION_URL", "OLLAMA_URL"]
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        
        for var in url_vars:
            if var in self._env_vars and self._env_vars[var]:
                value = self._env_vars[var]
                if not url_pattern.match(value):
                    self.result.add_warning(
                        var,
                        f"Invalid URL format for {var}: '{value}'",
                        "Use format: http://host:port or https://domain.com"
                    )
    
    def _check_deprecated_vars(self):
        """Check for deprecated variables."""
        deprecated = {
            # "OLD_VAR": "NEW_VAR",  # Example
        }
        
        for old_var, new_var in deprecated.items():
            if old_var in self._env_vars:
                self.result.add_warning(
                    old_var,
                    f"{old_var} is deprecated",
                    f"Use {new_var} instead"
                )
    
    def print_report(self, exit_on_error: bool = True):
        """
        Print validation report to console.
        
        Args:
            exit_on_error: If True, exit with code 1 on validation errors
        """
        if not self.result.messages:
            print("✅ Environment validation passed")
            return
        
        # Group by level
        errors = self.result.errors
        warns = self.result.warnings
        infos = self.result.infos
        
        # Print errors
        if errors:
            print("\n❌ ERRORS (must fix before starting):")
            print("-" * 50)
            for msg in errors:
                print(f"  • {msg.variable}: {msg.message}")
                if msg.suggestion:
                    print(f"    💡 {msg.suggestion}")
        
        # Print warnings
        if warns:
            print("\n⚠️  WARNINGS (should fix):")
            print("-" * 50)
            for msg in warns:
                print(f"  • {msg.variable}: {msg.message}")
                if msg.suggestion:
                    print(f"    💡 {msg.suggestion}")
        
        # Print info
        if infos:
            print("\nℹ️  INFO:")
            print("-" * 50)
            for msg in infos:
                print(f"  • {msg.variable}: {msg.message}")
                if msg.suggestion:
                    print(f"    💡 {msg.suggestion}")
        
        print()
        
        if errors:
            print(f"❌ Validation failed with {len(errors)} error(s)")
            if exit_on_error:
                sys.exit(1)
        elif warns:
            print(f"⚠️  Validation passed with {len(warns)} warning(s)")
        else:
            print("✅ Environment validation passed")


def validate_environment(
    env_path: Optional[Path] = None,
    exit_on_error: bool = True,
    print_report: bool = True
) -> ValidationResult:
    """
    Validate environment configuration.
    
    This is the main entry point for environment validation.
    Call this at application startup.
    
    Args:
        env_path: Path to .env file
        exit_on_error: Exit if validation fails
        print_report: Print report to console
    
    Returns:
        ValidationResult
    
    Example:
        >>> from app.core.env_validator import validate_environment
        >>> result = validate_environment()
        >>> if not result.valid:
        ...     print("Validation failed!")
    """
    validator = EnvironmentValidator(env_path)
    result = validator.validate()
    
    if print_report:
        validator.print_report(exit_on_error=exit_on_error)
    
    return result


def validate_settings(settings_class: type, exit_on_error: bool = True) -> bool:
    """
    Validate Pydantic settings class.
    
    Args:
        settings_class: Pydantic Settings class to validate
        exit_on_error: Exit if validation fails
    
    Returns:
        True if valid, False otherwise
    """
    try:
        settings_class()
        return True
    except ValidationError as e:
        print("\n❌ Settings validation failed:")
        print("-" * 50)
        for error in e.errors():
            loc = ".".join(str(part) for part in error["loc"])
            print(f"  • {loc}: {error['msg']}")
        print()
        
        if exit_on_error:
            sys.exit(1)
        return False
