"""
Password Policy Module.

Implements configurable password validation with strength requirements:
- Minimum length
- Character complexity (uppercase, lowercase, digits, special chars)
- Common password detection
- Password strength scoring
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional



# Common weak passwords to reject
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "password123", "admin", "admin123", "letmein", "welcome",
    "monkey", "dragon", "master", "111111", "1234567", "12345", "123123",
    "000000", "654321", "qwerty123", "iloveyou", "princess", "sunshine",
    "passw0rd", "shadow", "superman", "qazwsx", "michael", "football",
    "baseball", "trustno1", "hunter", "harley", "ranger", "buster",
    "thomas", "robert", "soccer", "hockey", "killer", "george", "charlie",
    "andrew", "michelle", "love", "jessica", "pepper", "daniel", "access",
    "joshua", "maggie", "starwars", "silver", "william", "dallas", "yankees",
    "123qwe", "test", "testing", "raspberry", "raspberrypi", "pi", "easypi",
}


class PasswordStrength(str, Enum):
    """Password strength levels."""
    WEAK = "weak"
    FAIR = "fair"
    GOOD = "good"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 8
    max_length: int = 256
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = False
    min_strength: PasswordStrength = PasswordStrength.FAIR
    reject_common: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Optional: reject passwords containing username
    reject_username_in_password: bool = True


@dataclass
class PasswordValidationResult:
    """Result of password validation."""
    is_valid: bool
    errors: List[str]
    strength: PasswordStrength
    score: int  # 0-100
    suggestions: List[str]


class PasswordValidator:
    """
    Validates passwords according to configurable policy.
    
    Usage:
        validator = PasswordValidator()
        result = validator.validate("mypassword", username="admin")
        if not result.is_valid:
            print(result.errors)
    """
    
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        self.policy = policy or PasswordPolicy()
    
    def validate(
        self,
        password: str,
        username: Optional[str] = None,
    ) -> PasswordValidationResult:
        """
        Validate a password against the policy.
        
        Args:
            password: The password to validate
            username: Optional username to check against
            
        Returns:
            PasswordValidationResult with validation details
        """
        errors = []
        suggestions = []
        
        # Length checks
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters")
            suggestions.append("Use a longer password")
        
        if len(password) > self.policy.max_length:
            errors.append(f"Password must be at most {self.policy.max_length} characters")
        
        # Character complexity
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(rf'[{re.escape(self.policy.special_chars)}]', password))
        
        if self.policy.require_uppercase and not has_upper:
            errors.append("Password must contain at least one uppercase letter")
            suggestions.append("Add uppercase letters (A-Z)")
        
        if self.policy.require_lowercase and not has_lower:
            errors.append("Password must contain at least one lowercase letter")
            suggestions.append("Add lowercase letters (a-z)")
        
        if self.policy.require_digit and not has_digit:
            errors.append("Password must contain at least one digit")
            suggestions.append("Add numbers (0-9)")
        
        if self.policy.require_special and not has_special:
            errors.append(f"Password must contain at least one special character ({self.policy.special_chars})")
            suggestions.append("Add special characters (!@#$%...)")
        
        # Common password check
        if self.policy.reject_common:
            if password.lower() in COMMON_PASSWORDS:
                errors.append("This password is too common and easily guessable")
                suggestions.append("Choose a more unique password")
        
        # Username in password check
        if username and self.policy.reject_username_in_password:
            if username.lower() in password.lower():
                errors.append("Password should not contain your username")
                suggestions.append("Remove your username from the password")
        
        # Calculate strength
        strength, score = self._calculate_strength(
            password, has_upper, has_lower, has_digit, has_special
        )
        
        # Check minimum strength requirement
        strength_order = [
            PasswordStrength.WEAK,
            PasswordStrength.FAIR,
            PasswordStrength.GOOD,
            PasswordStrength.STRONG,
            PasswordStrength.VERY_STRONG,
        ]
        
        current_level = strength_order.index(strength)
        required_level = strength_order.index(self.policy.min_strength)
        
        if current_level < required_level:
            errors.append(f"Password strength must be at least {self.policy.min_strength.value}")
            if not has_special:
                suggestions.append("Add special characters for stronger password")
            if len(password) < 12:
                suggestions.append("Use at least 12 characters for stronger password")
        
        return PasswordValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            strength=strength,
            score=score,
            suggestions=list(set(suggestions)),  # Remove duplicates
        )
    
    def _calculate_strength(
        self,
        password: str,
        has_upper: bool,
        has_lower: bool,
        has_digit: bool,
        has_special: bool,
    ) -> tuple[PasswordStrength, int]:
        """
        Calculate password strength score.
        
        Returns:
            Tuple of (PasswordStrength, score 0-100)
        """
        score = 0
        
        # Length score (up to 30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 20
        elif length >= 8:
            score += 15
        else:
            score += length * 2  # 0-14 points for short passwords
        
        # Character variety (up to 40 points)
        variety_count = sum([has_upper, has_lower, has_digit, has_special])
        score += variety_count * 10
        
        # Bonus for mixed case usage (up to 10 points)
        if has_upper and has_lower:
            # Count actual variety
            upper_count = sum(1 for c in password if c.isupper())
            lower_count = sum(1 for c in password if c.islower())
            if upper_count >= 2 and lower_count >= 2:
                score += 10
            else:
                score += 5
        
        # Bonus for multiple digits (up to 10 points)
        digit_count = sum(1 for c in password if c.isdigit())
        if digit_count >= 3:
            score += 10
        elif digit_count >= 2:
            score += 5
        
        # Bonus for special characters (up to 10 points)
        special_count = sum(1 for c in password if c in self.policy.special_chars)
        if special_count >= 2:
            score += 10
        elif special_count >= 1:
            score += 5
        
        # Penalty for common patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 10
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            score -= 10
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            score -= 10
        
        # Cap score at 100
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 80:
            strength = PasswordStrength.VERY_STRONG
        elif score >= 60:
            strength = PasswordStrength.STRONG
        elif score >= 40:
            strength = PasswordStrength.GOOD
        elif score >= 25:
            strength = PasswordStrength.FAIR
        else:
            strength = PasswordStrength.WEAK
        
        return strength, score
    
    def get_password_feedback(self, password: str) -> dict:
        """
        Get user-friendly feedback about password strength.
        
        Returns dict with:
            - strength: PasswordStrength enum
            - score: 0-100
            - feedback: List of improvement suggestions
            - criteria: Dict of which requirements are met
        """
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(rf'[{re.escape(self.policy.special_chars)}]', password))
        
        strength, score = self._calculate_strength(
            password, has_upper, has_lower, has_digit, has_special
        )
        
        feedback = []
        if len(password) < 12:
            feedback.append("Use 12+ characters for better security")
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_lower:
            feedback.append("Add lowercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_special:
            feedback.append("Add special characters")
        
        return {
            "strength": strength.value,
            "score": score,
            "feedback": feedback,
            "criteria": {
                "min_length": len(password) >= self.policy.min_length,
                "has_uppercase": has_upper,
                "has_lowercase": has_lower,
                "has_digit": has_digit,
                "has_special": has_special,
                "not_common": password.lower() not in COMMON_PASSWORDS,
            }
        }


# ============================================================================
# Pydantic Field Validator
# ============================================================================

def validate_password_field(password: str, username: Optional[str] = None) -> str:
    """
    Validate password using the default policy.
    
    Raises ValueError if password is invalid.
    Use in Pydantic models with field_validator.
    """
    validator = PasswordValidator()
    result = validator.validate(password, username)
    
    if not result.is_valid:
        raise ValueError("; ".join(result.errors))
    
    return password


# ============================================================================
# Global default validator instance
# ============================================================================

# Default password policy
DEFAULT_POLICY = PasswordPolicy(
    min_length=8,
    max_length=256,
    require_uppercase=True,
    require_lowercase=True,
    require_digit=True,
    require_special=False,  # Not required by default, but adds strength
    min_strength=PasswordStrength.FAIR,
    reject_common=True,
    reject_username_in_password=True,
)

password_validator = PasswordValidator(DEFAULT_POLICY)


def validate_password(password: str, username: Optional[str] = None) -> PasswordValidationResult:
    """
    Validate password using the default global validator.
    
    Args:
        password: Password to validate
        username: Optional username to check against
        
    Returns:
        PasswordValidationResult
    """
    return password_validator.validate(password, username)


def check_password_strength(password: str) -> dict:
    """
    Check password strength and get feedback.
    
    Args:
        password: Password to check
        
    Returns:
        Dict with strength info and suggestions
    """
    return password_validator.get_password_feedback(password)
