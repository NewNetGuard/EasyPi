"""
Age-Based Content Filtering

Defines age categories with associated blocked content categories.
Based on common content rating systems (PEGI, ESRB, etc.)

AGE CATEGORIES:
- CHILD (0-7): Maximum protection, only educational/kids content
- KID (8-12): Block adult, violence, gambling, dating, social
- TEEN (13-17): Block adult, gambling, some restrictions
- ADULT (18+): Minimal restrictions (malware/phishing only)

CONTENT CATEGORIES:
Each category has predefined domains and keywords that are blocked.
"""

from __future__ import annotations

import logging
import threading
import time
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


logger = logging.getLogger(__name__)


class AgeCategory(Enum):
    """Age-based content filtering categories."""
    
    CHILD = "child"      # 0-7 years - maximum protection
    KID = "kid"          # 8-12 years - heavy filtering
    TEEN = "teen"        # 13-17 years - moderate filtering
    ADULT = "adult"      # 18+ - minimal filtering
    
    @property
    def min_age(self) -> int:
        return {
            AgeCategory.CHILD: 0,
            AgeCategory.KID: 8,
            AgeCategory.TEEN: 13,
            AgeCategory.ADULT: 18,
        }[self]
    
    @property
    def max_age(self) -> int:
        return {
            AgeCategory.CHILD: 7,
            AgeCategory.KID: 12,
            AgeCategory.TEEN: 17,
            AgeCategory.ADULT: 99,
        }[self]
    
    @classmethod
    def from_age(cls, age: int) -> "AgeCategory":
        """Determine category from numeric age."""
        if age < 8:
            return cls.CHILD
        elif age < 13:
            return cls.KID
        elif age < 18:
            return cls.TEEN
        return cls.ADULT


class ContentCategory(Enum):
    """Content categories for filtering."""
    
    # Dangerous
    MALWARE = "malware"
    PHISHING = "phishing"
    
    # Adult content
    ADULT = "adult"
    PORNOGRAPHY = "pornography"
    NUDITY = "nudity"
    
    # Violence
    VIOLENCE = "violence"
    GORE = "gore"
    WEAPONS = "weapons"
    
    # Gambling & Drugs
    GAMBLING = "gambling"
    DRUGS = "drugs"
    ALCOHOL = "alcohol"
    TOBACCO = "tobacco"
    
    # Social & Dating
    SOCIAL_MEDIA = "social_media"
    DATING = "dating"
    CHAT = "chat"
    
    # Gaming
    GAMING = "gaming"
    GAMING_MATURE = "gaming_mature"
    
    # Other
    PIRACY = "piracy"
    VPN_PROXY = "vpn_proxy"
    STREAMING = "streaming"
    ADS = "ads"
    TRACKERS = "trackers"


# Category blocking rules per age category
# True = blocked, False = allowed
AGE_CATEGORY_RULES: dict[AgeCategory, dict[ContentCategory, bool]] = {
    AgeCategory.CHILD: {
        # Block everything except safe categories
        ContentCategory.MALWARE: True,
        ContentCategory.PHISHING: True,
        ContentCategory.ADULT: True,
        ContentCategory.PORNOGRAPHY: True,
        ContentCategory.NUDITY: True,
        ContentCategory.VIOLENCE: True,
        ContentCategory.GORE: True,
        ContentCategory.WEAPONS: True,
        ContentCategory.GAMBLING: True,
        ContentCategory.DRUGS: True,
        ContentCategory.ALCOHOL: True,
        ContentCategory.TOBACCO: True,
        ContentCategory.SOCIAL_MEDIA: True,
        ContentCategory.DATING: True,
        ContentCategory.CHAT: True,
        ContentCategory.GAMING: True,  # Only educational games
        ContentCategory.GAMING_MATURE: True,
        ContentCategory.PIRACY: True,
        ContentCategory.VPN_PROXY: True,
        ContentCategory.STREAMING: True,  # Only kids streaming
        ContentCategory.ADS: True,
        ContentCategory.TRACKERS: True,
    },
    AgeCategory.KID: {
        ContentCategory.MALWARE: True,
        ContentCategory.PHISHING: True,
        ContentCategory.ADULT: True,
        ContentCategory.PORNOGRAPHY: True,
        ContentCategory.NUDITY: True,
        ContentCategory.VIOLENCE: True,
        ContentCategory.GORE: True,
        ContentCategory.WEAPONS: True,
        ContentCategory.GAMBLING: True,
        ContentCategory.DRUGS: True,
        ContentCategory.ALCOHOL: True,
        ContentCategory.TOBACCO: True,
        ContentCategory.SOCIAL_MEDIA: True,
        ContentCategory.DATING: True,
        ContentCategory.CHAT: True,
        ContentCategory.GAMING: False,  # Age-appropriate games OK
        ContentCategory.GAMING_MATURE: True,
        ContentCategory.PIRACY: True,
        ContentCategory.VPN_PROXY: True,
        ContentCategory.STREAMING: False,  # Streaming allowed
        ContentCategory.ADS: True,
        ContentCategory.TRACKERS: True,
    },
    AgeCategory.TEEN: {
        ContentCategory.MALWARE: True,
        ContentCategory.PHISHING: True,
        ContentCategory.ADULT: True,
        ContentCategory.PORNOGRAPHY: True,
        ContentCategory.NUDITY: True,
        ContentCategory.VIOLENCE: False,  # Some violence OK for teens
        ContentCategory.GORE: True,
        ContentCategory.WEAPONS: False,
        ContentCategory.GAMBLING: True,
        ContentCategory.DRUGS: True,
        ContentCategory.ALCOHOL: True,
        ContentCategory.TOBACCO: True,
        ContentCategory.SOCIAL_MEDIA: False,  # Social media allowed
        ContentCategory.DATING: True,
        ContentCategory.CHAT: False,
        ContentCategory.GAMING: False,
        ContentCategory.GAMING_MATURE: True,  # M-rated games still blocked
        ContentCategory.PIRACY: True,
        ContentCategory.VPN_PROXY: True,  # Prevent bypassing
        ContentCategory.STREAMING: False,
        ContentCategory.ADS: True,
        ContentCategory.TRACKERS: True,
    },
    AgeCategory.ADULT: {
        # Only security-related blocks
        ContentCategory.MALWARE: True,
        ContentCategory.PHISHING: True,
        ContentCategory.ADULT: False,
        ContentCategory.PORNOGRAPHY: False,
        ContentCategory.NUDITY: False,
        ContentCategory.VIOLENCE: False,
        ContentCategory.GORE: False,
        ContentCategory.WEAPONS: False,
        ContentCategory.GAMBLING: False,
        ContentCategory.DRUGS: False,
        ContentCategory.ALCOHOL: False,
        ContentCategory.TOBACCO: False,
        ContentCategory.SOCIAL_MEDIA: False,
        ContentCategory.DATING: False,
        ContentCategory.CHAT: False,
        ContentCategory.GAMING: False,
        ContentCategory.GAMING_MATURE: False,
        ContentCategory.PIRACY: False,
        ContentCategory.VPN_PROXY: False,
        ContentCategory.STREAMING: False,
        ContentCategory.ADS: False,
        ContentCategory.TRACKERS: False,
    },
}


# Domain patterns for each content category
# Using frozensets for O(1) lookup and immutability
CATEGORY_DOMAINS: dict[ContentCategory, frozenset[str]] = {
    ContentCategory.ADULT: frozenset({
        "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
        "redtube.com", "youporn.com", "tube8.com", "spankbang.com",
        "chaturbate.com", "stripchat.com", "livejasmin.com",
        "onlyfans.com", "fansly.com", "manyvids.com",
        "brazzers.com", "bangbros.com", "realitykings.com",
        "playboy.com", "penthouse.com",
    }),
    
    ContentCategory.GAMBLING: frozenset({
        "bet365.com", "betway.com", "888casino.com", "pokerstars.com",
        "unibet.com", "williamhill.com", "paddypower.com", "betfair.com",
        "draftkings.com", "fanduel.com", "bovada.com", "betonline.ag",
        "1xbet.com", "stake.com", "roobet.com", "rollbit.com",
        "casumo.com", "leovegas.com", "mrgreen.com",
    }),
    
    ContentCategory.DATING: frozenset({
        "tinder.com", "bumble.com", "hinge.co", "match.com",
        "okcupid.com", "pof.com", "eharmony.com", "zoosk.com",
        "badoo.com", "meetme.com", "tagged.com", "grindr.com",
        "her.app", "coffee-meets-bagel.com", "happn.com",
    }),
    
    ContentCategory.SOCIAL_MEDIA: frozenset({
        "facebook.com", "instagram.com", "twitter.com", "x.com",
        "tiktok.com", "snapchat.com", "reddit.com", "tumblr.com",
        "pinterest.com", "linkedin.com", "threads.net",
        "mastodon.social", "bsky.app", "discord.com",
        "telegram.org", "whatsapp.com", "signal.org",
    }),
    
    ContentCategory.GAMING: frozenset({
        "store.steampowered.com", "epicgames.com", "gog.com",
        "ea.com", "origin.com", "ubisoft.com", "blizzard.com",
        "riotgames.com", "minecraft.net", "roblox.com",
        "fortnite.com", "leagueoflegends.com", "twitch.tv",
    }),
    
    ContentCategory.GAMING_MATURE: frozenset({
        "rockstargames.com",  # GTA
        "callofduty.com",
        "doom.com",
        "mortalkombat.com",
    }),
    
    ContentCategory.VIOLENCE: frozenset({
        "liveleak.com", "bestgore.com", "documenting.com",
        "theync.com", "kaotic.com",
    }),
    
    ContentCategory.DRUGS: frozenset({
        "erowid.org", "leafly.com", "weedmaps.com",
        "hightimes.com", "420magazine.com",
    }),
    
    ContentCategory.ALCOHOL: frozenset({
        "totalwine.com", "drizly.com", "wine.com",
        "bevmo.com", "minibar.com",
    }),
    
    ContentCategory.PIRACY: frozenset({
        "thepiratebay.org", "1337x.to", "rarbg.to", "yts.mx",
        "nyaa.si", "fitgirl-repacks.site", "skidrowreloaded.com",
        "igg-games.com", "oceanofgames.com",
    }),
    
    ContentCategory.VPN_PROXY: frozenset({
        "nordvpn.com", "expressvpn.com", "surfshark.com",
        "protonvpn.com", "privateinternetaccess.com", "cyberghost.com",
        "tunnelbear.com", "windscribe.com", "mullvad.net",
        "hidemyass.com", "hotspotshield.com",
        # Proxy sites
        "hide.me", "kproxy.com", "proxysite.com",
        "croxyproxy.com", "webproxy.to",
    }),
    
    ContentCategory.STREAMING: frozenset({
        "netflix.com", "hulu.com", "disneyplus.com", "hbomax.com",
        "peacocktv.com", "paramountplus.com", "amazon.com/primevideo",
        "youtube.com", "twitch.tv", "crunchyroll.com",
    }),
    
    ContentCategory.CHAT: frozenset({
        "omegle.com", "chatroulette.com", "chatrandom.com",
        "emeraldchat.com", "camsurf.com",
    }),
}

# Keyword patterns for URL/domain matching
CATEGORY_KEYWORDS: dict[ContentCategory, list[re.Pattern]] = {
    ContentCategory.ADULT: [
        re.compile(r'\b(porn|xxx|sex|nude|naked|adult)\b', re.I),
        re.compile(r'\b(nsfw|hentai|erotic)\b', re.I),
    ],
    ContentCategory.GAMBLING: [
        re.compile(r'\b(casino|poker|betting|slots|blackjack)\b', re.I),
        re.compile(r'\b(sportsbook|wager|gambl)\b', re.I),
    ],
    ContentCategory.VIOLENCE: [
        re.compile(r'\b(gore|brutal|murder|torture)\b', re.I),
    ],
    ContentCategory.DRUGS: [
        re.compile(r'\b(weed|cannabis|marijuana|cocaine|heroin)\b', re.I),
    ],
}


@dataclass
class AgeFilterResult:
    """Result of age-based filtering check."""
    
    blocked: bool
    category: ContentCategory | None = None
    age_category: AgeCategory | None = None
    reason: str = ""
    matched_domain: str = ""
    matched_keyword: str = ""


class AgeFilter:
    """
    Age-based content filter.
    
    Checks domains against age-appropriate content categories.
    """
    
    def __init__(self):
        self._stats = {
            "checks": 0,
            "blocked": 0,
            "by_category": {cat.value: 0 for cat in ContentCategory},
        }
        self._cache_lock = threading.Lock()
        self._cache_built_at = 0.0
        self._domain_to_category: dict[str, ContentCategory] = {}
        self._rebuild_category_cache()

    def _rebuild_category_cache(self) -> None:
        """Rebuild the reverse lookup and publish it atomically."""
        domain_to_category: dict[str, ContentCategory] = {}
        for category, domains in CATEGORY_DOMAINS.items():
            for domain in domains:
                domain_to_category[domain] = category
        self._domain_to_category = domain_to_category
        self._cache_built_at = time.monotonic()

    def refresh_if_stale(self, ttl_hours: float) -> bool:
        """Refresh the embedded category lookup once its configured TTL expires."""
        ttl_seconds = max(0.0, float(ttl_hours)) * 3600.0
        if time.monotonic() - self._cache_built_at < ttl_seconds:
            return False
        with self._cache_lock:
            if time.monotonic() - self._cache_built_at < ttl_seconds:
                return False
            self._rebuild_category_cache()
            return True

    @property
    def category_data_available(self) -> bool:
        return bool(self._domain_to_category)
    
    def check(
        self,
        domain: str,
        age_category: AgeCategory,
    ) -> AgeFilterResult:
        """
        Check if domain should be blocked for given age category.
        
        Args:
            domain: Domain to check
            age_category: Age category to apply
            
        Returns:
            AgeFilterResult with block decision and reason
        """
        self._stats["checks"] += 1
        domain_lower = domain.lower().rstrip('.')
        
        # Get blocking rules for this age category
        rules = AGE_CATEGORY_RULES.get(age_category, {})
        
        # 1. Check exact domain match
        for check_domain in self._get_domain_variants(domain_lower):
            if check_domain in self._domain_to_category:
                content_cat = self._domain_to_category[check_domain]
                if rules.get(content_cat, False):
                    self._stats["blocked"] += 1
                    self._stats["by_category"][content_cat.value] += 1
                    return AgeFilterResult(
                        blocked=True,
                        category=content_cat,
                        age_category=age_category,
                        reason=f"Domain in {content_cat.value} category (blocked for {age_category.value})",
                        matched_domain=check_domain,
                    )
        
        # 2. Check keyword patterns
        for content_cat, patterns in CATEGORY_KEYWORDS.items():
            if not rules.get(content_cat, False):
                continue
            
            for pattern in patterns:
                match = pattern.search(domain_lower)
                if match:
                    self._stats["blocked"] += 1
                    self._stats["by_category"][content_cat.value] += 1
                    return AgeFilterResult(
                        blocked=True,
                        category=content_cat,
                        age_category=age_category,
                        reason=f"Keyword match for {content_cat.value} (blocked for {age_category.value})",
                        matched_keyword=match.group(0),
                    )
        
        return AgeFilterResult(blocked=False)
    
    def _get_domain_variants(self, domain: str) -> list[str]:
        """Get domain variants for matching (with/without www, parent domains)."""
        variants = [domain]
        
        # Remove www prefix
        if domain.startswith("www."):
            variants.append(domain[4:])
        else:
            variants.append(f"www.{domain}")
        
        # Parent domains (up to 2 levels)
        parts = domain.split('.')
        for i in range(1, min(len(parts) - 1, 3)):
            parent = '.'.join(parts[i:])
            if len(parent.split('.')) >= 2:  # At least TLD + 1
                variants.append(parent)
        
        return variants
    
    def get_blocked_categories(self, age_category: AgeCategory) -> list[str]:
        """Get list of blocked content categories for an age category."""
        rules = AGE_CATEGORY_RULES.get(age_category, {})
        return [cat.value for cat, blocked in rules.items() if blocked]
    
    def get_stats(self) -> dict[str, Any]:
        """Get filter statistics (no PII)."""
        return {
            "total_checks": self._stats["checks"],
            "total_blocked": self._stats["blocked"],
            "blocked_by_category": dict(self._stats["by_category"]),
        }


# Singleton instance
_age_filter: AgeFilter | None = None


def get_age_filter() -> AgeFilter:
    """Get singleton AgeFilter instance."""
    global _age_filter
    if _age_filter is None:
        _age_filter = AgeFilter()
    return _age_filter
