"""Modular WeChat flow policy for PRISM DPI."""

from .policy import (
    WECHAT_SERVER_NAMES,
    WECHAT_SERVER_SUFFIXES,
    WeChatFlowPolicy,
)

__all__ = [
    "WECHAT_SERVER_NAMES",
    "WECHAT_SERVER_SUFFIXES",
    "WeChatFlowPolicy",
]
