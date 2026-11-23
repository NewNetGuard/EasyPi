"""Policy-gated WeChat TLS and QUIC flow classification.

Only dedicated WeChat/Weixin service zones and observed first-party control
names are actionable. Generic QQ, Tencent Cloud, and shared CDN zones are
deliberately excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


WECHAT_SERVER_SUFFIXES = (
    "wechat.com",
    "wechat.com.cn",
    "weixin.com",
    "weixin.qq.com",
    "weixin.qq.com.cn",
    "wxqcloud.qq.com.cn",
)
WECHAT_SERVER_NAMES = (
    "weixin110.qq.com",
    "weixinconf.qq.com",
)
WECHAT_POLICY_NAMES = frozenset({"wechat", "wechat_ip"})


class WeChatFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh WeChat TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="wechat",
            policy_names=WECHAT_POLICY_NAMES,
            server_suffixes=WECHAT_SERVER_SUFFIXES,
            server_names=WECHAT_SERVER_NAMES,
            address_resolver=address_resolver,
        )


__all__ = [
    "WECHAT_SERVER_NAMES",
    "WECHAT_SERVER_SUFFIXES",
    "WeChatFlowPolicy",
]
