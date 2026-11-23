"""
Schedule Checker for Verdict Engine

Checks schedules from backend and blocks domains based on time rules.
Reads schedules from /opt/EasyPi/data/netprotection/schedules.json

For "block all" schedules, also manages firewall (iptables) rules
to prevent apps from bypassing DNS blocking via cached IPs.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import get_settings

logger = logging.getLogger(__name__)

# Try to import firewall manager
try:
    from easypi_netprotection.system.firewall_manager import get_firewall_manager
    FIREWALL_AVAILABLE = True
except ImportError:
    FIREWALL_AVAILABLE = False
    logger.warning("Firewall manager not available - iptables blocking disabled")


# IP ranges for services that bypass DNS (hardcoded IPs in apps)
# These are official ASN/IP ranges for apps that ignore DNS
CATEGORY_IP_RANGES: dict[str, list[str]] = {
    "social": [
        # === WhatsApp (Meta/Facebook AS32934, AS63293) ===
        "157.240.0.0/16",      # Meta primary
        "31.13.0.0/16",        # Facebook/WhatsApp
        "179.60.192.0/22",     # WhatsApp
        "185.60.216.0/22",     # Facebook
        "66.220.144.0/20",     # Facebook
        "69.63.176.0/20",      # Facebook
        "69.171.224.0/19",     # Facebook
        "74.119.76.0/22",      # Facebook
        "102.132.96.0/20",     # Meta Africa
        "129.134.0.0/16",      # Meta
        "147.75.208.0/20",     # WhatsApp media
        
        # === Telegram (AS62041, AS59930) ===
        "91.108.4.0/22",       # Telegram DC1
        "91.108.8.0/22",       # Telegram DC2
        "91.108.12.0/22",      # Telegram DC3
        "91.108.16.0/22",      # Telegram DC4
        "91.108.20.0/22",      # Telegram DC5
        "91.108.56.0/22",      # Telegram
        "149.154.160.0/20",    # Telegram
        "185.76.151.0/24",     # Telegram
        "95.161.64.0/20",      # Telegram RU
        
        # === Signal ===
        "76.223.92.165/32",    # Signal server
        "13.248.212.111/32",   # Signal
        
        # === Viber ===
        "54.72.0.0/13",        # Viber (AWS Ireland)
        
        # === Snapchat ===
        "64.233.160.0/19",     # Snapchat via Google
        "216.58.192.0/19",     # Snapchat via Google
        
        # === TikTok (ByteDance) ===
        "161.117.0.0/16",      # TikTok
        "144.48.32.0/19",      # ByteDance
        "203.107.32.0/19",     # ByteDance Asia
    ],
    "gaming": [
        # === Discord ===
        "162.159.128.0/17",    # Discord (Cloudflare)
        "104.16.0.0/12",       # Cloudflare (Discord uses this)
        "66.22.196.0/22",      # Discord voice
        "35.214.128.0/17",     # Discord (Google Cloud)
        
        # === Steam ===
        "208.64.200.0/21",     # Valve/Steam
        "208.78.164.0/22",     # Valve
        "205.196.6.0/24",      # Steam CDN
        "103.10.124.0/23",     # Steam Asia
        "103.28.54.0/24",      # Steam SEA
        
        # === Riot Games (LoL, Valorant) ===
        "104.160.128.0/17",    # Riot Games
        "185.40.64.0/22",      # Riot EU
        "203.24.103.0/24",     # Riot OCE
        
        # === Epic Games ===
        "23.246.48.0/20",      # Epic Games
        
        # === Roblox ===
        "128.116.0.0/16",      # Roblox
        
        # === Xbox Live ===
        "52.160.0.0/11",       # Microsoft/Xbox (Azure)
        
        # === PlayStation Network ===
        "103.247.168.0/22",    # PSN Asia
    ],
    "streaming": [
        # === Netflix ===
        "23.246.0.0/18",       # Netflix
        "37.77.184.0/21",      # Netflix EU
        "45.57.0.0/17",        # Netflix
        "64.120.128.0/17",     # Netflix
        "66.197.128.0/17",     # Netflix
        "108.175.32.0/20",     # Netflix
        "185.2.220.0/22",      # Netflix
        "185.9.188.0/22",      # Netflix
        "192.173.64.0/18",     # Netflix
        "198.38.96.0/19",      # Netflix
        "198.45.48.0/20",      # Netflix
        
        # === YouTube (Google) ===
        "172.217.0.0/16",      # Google
        "142.250.0.0/15",      # Google
        "74.125.0.0/16",       # Google
        "173.194.0.0/16",      # Google
        "209.85.128.0/17",     # Google
        "216.239.32.0/19",     # Google
        "64.233.160.0/19",     # Google
        "66.102.0.0/20",       # Google
        "66.249.64.0/19",      # Google
        "72.14.192.0/18",      # Google
        
        # === Spotify ===
        "35.186.224.0/20",     # Spotify (Google Cloud)
        "104.154.0.0/15",      # Spotify
        "78.31.8.0/21",        # Spotify
        
        # === Twitch ===
        "52.223.192.0/18",     # Twitch (Amazon)
        "99.181.64.0/18",      # Twitch
        "185.42.204.0/22",     # Twitch EU
    ],
}

# IP ranges for messenger QUIC blocking (UDP 443)
# Apps will open but messages/calls won't work - like Netflix
MESSENGER_QUIC_IP_RANGES: list[str] = [
    # === WhatsApp / Meta / Instagram / Facebook Messenger ===
    "157.240.0.0/16",      # Meta primary
    "31.13.0.0/16",        # Facebook/WhatsApp
    "185.60.216.0/22",     # Facebook
    "69.63.176.0/20",      # Facebook
    "102.132.96.0/20",     # Meta Africa
    "179.60.192.0/22",     # WhatsApp
    "129.134.0.0/16",      # Meta
    "185.89.218.0/23",     # Meta
    
    # === Telegram ===
    "91.108.4.0/22",       # Telegram DC1
    "91.108.8.0/22",       # Telegram DC2
    "91.108.12.0/22",      # Telegram DC3
    "91.108.16.0/22",      # Telegram DC4
    "91.108.20.0/22",      # Telegram DC5
    "91.108.56.0/22",      # Telegram
    "149.154.160.0/20",    # Telegram
    "185.76.151.0/24",     # Telegram
    
    # === Discord ===
    "162.159.128.0/17",    # Discord (Cloudflare)
    "162.159.0.0/16",      # Discord
    "104.16.0.0/12",       # Cloudflare (Discord uses this)
    
    # === Signal ===
    "142.250.0.0/15",      # Signal via Google
    "172.217.0.0/16",      # Google
    "108.177.0.0/17",      # Google
    
    # === Viber ===
    "54.171.0.0/16",       # Viber (AWS)
    "52.0.0.0/8",          # AWS general
    
    # === Skype / Microsoft Teams ===
    "13.64.0.0/11",        # Microsoft Azure
    "40.64.0.0/10",        # Microsoft Azure
    "52.96.0.0/12",        # Microsoft 365
    "104.40.0.0/13",       # Microsoft Azure
    
    # === Snapchat ===
    "34.64.0.0/10",        # Google Cloud
    "35.184.0.0/13",       # Google Cloud
    
    # === WeChat ===
    "101.32.0.0/16",       # Tencent
    "109.244.0.0/16",      # Tencent
    "203.205.0.0/16",      # Tencent
    
    # === Line ===
    "147.92.0.0/16",       # Line
    "203.104.128.0/19",    # Line
]

# VPN/Tor/Proxy port blocking
# Block these ports to prevent bypass via VPN applications
# NOTE: WireGuard NOT blocked - Tailscale uses WireGuard!
VPN_TOR_PORTS: dict[str, list[tuple[str, int]]] = {
    # Format: (protocol, port)
    "openvpn": [
        ("udp", 1194),  # OpenVPN default
        ("tcp", 1194),
        ("udp", 1195),  # OpenVPN alternate
        # ("tcp", 443),   # OpenVPN over HTTPS - DON'T block, breaks HTTPS!
    ],
    # WireGuard - DO NOT BLOCK! Tailscale uses WireGuard
    # "wireguard": [
    #     ("udp", 51820),  # WireGuard default
    #     ("udp", 51821),  # WireGuard alternate
    # ],
    "ipsec_ikev2": [
        ("udp", 500),    # IKE
        ("udp", 4500),   # NAT-T
    ],
    "pptp": [
        ("tcp", 1723),   # PPTP
    ],
    "l2tp": [
        ("udp", 1701),   # L2TP
    ],
    "tor": [
        ("tcp", 9001),   # Tor relay
        ("tcp", 9030),   # Tor directory
        ("tcp", 9050),   # Tor SOCKS local
        ("tcp", 9051),   # Tor control
        ("tcp", 9150),   # Tor Browser SOCKS
    ],
    "shadowsocks": [
        ("tcp", 8388),   # Shadowsocks default
        ("udp", 8388),
    ],
    "ssh_tunnel": [
        ("tcp", 22),     # SSH (can be used for tunneling)
    ],
}

# Known Tor entry/guard node IP ranges (updated periodically)
# These are public Tor relays that can be blocked
TOR_EXIT_NODE_RANGES: list[str] = [
    # Tor directory authorities
    "128.31.0.0/16",      # MIT (some Tor nodes)
    "193.23.244.0/24",    # Tor Project
    "199.58.81.0/24",     # Tor Project
    "204.13.164.0/24",    # Tor Project  
]


# Domain categories mapping
CATEGORY_DOMAINS: dict[str, set[str]] = {
    "social": {
        # === MAJOR SOCIAL NETWORKS ===
        "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com",
        "facebook.net", "messenger.com", "m.me",
        "instagram.com", "cdninstagram.com", "ig.me",
        "twitter.com", "x.com", "twimg.com", "t.co",
        "tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly",
        "byteoversea.com", "bytecdn.cn", "ibytedtos.com",
        "snapchat.com", "snap.com", "snapkit.com", "sc-cdn.net",
        "bitmoji.com", "snapads.com",
        "threads.net", "threads.com",
        
        # === DISCUSSION & FORUMS ===
        "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
        "tumblr.com", "tumblr.co",
        "quora.com", "quoracdn.net",
        "medium.com", "medium.com",
        "substack.com", "substackcdn.com",
        "4chan.org", "4channel.org",
        "9gag.com",
        
        # === PROFESSIONAL NETWORKS ===
        "linkedin.com", "licdn.com",
        "xing.com",
        "glassdoor.com",
        
        # === MESSENGERS & CHAT ===
        "whatsapp.com", "whatsapp.net", "wa.me",
        "telegram.org", "telegram.me", "t.me", "tg.me",
        "telesco.pe", "tdesktop.com",
        "signal.org", "signal.art",
        "viber.com", "viber.media",
        "line.me", "line.naver.jp", "linecorp.com",
        "wechat.com", "weixin.qq.com", "wx.qq.com",
        "kakaotalk.com", "kakao.com",
        "imo.im", "imo-im.com",
        "kik.com",
        
        # === VIDEO CHAT ===
        "zoom.us", "zoomgov.com",
        "webex.com", "ciscospark.com",
        "skype.com", "skype.net", "skypeforbusiness.com",
        "teams.microsoft.com", "teams.live.com",
        "meet.google.com", "hangouts.google.com",
        "whereby.com", "appear.in",
        "houseparty.com",
        
        # === DATING APPS ===
        "tinder.com", "gotinder.com",
        "bumble.com",
        "badoo.com",
        "okcupid.com",
        "hinge.co",
        "match.com", "meetic.com",
        "pof.com",
        "happn.com",
        "grindr.com",
        
        # === PHOTO SHARING ===
        "pinterest.com", "pinimg.com",
        "flickr.com", "staticflickr.com",
        "500px.com",
        "vsco.co",
        "unsplash.com",
        "imgur.com", "imgur.io",
        "giphy.com", "gph.is",
        
        # === REGIONAL SOCIAL (Russia/CIS) ===
        "vk.com", "vkontakte.ru", "userapi.com", "vk.me",
        "ok.ru", "odnoklassniki.ru",
        "mail.ru", "my.mail.ru",
        "mirtesen.ru",
        "livejournal.com", "lj.ru",
        "yandex.ru/q",
        
        # === REGIONAL SOCIAL (Asia) ===
        "weibo.com", "weibo.cn", "sinaimg.cn",
        "douyin.com", "douyincdn.com",
        "kuaishou.com", "gifshow.com",
        "xiaohongshu.com", "xhscdn.com",
        "bilibili.com", "bilivideo.com", "hdslb.com",
        "zhihu.com", "zhimg.com",
        "douban.com",
        "tieba.baidu.com",
        "ameblo.jp", "ameba.jp",
        "mixi.jp",
        "pixiv.net",
        "naver.com",
        
        # === ANONYMOUS & TEMPORARY ===
        "ask.fm",
        "tellonym.me",
        "yik-yak.com",
        "whisper.sh",
        "sarahah.com",
        "curious.cat",
        
        # === COMMUNITY PLATFORMS ===
        "nextdoor.com",
        "meetup.com",
        "eventbrite.com",
        "patreon.com",
        "ko-fi.com",
        "buymeacoffee.com",
        "gofundme.com",
        "kickstarter.com",
        "indiegogo.com",
        
        # === BLOGGING & MICROBLOGGING ===
        "blogger.com", "blogspot.com",
        "wordpress.com", "wp.com",
        "wix.com",
        "squarespace.com",
        "typepad.com",
        "ghost.org",
        "hashnode.com",
        "dev.to",
    },
    "gaming": {
        # === GAME STORES & PLATFORMS ===
        "steampowered.com", "steam.com", "steamcommunity.com", "steamcdn-a.akamaihd.net",
        "steamcontent.com", "steamgames.com", "steamusercontent.com", "steamstatic.com",
        "epicgames.com", "epicgames.dev", "unrealengine.com",
        "origin.com", "ea.com", "eaplay.com",
        "gog.com", "gogalaxy.com",
        "ubisoft.com", "uplay.com", "ubi.com",
        "rockstargames.com", "socialclub.rockstargames.com",
        "bethesda.net", "elderscrollsonline.com",
        "humblebundle.com", "humblebundle.net",
        "greenmangaming.com", "fanatical.com",
        "cdkeys.com", "g2a.com", "kinguin.net", "eneba.com",
        "itch.io", "gamejolt.com", "newgrounds.com",
        "indiegala.com", "bundlestars.com",
        
        # === CONSOLE PLATFORMS ===
        "xbox.com", "xboxlive.com", "xbox.net", "xboxservices.com",
        "microsoft.com/xbox", "microsoftstore.com",
        "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
        "playstationnetwork.com", "sie.com",
        "nintendo.com", "nintendo.net", "nintendo-europe.com",
        "accounts.nintendo.com", "nso.nintendo.net",
        
        # === PC GAME LAUNCHERS ===
        "battle.net", "blizzard.com", "blizzard.cn",
        "worldofwarcraft.com", "starcraft.com", "diablo.com",
        "hearthstone.com", "overwatch.com", "warcraft.com",
        "wargaming.net", "worldoftanks.com", "worldofwarships.com",
        "gaijin.net", "warthunder.com",
        "escapefromtarkov.com", "battlestategames.com",
        
        # === GAMING CHAT & COMMUNITIES ===
        "discord.com", "discord.gg", "discordapp.com", "discord.media",
        "discordapp.net", "dis.gd",
        "teamspeak.com", "teamspeak.de",
        "guilded.gg",
        "curse.com", "curseforge.com", "cursecdn.com",
        "overwolf.com",
        
        # === STREAMING & ESPORTS ===
        "twitch.tv", "twitchcdn.net", "twitchsvc.net", "jtvnw.net",
        "kick.com",
        
        # === POPULAR ONLINE GAMES ===
        "roblox.com", "robloxcdn.com", "rbxcdn.com", "rbx.com",
        "minecraft.net", "mojang.com", "minecraftservices.com",
        "fortnite.com", "fn.gg",
        "leagueoflegends.com", "riotgames.com", "pvp.net", "lol.com",
        "valorant.com", "playvalorant.com",
        "dota2.com", "valvesoftware.com",
        "pubg.com", "pubgmobile.com", "krafton.com",
        "callofduty.com", "activision.com", "activisionblizzard.com",
        "apexlegends.com",
        "genshin.hoyoverse.com", "hoyoverse.com", "mihoyo.com",
        "honkaiimpact3.hoyoverse.com", "starrail.hoyoverse.com",
        "pocketpair.jp", "palworld.gg",
        
        # === MMORPG & ONLINE GAMES ===
        "finalfantasyxiv.com", "square-enix.com", "playonline.com",
        "guildwars2.com", "arenanet.com",
        "runescape.com", "jagex.com", "oldschool.runescape.com",
        "blackdesertonline.com", "pearlabyss.com",
        "pathofexile.com", "grindinggear.com",
        "lostark.com", "playlostark.com",
        "newworld.com", "amazon games",
        "warframe.com", "digitalextremes.com",
        "maplestory.nexon.net", "nexon.com", "nexon.net",
        "enmasse.com", "terapc.enmasse.com",
        
        # === MOBILE GAMES ===
        "supercell.com", "clashofclans.com", "clashroyale.com", "brawlstars.com",
        "king.com", "candycrush.com",
        "pokemongo.nianticlabs.com", "nianticlabs.com", "pokemon.com",
        "mobilelegends.com", "moonton.com",
        "freefiremax.com", "garena.com", "ff.garena.com",
        "pubgmobile.com", "tencent.com",
        "playmobilegames.com", "gameloft.com",
        "kabam.com", "zynga.com", "scopely.com",
        "plarium.com", "innersloth.com",
        
        # === VR GAMING ===
        "oculus.com", "meta.com/quest", "sidequestvr.com",
        "viveport.com", "vrdesktop.net",
        
        # === GAME MODS & CHEATS (block everything) ===
        "nexusmods.com", "moddb.com", "gamebanana.com",
        "modrinth.com", "planetminecraft.com",
        "unknowncheats.me", "mpgh.net", "elitepvpers.com",
        
        # === GAME WIKIS & GUIDES ===
        "fandom.com", "wikia.com", "gamepedia.com",
        "ign.com", "gamespot.com", "kotaku.com", "polygon.com",
        "pcgamer.com", "gamesradar.com", "eurogamer.net",
        "gamerant.com", "thegamer.com", "dualshockers.com",
        
        # === REGIONAL GAMING (Russia/CIS) ===
        "vkplay.ru", "my.games", "mail.ru/games",
        "gameawards.ru", "playground.ru",
        
        # === REGIONAL GAMING (Asia) ===
        "qq.com", "wegame.com.cn", "4399.com", "37.com",
        "netease.com", "163.com/game",
        "dmm.com", "dmm.co.jp",
        "kakaogames.com", "netmarble.com", "ncsoft.com",
        "garena.com", "sea.com",
    },
    "streaming": {
        # === VIDEO STREAMING (Major) ===
        # Netflix - full API/CDN coverage
        "netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxso.net",
        "nflxext.com", "netflix.ca", "netflix.de", "netflix.fr", "netflix.co.uk",
        "prod.ftl.netflix.com", "prod.cloud.netflix.com", "appboot.netflix.com",
        "ichnaea.netflix.com", "customerevents.netflix.com",
        # YouTube - full API/CDN coverage (wildcards matched by suffix)
        "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
        "yt.be", "youtube-nocookie.com", "youtubei.googleapis.com",
        "yt3.ggpht.com", "i.ytimg.com", "s.ytimg.com",
        "youtube.googleapis.com", "wide-youtube.l.google.com",
        "r1---sn-", "r2---sn-", "r3---sn-", "r4---sn-", "r5---sn-",  # CDN patterns
        # Hulu
        "hulu.com", "huluim.com", "hulustream.com", "hulu.tv",
        # Disney+
        "disneyplus.com", "disney.com", "dssott.com", "disney-plus.net",
        "disneystreaming.com", "bamgrid.com", "execute-api.us-east-1.amazonaws.com",
        # HBO Max
        "hbomax.com", "max.com", "hbo.com", "hbogo.com", "hbonow.com",
        # Amazon Prime Video
        "primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net",
        "atv-ps.amazon.com", "atv-ext.amazon.com",
        "peacocktv.com", "peacock.com",
        "paramountplus.com", "paramount.com", "cbs.com", "cbsnews.com",
        "pluto.tv", "plutotv.com",
        "sling.com", "slingtv.com",
        "fubo.tv", "fubotv.com",
        "tubitv.com", "tubi.tv",
        "plex.tv", "plex.direct",
        "emby.media",
        "jellyfin.org",
        
        # === ANIME & ASIAN ===
        "crunchyroll.com", "crunchyrollsvc.com", "vrv.co",
        "funimation.com", "funimationnow.com",
        "hidive.com", "sentaifilmworks.com",
        "animelab.com",
        "kiss-anime.ws", "gogoanime.tv", "9anime.to",
        "bilibili.com", "bilivideo.com", "hdslb.com",
        "iqiyi.com", "iq.com",
        "youku.com", "tudou.com",
        "viki.com", "viki.io",
        "wetv.vip",
        "viu.com",
        
        # === LIVE STREAMING ===
        # Twitch - full CDN coverage
        "twitch.tv", "twitchcdn.net", "twitchsvc.net", "jtvnw.net",
        "ttvnw.net", "static.twitchcdn.net", "usher.ttvnw.net",
        "video-edge-", "video-weaver.", "clips-media-assets",
        # Kick
        "kick.com", "kick.stream",
        # Other live streaming
        "facebook.com/gaming", "fb.gg",
        "youtube.com/gaming",
        "caffeine.tv",
        "dlive.tv",
        "trovo.live",
        "nimo.tv",
        "bigo.tv", "bigolive.tv",
        
        # === VIDEO SHARING ===
        "vimeo.com", "vimeocdn.com", "player.vimeo.com",
        "dailymotion.com", "dm-event.net", "dmcdn.net",
        "veoh.com",
        "metacafe.com",
        "rumble.com",
        "bitchute.com",
        "odysee.com", "lbry.tv",
        "dtube.video",
        
        # === MUSIC STREAMING ===
        # Spotify - full API/CDN coverage
        "spotify.com", "spotifycdn.com", "scdn.co", "spotify.net",
        "open.spotify.com", "audio-ak-spotify-com.akamaized.net",
        "apresolve.spotify.com", "api.spotify.com", "spclient.wg.spotify.com",
        "dealer.spotify.com", "audio-fa.scdn.co", "heads-fa.scdn.co",
        # Apple Music
        "music.apple.com", "applemusic.com", "itunes.apple.com",
        "mzstatic.com", "audio.itunes.apple.com",
        "music.youtube.com", "music.youtube.googlevideo.com",
        "soundcloud.com", "sndcdn.com",
        "pandora.com", "pandora.tv",
        "deezer.com", "dzcdn.net",
        "tidal.com", "tidalhifi.com",
        "amazonmusic.com", "music.amazon.com",
        "napster.com", "rhapsody.com",
        "audiomack.com",
        "bandcamp.com",
        "mixcloud.com",
        "last.fm", "lastfm.freetls.fastly.net",
        "genius.com",
        "shazam.com",
        
        # === MUSIC (Regional) ===
        "yandex.ru/music", "music.yandex.ru",
        "vk.com/music", "boom.ru",
        "zvuk.com",
        "netease.com/music", "music.163.com",
        "kugou.com", "kuwo.cn", "qq.com/music",
        
        # === PODCASTS ===
        "podcasts.apple.com",
        "podcasts.google.com",
        "overcast.fm",
        "pocketcasts.com",
        "castbox.fm",
        "stitcher.com",
        "anchor.fm",
        "spreaker.com",
        "podbean.com",
        "buzzsprout.com",
        "transistor.fm",
        "simplecast.com",
        
        # === AUDIOBOOKS ===
        "audible.com", "audible.de", "audible.co.uk",
        "libro.fm",
        "scribd.com",
        "storytel.com",
        "chirpbooks.com",
        
        # === REGIONAL STREAMING (Russia) ===
        "ivi.ru", "ivi.tv",
        "kinopoisk.ru", "hd.kinopoisk.ru",
        "okko.tv", "okko.ru",
        "more.tv",
        "start.ru", "start.video",
        "premier.one", "tnt-premier.ru",
        "wink.ru", "wink.rt.ru",
        "kion.ru",
        "megogo.net", "megogo.ru",
        "amediateka.ru",
        
        # === REGIONAL STREAMING (Europe) ===
        "rtlplus.de", "tvnow.de",
        "joyn.de",
        "zdf.de", "ardmediathek.de",
        "sky.com", "skygo.sky.de", "now.sky.de",
        "britbox.com",
        "itvhub.com", "itv.com",
        "all4.channel4.com", "channel4.com",
        "bbc.co.uk/iplayer", "iplayer.bbc.co.uk",
        "arte.tv",
        "tf1.fr", "canalplus.com", "mycanal.fr",
        "videoland.com",
        "npo.nl",
        
        # === SPORTS STREAMING ===
        "espn.com", "espnplus.com", "espn.go.com",
        "dazn.com",
        "nba.com/watch", "nbastreams.to",
        "nfl.com", "nflgamepass.com",
        "mlb.tv", "mlb.com",
        "nhl.tv", "nhl.com",
        "f1tv.formula1.com",
        "bt.com/sport", "btsport.com",
        "skysports.com",
        "nbcsports.com",
        "cbssports.com",
        "foxsports.com",
        "peacock.com/sports",
        
        # === SHORT VIDEO ===
        # TikTok - full API/CDN coverage
        "tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com",
        "musical.ly", "byteoversea.com", "ibytedtos.com", "ipstatp.com",
        "bytedance.com", "bytecdn.cn", "bytegecko.com", "tiktok.org",
        "lf1-cdn-tos.bytegecko.com", "p16-sign-va.tiktokcdn.com",
        # YouTube Shorts
        "youtube.com/shorts",
        # Instagram Reels  
        "instagram.com/reels",
        # Snapchat Spotlight
        "snapchat.com/spotlight",
        # Other short video
        "likee.video", "likee.com",
        "triller.co",
        "clash.me",
        "dubsmash.com",
        
        # === ADULT STREAMING (SFW names only) ===
        "onlyfans.com",
        "fansly.com",
        "patreon.com",
    },
    "adult": {
        # Adult content domains - blocked by default
    },
    # ===== BYPASS PROTECTION =====
    # Automatically included when any schedule restriction is active
    "bypass": {
        # === VPN PROVIDERS ===
        "nordvpn.com", "nordvpn.net", "nordcdn.com",
        "expressvpn.com", "expressvpn.net", "xvpn.io",
        "surfshark.com", "surfshark.net",
        "protonvpn.com", "protonvpn.net", "proton.me",
        "cyberghostvpn.com", "cyberghostvpn.biz",
        "privateinternetaccess.com", "piavpn.com", "privateinternetaccess.net",
        "windscribe.com", "windscribe.net", "wscdn.net",
        "tunnelbear.com", "tunnelbear.net",
        "hotspotshield.com", "hsselite.com", "anchorfree.com",
        "hidemyass.com", "privax.com",
        "ipvanish.com", "ipvanish.net",
        "purevpn.com", "purevpn.net",
        "strongvpn.com", "reliablehosting.com",
        "vyprvpn.com", "goldenfrog.com",
        "zenmate.com", "zenguard.biz",
        "privatevpn.com",
        "torguard.net", "torguard.org",
        "mullvad.net",
        "ivpn.net",
        "airvpn.org",
        "astrill.com",
        "speedify.com",
        "hide.me",
        "touch.vpn", "touchvpn.net",
        "betternet.co", "betternet.com",
        "psiphon.ca", "psiphon3.com",
        "opera.com/vpn", "opera.com/proxy",
        
        # === DOH/DOT PROVIDERS (DNS bypass) ===
        "cloudflare-dns.com", "1.1.1.1", "one.one.one.one",
        "dns.google", "dns.google.com", "8.8.8.8", "8.8.4.4",
        "dns.quad9.net", "quad9.net", "9.9.9.9",
        "doh.cleanbrowsing.org", "cleanbrowsing.org",
        "dns.nextdns.io", "nextdns.io", "my.nextdns.io",
        "doh.opendns.com", "opendns.com",
        "adguard-dns.io", "dns.adguard.com",
        "controld.com", "dns.controld.com",
        "mullvad.net/dns",
        "odvr.nic.cz",
        "dns.switch.ch",
        "dns.alidns.com",
        
        # === TOR NETWORK ===
        "torproject.org", "tor.eff.org",
        "check.torproject.org", "bridges.torproject.org",
        "dist.torproject.org", "torbrowser.org",
        "onion.foundation", "onion.ly", "onion.ws",
        "tor.onion",
        "geti2p.net", "i2p2.de", "i2p-projekt.de",
        
        # === PROXY SERVICES ===
        "hide.me/proxy", "hideme.io",
        "kproxy.com", "kproxy.net",
        "proxysite.com",
        "hidemyass.com/proxy",
        "croxyproxy.com", "croxyproxy.net",
        "4everproxy.com",
        "filterbypass.me",
        "webproxy.to",
        "proxyscrape.com",
        "geonode.com",
        "free-proxy.cz",
        "proxy-list.download",
        "proxify.com",
        "anonymox.net",
        "hola.org", "hola.com",
        "ultrasurf.us",
        "freegate.org",
        "unblock-websites.com",
        "blockaway.net",
        
        # === SMARTDNS SERVICES ===
        "getflix.com.au",
        "unlocator.com",
        "smartydns.com",
        "unotelly.com",
        "overplay.net",
        "unblock-us.com",
        "ironsocket.com",
        "smartdns.com",
    },
}


@dataclass
class ScheduleMatch:
    """Result of schedule check."""
    blocked: bool
    schedule_name: str
    rule_target: str
    reason: str


class ScheduleChecker:
    """
    Checks if a domain should be blocked based on time schedules.
    
    Loads schedules from backend JSON file and checks:
    - Current day of week
    - Current time
    - Profile/device mapping
    """
    
    def __init__(self, data_dir: str | Path | None = None):
        self._data_dir = Path(data_dir) if data_dir else get_settings().NETPROTECTION_DATA_DIR
        self._schedules_file = self._data_dir / "schedules.json"
        self._bindings_file = self._data_dir / "bindings.json"
        self._reload_signal_file = self._data_dir / ".schedules_reload"

        self._firewall_disabled = os.getenv("NETPROTECTION_DISABLE_FIREWALL") == "1"
        self._has_sudo = shutil.which("sudo") is not None
        self._has_iptables = shutil.which("iptables") is not None
        self._has_ipset = shutil.which("ipset") is not None

        self._schedules: list[dict] = []
        self._ip_to_profile: dict[str, str] = {}   # ip  -> profile_id (ip bindings)
        self._mac_to_profile: dict[str, str] = {}  # mac -> profile_id (mac bindings)
        # Live IP<->MAC from the kernel ARP table, so device targeting survives DHCP.
        self._ip_to_mac: dict[str, str] = {}
        self._mac_to_ips: dict[str, set[str]] = {}
        self._arp_last = 0.0
        self._last_load = 0.0
        self._reload_interval = 30.0  # Reload every 30 seconds

        self._load_data()
        logger.info(f"ScheduleChecker initialized, schedules_file={self._schedules_file}")

    def _firewall_enabled(self) -> bool:
        if self._firewall_disabled:
            return False
        if not FIREWALL_AVAILABLE:
            return False
        return self._has_sudo and self._has_iptables

    def _ipset_enabled(self) -> bool:
        return self._firewall_enabled() and self._has_ipset
    
    def _load_data(self) -> None:
        """Load schedules and bindings from JSON files."""
        # Load schedules
        if self._schedules_file.exists():
            try:
                data = json.loads(self._schedules_file.read_text(encoding="utf-8"))
                schedules = data.get("schedules") if isinstance(data, dict) else None
                if not isinstance(schedules, list):
                    raise ValueError("schedules must be a list")
                self._schedules = schedules
                logger.info(f"Loaded {len(self._schedules)} schedules from {self._schedules_file}")
            except Exception as e:
                # Keep the last known-good in-memory policy and existing firewall
                # rules. Clearing either here would silently disable parental controls.
                logger.error("Failed to load schedules; keeping last known policy: %s", e)
                self._last_load = time.time()
                return
        else:
            self._schedules = []
        
        # Load bindings (device -> profile_id). Support BOTH ip and mac bindings;
        # mac bindings are resolved to the current IP at enforcement time (DHCP-proof).
        if self._bindings_file.exists():
            try:
                data = json.loads(self._bindings_file.read_text(encoding="utf-8"))
                bindings_list = data.get("bindings") if isinstance(data, dict) else None
                if not isinstance(bindings_list, list):
                    raise ValueError("bindings must be a list")
                ip_to_profile: dict[str, str] = {}
                mac_to_profile: dict[str, str] = {}
                for b in bindings_list:
                    if not isinstance(b, dict):
                        continue
                    if not b.get("enabled", True):
                        continue
                    bt = b.get("binding_type")
                    value = str(b.get("value", "")).strip()
                    profile_id = b.get("profile_id", "")
                    if not value or not profile_id:
                        continue
                    if bt == "ip":
                        ip_to_profile[value] = profile_id
                    elif bt == "mac":
                        mac_to_profile[value.lower()] = profile_id
                self._ip_to_profile = ip_to_profile
                self._mac_to_profile = mac_to_profile
                logger.info(
                    f"Loaded {len(bindings_list)} bindings "
                    f"({len(self._ip_to_profile)} ip, {len(self._mac_to_profile)} mac)"
                )
            except Exception as e:
                logger.error("Failed to load bindings; keeping last known bindings: %s", e)
        else:
            self._ip_to_profile = {}
            self._mac_to_profile = {}

        self._last_load = time.time()
        self._refresh_arp(force=True)
        # One-time migration: drop the old network-wide category rules/ipsets.
        self._cleanup_legacy_category_ipsets()

        # Update firewall rules based on current schedules
        self._update_firewall_rules()
        # Update category IP blocking (for apps that bypass DNS)
        self._update_category_ip_blocking()
        # Update VPN/Tor port blocking for active schedules
        self._update_vpn_blocking_for_schedules()

    def _refresh_arp(self, force: bool = False) -> None:
        """Refresh live IP<->MAC maps from the kernel ARP table (cheap; LAN only).
        This lets device targeting follow a device across DHCP IP changes."""
        if not force and (time.time() - self._arp_last) < 2.0:
            return
        ip_to_mac: dict[str, str] = {}
        mac_to_ips: dict[str, set[str]] = {}
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                next(f, None)  # skip header row
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip, flags, mac = parts[0], parts[2], parts[3].lower()
                        if flags != "0x0" and mac and mac != "00:00:00:00:00:00":
                            ip_to_mac[ip] = mac
                            mac_to_ips.setdefault(mac, set()).add(ip)
        except Exception as exc:
            logger.warning("Could not refresh ARP mappings; keeping last known mappings: %s", exc)
            self._arp_last = time.time()
            return
        self._ip_to_mac = ip_to_mac
        self._mac_to_ips = mac_to_ips
        self._arp_last = time.time()

    def _resolve_schedule_ips(self, schedule: dict) -> set[str]:
        """Resolve durable MAC targets; use literal IPs only for legacy schedules."""
        macs = schedule.get("device_macs") or []
        if not macs:
            return set(schedule.get("device_ips") or [])
        ips: set[str] = set()
        for mac in macs:
            ips |= self._mac_to_ips.get(str(mac).lower(), set())
        return ips

    def _is_device_scoped(self, schedule: dict) -> bool:
        return bool(schedule.get("device_ips") or schedule.get("device_macs"))

    def _ips_for_profile(self, profile_id: str) -> set[str]:
        """All current IPs bound to a profile, preferring observed MAC identity."""
        ips = {
            ip for ip, pid in self._ip_to_profile.items()
            if pid == profile_id and ip not in self._ip_to_mac
        }
        for mac, pid in self._mac_to_profile.items():
            if pid == profile_id:
                ips |= self._mac_to_ips.get(mac, set())
        return ips

    def _profile_for_ip(self, ip: str) -> str | None:
        """Profile bound to the observed device MAC, with legacy IP fallback."""
        mac = self._ip_to_mac.get(ip)
        pid = self._mac_to_profile.get(mac) if mac else None
        if pid:
            return pid
        return self._ip_to_profile.get(ip)

    def _update_category_ip_blocking(self) -> None:
        """Block hardcoded category server IPs (WhatsApp/Discord/Netflix…) that bypass
        DNS — PER DEVICE. Each active (device, category) gets its own FORWARD rule
        (-s <ip> --match-set easypi_cat_<cat> dst -j DROP), so a rule for one kid never
        blocks the whole network."""
        if not self._ipset_enabled():
            return

        now = datetime.now()
        js_day = (now.weekday() + 1) % 7
        current_time = now.strftime("%H:%M")

        desired: set[tuple[str, str]] = set()   # (device_ip, category)
        social_ips: set[str] = set()
        for schedule in self._schedules:
            if not schedule.get("enabled", True):
                continue
            profile_id = schedule.get("profile_id")
            for rule in schedule.get("rules", []):
                if rule.get("type", "block") != "block":
                    continue
                if rule.get("target_type") != "category":
                    continue
                if js_day not in rule.get("days", []):
                    continue
                if not self._time_in_range(current_time, rule.get("start_time", "00:00"),
                                           rule.get("end_time", "23:59")):
                    continue
                cat = rule.get("target", "")
                if cat not in CATEGORY_IP_RANGES:
                    continue
                resolved = self._resolve_schedule_ips(schedule)
                if resolved:
                    ips = resolved
                elif profile_id:
                    ips = self._ips_for_profile(profile_id)
                else:
                    ips = set(self._ip_to_mac.keys()) | set(self._ip_to_profile.keys())
                for ip in ips:
                    desired.add((ip, cat))
                    if cat == "social":
                        social_ips.add(ip)

        # Destination-IP ipsets are shared across devices (only the source differs).
        for cat in {c for _, c in desired}:
            self._ensure_category_ipset(cat)

        current = self._list_tagged_forward("easypi_sched_cat")
        for ip, cat in current - desired:
            self._del_forward_rule(self._cat_rule_args(ip, cat))
        for ip, cat in desired - current:
            self._add_forward_rule(self._cat_rule_args(ip, cat))

        if desired:
            logger.info("Per-device category IP blocking: %d rule(s) active", len(desired))

        # Per-device messenger QUIC (UDP 443) blocking for social-blocked devices.
        self._update_messenger_quic_per_device(social_ips)
    
    def _ensure_category_ipset(self, category: str) -> None:
        """Ensure the shared destination-IP ipset for a category exists + is populated."""
        name = f"easypi_cat_{category}"
        try:
            subprocess.run(["sudo", "ipset", "create", name, "hash:net", "-exist"], capture_output=True)
            for ip_range in CATEGORY_IP_RANGES.get(category, []):
                subprocess.run(["sudo", "ipset", "add", name, ip_range, "-exist"], capture_output=True)
        except Exception as e:
            logger.error(f"Failed to setup ipset {name}: {e}")

    def _cat_rule_args(self, ip: str, category: str) -> list[str]:
        return ["-s", ip, "-m", "set", "--match-set", f"easypi_cat_{category}", "dst",
                "-m", "comment", "--comment", "easypi_sched_cat", "-j", "DROP"]

    def _quic_rule_args(self, ip: str) -> list[str]:
        return ["-s", ip, "-p", "udp", "--dport", "443",
                "-m", "set", "--match-set", "easypi_messenger_quic", "dst",
                "-m", "comment", "--comment", "easypi_sched_quic", "-j", "DROP"]

    def _add_forward_rule(self, args: list[str]) -> None:
        try:
            if subprocess.run(["sudo", "iptables", "-C", "FORWARD", *args], capture_output=True).returncode != 0:
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", *args], capture_output=True)
        except Exception as e:
            logger.error(f"iptables add failed: {e}")

    def _del_forward_rule(self, args: list[str]) -> None:
        try:
            subprocess.run(["sudo", "iptables", "-D", "FORWARD", *args], capture_output=True)
        except Exception as exc:
            logger.warning("iptables delete failed: %s", exc)

    def _list_tagged_forward(self, tag: str) -> set[tuple[str, str]]:
        """EasyPi per-device FORWARD rules carrying a comment tag → {(src_ip, key)},
        where key is the category (from easypi_cat_<cat>) or 'quic'."""
        out: set[tuple[str, str]] = set()
        try:
            res = subprocess.run(["sudo", "iptables", "-S", "FORWARD"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if tag not in line:
                    continue
                parts = line.split()
                ip = ""
                key = ""
                for i, p in enumerate(parts):
                    if p == "-s" and i + 1 < len(parts):
                        ip = parts[i + 1].split("/")[0]
                    elif p == "--match-set" and i + 1 < len(parts):
                        ms = parts[i + 1]
                        if ms.startswith("easypi_cat_"):
                            key = ms[len("easypi_cat_"):]
                        elif ms == "easypi_messenger_quic":
                            key = "quic"
                if ip and key:
                    out.add((ip, key))
        except Exception as exc:
            logger.warning("Could not list tagged iptables rules (%s): %s", tag, exc)
        return out

    def _update_messenger_quic_per_device(self, social_ips: set[str]) -> None:
        """Per-device QUIC (UDP 443) DROP for social-blocked devices (messenger calls)."""
        if not self._ipset_enabled():
            return
        if social_ips:
            try:
                subprocess.run(["sudo", "ipset", "create", "easypi_messenger_quic", "hash:net", "-exist"],
                               capture_output=True)
                for ip_range in MESSENGER_QUIC_IP_RANGES:
                    subprocess.run(["sudo", "ipset", "add", "easypi_messenger_quic", ip_range, "-exist"],
                                   capture_output=True)
            except Exception as e:
                logger.error(f"Failed to setup messenger QUIC ipset: {e}")
        desired = {(ip, "quic") for ip in social_ips}
        current = self._list_tagged_forward("easypi_sched_quic")
        for ip, _ in current - desired:
            self._del_forward_rule(self._quic_rule_args(ip))
        for ip, _ in desired - current:
            self._add_forward_rule(self._quic_rule_args(ip))

    def _cleanup_legacy_category_ipsets(self) -> None:
        """Remove the OLD network-wide category rules/ipsets (easypi_<cat>, no source)
        superseded by the per-device rules. Idempotent; runs once per reload."""
        if not self._ipset_enabled():
            return
        for cat in CATEGORY_IP_RANGES:
            name = f"easypi_{cat}"
            for chain in ("FORWARD", "OUTPUT"):
                subprocess.run(["sudo", "iptables", "-D", chain, "-m", "set",
                                "--match-set", name, "dst", "-j", "DROP"], capture_output=True)
            subprocess.run(["sudo", "ipset", "destroy", name], capture_output=True)
        # Old global (sourceless) messenger QUIC rule.
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-p", "udp", "--dport", "443",
                        "-m", "set", "--match-set", "easypi_messenger_quic", "dst", "-j", "DROP"],
                       capture_output=True)

    def _setup_vpn_tor_port_blocking(self, client_ip: str) -> None:
        """Block VPN/Tor ports for a specific client IP.
        
        This prevents bypass via:
        - OpenVPN (1194)
        - WireGuard (51820)
        - IKEv2/IPSec (500, 4500)
        - Tor (9001, 9030, 9050, 9051, 9150)
        - PPTP, L2TP, Shadowsocks
        """
        if not self._has_iptables:
            return
        
        chain_name = f"EASYPI_VPN_BLOCK_{client_ip.replace('.', '_')}"
        
        try:
            # Check if chain already exists
            check = subprocess.run(
                ["sudo", "iptables", "-L", chain_name],
                capture_output=True
            )
            
            if check.returncode == 0:
                # Chain exists, skip
                return
            
            # Create new chain
            subprocess.run(
                ["sudo", "iptables", "-N", chain_name],
                capture_output=True
            )
            
            # Add port blocking rules to the chain
            blocked_ports = []
            for category, ports in VPN_TOR_PORTS.items():
                if category == "ssh_tunnel":
                    continue  # Don't block SSH by default
                    
                for proto, port in ports:
                    subprocess.run(
                        ["sudo", "iptables", "-A", chain_name, "-p", proto, 
                         "--dport", str(port), "-j", "DROP"],
                        capture_output=True
                    )
                    blocked_ports.append(f"{proto}/{port}")
            
            # Block Tor node IP ranges
            for ip_range in TOR_EXIT_NODE_RANGES:
                subprocess.run(
                    ["sudo", "iptables", "-A", chain_name, "-d", ip_range, "-j", "DROP"],
                    capture_output=True
                )
            
            # Jump to this chain from FORWARD for this client
            subprocess.run(
                ["sudo", "iptables", "-I", "FORWARD", "-s", client_ip, "-j", chain_name],
                capture_output=True
            )
            
            logger.info(f"🔒 VPN/Tor port blocking enabled for {client_ip}: {len(blocked_ports)} ports")
            
        except Exception as e:
            logger.error(f"Failed to setup VPN/Tor blocking for {client_ip}: {e}")
    
    def _remove_vpn_tor_port_blocking(self, client_ip: str) -> None:
        """Remove VPN/Tor port blocking for a specific client IP."""
        if not self._has_iptables:
            return
        
        chain_name = f"EASYPI_VPN_BLOCK_{client_ip.replace('.', '_')}"
        
        try:
            # Remove jump rule from FORWARD
            subprocess.run(
                ["sudo", "iptables", "-D", "FORWARD", "-s", client_ip, "-j", chain_name],
                capture_output=True
            )
            
            # Flush and delete chain
            subprocess.run(
                ["sudo", "iptables", "-F", chain_name],
                capture_output=True
            )
            subprocess.run(
                ["sudo", "iptables", "-X", chain_name],
                capture_output=True
            )
            
            logger.debug(f"Removed VPN/Tor port blocking for {client_ip}")
            
        except Exception as e:
            logger.error(f"Failed to remove VPN/Tor blocking for {client_ip}: {e}")
    
    def _update_vpn_blocking_for_schedules(self) -> None:
        """Update VPN/Tor blocking based on active schedules.
        
        If ANY schedule is active for a client IP, block VPN/Tor ports.
        """
        if not self._has_iptables:
            return
        
        now = datetime.now()
        current_day = now.weekday()
        js_day = (current_day + 1) % 7
        current_time = now.strftime("%H:%M")
        
        # Find all IPs that should have VPN blocking right now
        ips_to_block: set[str] = set()
        
        for schedule in self._schedules:
            if not schedule.get("enabled", True):
                continue
            
            schedule_profile_id = schedule.get("profile_id")
            
            for rule in schedule.get("rules", []):
                if rule.get("type", "block") != "block":
                    continue
                
                # Check day
                rule_days = rule.get("days", [])
                if js_day not in rule_days:
                    continue
                
                # Check time
                start_time = rule.get("start_time", "00:00")
                end_time = rule.get("end_time", "23:59")
                if not self._time_in_range(current_time, start_time, end_time):
                    continue
                
                # This rule is active! Find affected IPs (device_ips + device_macs).
                resolved = self._resolve_schedule_ips(schedule)
                if resolved:
                    ips_to_block |= resolved
                elif schedule_profile_id:
                    ips_to_block |= self._ips_for_profile(schedule_profile_id)
        
        # Get currently blocked IPs (check for existing chains)
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "-n"],
                capture_output=True,
                text=True
            )
            currently_blocked: set[str] = set()
            for line in result.stdout.split('\n'):
                if "EASYPI_VPN_BLOCK_" in line:
                    # Extract IP from chain name
                    parts = line.split()
                    for part in parts:
                        if "EASYPI_VPN_BLOCK_" in part:
                            ip = part.replace("EASYPI_VPN_BLOCK_", "").replace("_", ".")
                            currently_blocked.add(ip)
        except (OSError, subprocess.SubprocessError, ValueError):
            currently_blocked = set()
        
        # Remove blocking for IPs that shouldn't be blocked
        for ip in currently_blocked - ips_to_block:
            self._remove_vpn_tor_port_blocking(ip)
        
        # Add blocking for new IPs
        for ip in ips_to_block - currently_blocked:
            self._setup_vpn_tor_port_blocking(ip)

    def _update_firewall_rules(self) -> None:
        """Update iptables rules based on active 'block all' schedules."""
        if not self._firewall_enabled():
            return
        
        try:
            firewall = get_firewall_manager()
            now = datetime.now()
            current_day = now.weekday()
            js_day = (current_day + 1) % 7
            current_time = now.strftime("%H:%M")
            
            # Find all IPs that should be blocked right now
            ips_to_block: set[str] = set()
            
            for schedule in self._schedules:
                if not schedule.get("enabled", True):
                    continue
                
                schedule_profile_id = schedule.get("profile_id")
                
                for rule in schedule.get("rules", []):
                    # Only handle "block all" rules
                    if rule.get("target_type") != "all":
                        continue
                    if rule.get("type", "block") != "block":
                        continue
                    
                    # Check day
                    rule_days = rule.get("days", [])
                    if js_day not in rule_days:
                        continue
                    
                    # Check time
                    start_time = rule.get("start_time", "00:00")
                    end_time = rule.get("end_time", "23:59")
                    if not self._time_in_range(current_time, start_time, end_time):
                        continue
                    
                    # This rule is active! Find affected IPs.
                    # device_ips + device_macs (resolved to current IP via ARP).
                    resolved = self._resolve_schedule_ips(schedule)
                    if resolved:
                        ips_to_block |= resolved
                    elif schedule_profile_id:
                        # Profile-scoped: all IPs currently bound to the profile.
                        ips_to_block |= self._ips_for_profile(schedule_profile_id)
                    else:
                        # No device/profile targeting - block all known devices.
                        ips_to_block |= set(self._ip_to_mac.keys()) | set(self._ip_to_profile.keys())
            
            # Sync firewall rules
            currently_blocked = firewall.get_blocked_devices()
            
            # Unblock IPs that shouldn't be blocked anymore
            for ip in currently_blocked - ips_to_block:
                firewall.unblock_device(ip)
            
            # Block IPs that should be blocked
            for ip in ips_to_block - currently_blocked:
                firewall.block_device(ip)
            
            if ips_to_block:
                logger.info(f"Firewall: {len(ips_to_block)} devices blocked by schedule")
                
        except Exception as e:
            logger.error(f"Failed to update firewall rules: {e}")
    
    def _check_reload_signal(self) -> bool:
        """Check if reload signal file exists and remove it."""
        if self._reload_signal_file.exists():
            try:
                self._reload_signal_file.unlink()
                logger.info("Schedule reload signal received - forcing immediate reload")
                return True
            except Exception as e:
                logger.error(f"Failed to remove reload signal: {e}")
        return False
    
    def _maybe_reload(self) -> None:
        """Reload data if interval has passed or signal received."""
        # Check for immediate reload signal first
        if self._check_reload_signal():
            self._load_data()
            return
        
        # Regular interval-based reload
        if time.time() - self._last_load > self._reload_interval:
            self._load_data()
        else:
            # Even without reload, refresh ARP + firewall rules (time/IPs may change)
            self._refresh_arp()
            self._update_firewall_rules()
            self._update_category_ip_blocking()
            self._update_vpn_blocking_for_schedules()
    
    def force_reload(self) -> None:
        """Force immediate reload of schedules."""
        logger.info("Forcing immediate schedule reload")
        self._load_data()
    
    def check(
        self,
        domain: str,
        client_ip: str,
        now: datetime | None = None,
    ) -> ScheduleMatch | None:
        """
        Check if domain should be blocked by any schedule.
        
        Args:
            domain: Domain being queried
            client_ip: Client IP address
            now: Current time (defaults to now)
            
        Returns:
            ScheduleMatch if blocked, None if allowed
        """
        self._maybe_reload()
        
        if not self._schedules:
            return None
        
        now = now or datetime.now()
        current_day = now.weekday()  # 0=Monday, 6=Sunday
        # Frontend uses: 0=Sunday, 1=Monday... so we need to convert
        # Python: Mon=0, Tue=1, Wed=2, Thu=3, Fri=4, Sat=5, Sun=6
        # JS: Sun=0, Mon=1, Tue=2, Wed=3, Thu=4, Fri=5, Sat=6
        js_day = (current_day + 1) % 7  # Convert Python to JS day numbering
        
        current_time = now.strftime("%H:%M")
        domain_lower = domain.lower().rstrip('.')
        
        # Profile bound to this client (by IP or by current MAC).
        profile_id = self._profile_for_ip(client_ip)

        logger.debug(f"Schedule check: domain={domain_lower}, client_ip={client_ip}, profile_id={profile_id}")

        for schedule in self._schedules:
            if not schedule.get("enabled", True):
                continue

            # Scope the schedule to the right client. If it targets specific devices,
            # only apply to those (by current IP, resolved from MAC) — so the DNS layer
            # matches the firewall layer. Otherwise use the profile filter (or global).
            if self._is_device_scoped(schedule):
                if client_ip not in self._resolve_schedule_ips(schedule):
                    continue
            else:
                schedule_profile_id = schedule.get("profile_id")
                if schedule_profile_id and profile_id != schedule_profile_id:
                    continue

            # Check rules
            for rule in schedule.get("rules", []):
                # Check day
                rule_days = rule.get("days", [])
                if js_day not in rule_days:
                    continue
                
                # Check time
                start_time = rule.get("start_time", "00:00")
                end_time = rule.get("end_time", "23:59")
                
                if not self._time_in_range(current_time, start_time, end_time):
                    continue
                
                # Check target
                rule_type = rule.get("type", "block")
                target = rule.get("target", "")
                target_type = rule.get("target_type", "category")
                
                if rule_type != "block":
                    continue  # Only handle block rules for now
                
                # Match domain
                if target_type == "all":
                    # Block all internet
                    return ScheduleMatch(
                        blocked=True,
                        schedule_name=schedule.get("name", "Unknown"),
                        rule_target="all",
                        reason=f"Schedule '{schedule.get('name')}' blocks all internet {start_time}-{end_time}",
                    )
                
                elif target_type == "category":
                    # Check if domain is in category
                    if self._domain_in_category(domain_lower, target):
                        return ScheduleMatch(
                            blocked=True,
                            schedule_name=schedule.get("name", "Unknown"),
                            rule_target=target,
                            reason=f"Schedule '{schedule.get('name')}' blocks {target} {start_time}-{end_time}",
                        )
                
                elif target_type == "domain":
                    # Exact domain match
                    if domain_lower == target.lower() or domain_lower.endswith("." + target.lower()):
                        return ScheduleMatch(
                            blocked=True,
                            schedule_name=schedule.get("name", "Unknown"),
                            rule_target=target,
                            reason=f"Schedule '{schedule.get('name')}' blocks {target} {start_time}-{end_time}",
                        )
                
                # AUTOMATIC BYPASS PROTECTION:
                # If ANY schedule rule is active for this client, also block bypass domains
                # This prevents kids from using VPN/DoH/Tor to circumvent time limits
                if self._domain_in_category(domain_lower, "bypass"):
                    return ScheduleMatch(
                        blocked=True,
                        schedule_name=schedule.get("name", "Unknown"),
                        rule_target="bypass",
                        reason="Bypass protection: VPN/DoH/Proxy blocked during scheduled restriction",
                    )
        
        return None
    
    def _time_in_range(self, current: str, start: str, end: str) -> bool:
        """Check if current time is in range (handles overnight ranges)."""
        if start <= end:
            # Normal range: 09:00 - 17:00
            return start <= current <= end
        else:
            # Overnight range: 22:00 - 07:00
            return current >= start or current <= end
    
    def _domain_in_category(self, domain: str, category: str) -> bool:
        """Check if domain belongs to category."""
        domains = CATEGORY_DOMAINS.get(category, set())
        
        # Check exact match and subdomain match
        for cat_domain in domains:
            if domain == cat_domain or domain.endswith("." + cat_domain):
                return True
        
        return False
    
    def get_stats(self) -> dict[str, Any]:
        """Get checker statistics."""
        return {
            "schedules_count": len(self._schedules),
            "profiles_count": len(self._ip_to_profile) + len(self._mac_to_profile),
            "last_reload": self._last_load,
            "schedules_file": str(self._schedules_file),
        }


# Singleton instance
_schedule_checker: ScheduleChecker | None = None


def get_schedule_checker(data_dir: str | None = None) -> ScheduleChecker:
    """Get singleton ScheduleChecker instance."""
    global _schedule_checker
    if _schedule_checker is None:
        _schedule_checker = ScheduleChecker(data_dir)
    return _schedule_checker


def trigger_schedule_reload(data_dir: str | None = None) -> bool:
    """
    Trigger immediate schedule reload by creating signal file.
    Called from backend after schedule changes.
    
    Returns:
        True if signal file was created successfully
    """
    data_path = Path(data_dir) if data_dir else get_settings().NETPROTECTION_DATA_DIR
    signal_file = data_path / ".schedules_reload"
    
    try:
        signal_file.touch()
        logger.info(f"Schedule reload signal created: {signal_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to create reload signal: {e}")
        return False
