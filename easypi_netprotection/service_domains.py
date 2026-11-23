"""
Service-to-domains mapping for parental control and content filtering.

This module contains the actual domains used by apps and services,
not just their main websites. This enables effective blocking of
streaming, social media, gaming, and other content categories.
"""

from typing import Dict, List, Set

# Special marker that enables heuristic adult-domain detection in profile blacklist.
# This avoids relying only on static domain lists for pornography blocking.
ADULT_HEURISTIC_MARKER = "__adult_heuristic__"

# Retained internally for category coverage and existing saved policies, but
# intentionally omitted from the user-facing parental-control service catalog.
SERVICE_CATALOG_EXCLUSIONS = frozenset({
    "hulu",
    "gambling",
    "origin",
    "battlenet",
    "linkedin",
    "pandora",
    "news",
})
SERVICE_CATEGORY_CATALOG_EXCLUSIONS = frozenset({
    "streaming",
    "social_media",
    "messaging",
    "music",
    "gaming",
    "dating",
    "entertainment",
    "distractions",
})

# Individual services with all their domains
SERVICE_DOMAINS: Dict[str, List[str]] = {
    # === VIDEO STREAMING ===
    "youtube": [
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtu.be",
        "*.youtube.com",
        "*.googlevideo.com",        # Video streaming CDN
        "youtubei.googleapis.com",  # YouTube API
        "*.ytimg.com",              # Thumbnails
        "youtube-nocookie.com",
        "*.youtube-nocookie.com",
        "yt3.ggpht.com",
        "*.yt.be",
        "youtube.googleapis.com",
        "www.youtube-nocookie.com",
        # Regional YouTube domains
        "youtube.de",
        "youtube.co.uk",
        "youtube.fr",
        "youtube.es",
        "youtube.it",
        "youtube.nl",
        "youtube.be",
        "youtube.at",
        "youtube.ch",
        "youtube.pl",
        "youtube.ru",
        "youtube.jp",
        "youtube.com.au",
        "youtube.co.jp",
        "youtube.com.br",
        "youtube.com.mx",
        "youtube.ca",
        "youtube.se",
        "youtube.no",
        "youtube.dk",
        "youtube.fi",
        "youtube.pt",
        "youtube.co.kr",
        "youtube.in",
        "youtube.com.tw",
        "youtube.co.za",
        "youtube.com.ar",
        "youtube.ae",
        "youtube.co.nz",
        "youtube.ie",
        "youtube.gr",
        "youtube.com.tr",
        "youtube.co.il",
        "youtube.com.ua",
        "youtube.cz",
        "youtube.hu",
        "youtube.ro",
        "youtube.sk",
        "youtube.bg",
        "youtube.hr",
        "youtube.rs",
        "youtube.si",
        "youtube.lt",
        "youtube.lv",
        "youtube.ee",
    ],
    "netflix": [
        "netflix.com",
        "www.netflix.com",
        "*.netflix.com",
        "*.nflxvideo.net",          # Video streaming
        "*.nflximg.net",            # Images
        "*.nflxext.com",            # Extensions
        "*.nflxso.net",             # Netflix SO
        "netflix.net",
        "*.netflix.net",
        # Regional domains
        "netflix.de",
        "netflix.co.uk",
        "netflix.fr",
        "netflix.es",
        "netflix.it",
        "netflix.nl",
        "netflix.be",
        "netflix.at",
        "netflix.ch",
        "netflix.pl",
        "netflix.ru",
        "netflix.jp",
        "netflix.com.au",
        "netflix.co.jp",
        "netflix.com.br",
        "netflix.com.mx",
        "netflix.ca",
        "netflix.se",
        "netflix.no",
        "netflix.dk",
        "netflix.fi",
        "netflix.pt",
        "netflix.co.kr",
        "netflix.in",
        "netflix.com.tw",
        "netflix.co.za",
        "netflix.com.ar",
    ],
    "disney": [
        "disneyplus.com",
        "www.disneyplus.com",
        "*.disneyplus.com",
        "*.disney-plus.net",
        "*.bamgrid.com",            # Disney streaming backend
        "*.dssott.com",             # Disney streaming
        "*.disneystreaming.com",
        "disney.com",
        "*.disney.com",
        # Regional domains
        "disney.de",
        "disney.co.uk",
        "disney.fr",
        "disney.es",
        "disney.it",
        "disney.nl",
        "disney.be",
        "disney.at",
        "disney.ch",
        "disney.pl",
        "disney.ru",
        "disney.jp",
        "disney.com.au",
        "disney.co.jp",
        "disney.com.br",
        "disney.com.mx",
        "disney.ca",
        "disney.se",
        "disney.no",
        "disney.dk",
        "disney.fi",
        "disney.pt",
        "disney.co.kr",
        "disney.in",
        "disney.com.tw",
        "disney.co.za",
        "disney.com.ar",
        "*.disney.de",
        "*.disney.co.uk",
        "*.disney.fr",
        "*.disney.es",
        "*.disney.it",
        "*.disney.nl",
        "*.disney.be",
        "*.disney.at",
        "*.disney.ch",
        "*.disney.pl",
        "*.disney.ru",
        "*.disney.jp",
        "*.disney.com.au",
        "*.disney.co.jp",
        "*.disney.com.br",
        "*.disney.com.mx",
        "*.disney.ca",
    ],
    "hulu": [
        "hulu.com",
        "www.hulu.com",
        "*.hulu.com",
        "*.hulustream.com",
        "*.huluim.com",
        "*.hulu.tv",
    ],
    "hbo": [
        "hbomax.com",
        "*.hbomax.com",
        "max.com",
        "*.max.com",
        "discomax.com",
        "*.discomax.com",
        "*.hbo.com",
        "play.hbomax.com",
    ],
    "amazon_video": [
        "amazonvideo.com",
        "*.amazonvideo.com",
        "primevideo.com",
        "www.primevideo.com",
        "*.primevideo.com",
        "pv-cdn.net",
        "*.pv-cdn.net",
        "aiv-cdn.net",
        "*.aiv-cdn.net",
        "aiv-delivery.net",
        "*.aiv-delivery.net",
        "atv-ps.amazon.com",
        "atv-ext.amazon.com",
        # Exact Prime Video delivery hosts observed on shared CDN zones.
        "a72live-emt-pv-ta-amazon.akamaized.net",
        "a192live-emt-pv-ta-amazon.akamaized.net",
        "a17live-emt-pv-ta-amazon.akamaized.net",
        "a182live-emt-pv-ta-amazon.akamaized.net",
        "a27live-emt-pv-ta-amazon.akamaized.net",
        "a39avoddashs3ww-a.akamaihd.net",
        # Regional Prime Video-owned domains
        "*.primevideo.de",
        "*.primevideo.co.uk",
        "*.primevideo.fr",
        "*.primevideo.es",
        "*.primevideo.it",
        "*.primevideo.co.jp",
    ],
    "twitch": [
        "twitch.tv",
        "www.twitch.tv",
        "*.twitch.tv",
        "*.twitchcdn.net",
        "*.jtvnw.net",              # Twitch video
        "*.ttvnw.net",              # Twitch video
        "usher.ttvnw.net",
        "static.twitchcdn.net",
    ],
    "vimeo": [
        "vimeo.com",
        "*.vimeo.com",
        "*.vimeocdn.com",
        "player.vimeo.com",
    ],
    "dailymotion": [
        "dailymotion.com",
        "*.dailymotion.com",
        "*.dmcdn.net",
    ],
    
    # === SOCIAL MEDIA ===
    "tiktok": [
        "tiktok.com",
        "www.tiktok.com",
        "*.tiktok.com",
        "*.tiktokcdn.com",
        "*.tiktokcdn-eu.com",
        "*.tiktokv.com",
        "*.tiktokv.eu",
        "*.tiktokglobalshopv.com",
        "*.musical.ly",
        "*.byteoversea.com",
        "*.ibytedtos.com",
        "*.ipstatp.com",
        "*.tiktokcdn-us.com",
        "*.tiktok.org",
        "vm.tiktok.com",
        # Regional TikTok domains
        "tiktok.de",
        "tiktok.co.uk",
        "tiktok.fr",
        "tiktok.es",
        "tiktok.it",
        "tiktok.nl",
        "tiktok.ru",
        "tiktok.jp",
        "tiktok.com.br",
        "tiktok.co.kr",
        "*.tiktok.de",
        "*.tiktok.co.uk",
        "*.tiktok.fr",
        "*.tiktok.es",
        "*.tiktok.it",
    ],
    "facebook": [
        "facebook.com",
        "www.facebook.com",
        "m.facebook.com",
        "*.facebook.com",
        "*.fbcdn.net",              # Content CDN
        "*.fb.com",
        "*.fb.me",
        "messenger.com",
        "*.messenger.com",
        "fbsbx.com",
        "*.fbsbx.com",
        "facebook.net",
        "*.facebook.net",
        "*.facebookcorewwwi.onion",
        # Regional Facebook domains
        "facebook.de",
        "facebook.co.uk",
        "facebook.fr",
        "facebook.es",
        "facebook.it",
        "facebook.nl",
        "facebook.ru",
        "facebook.pl",
        "facebook.com.br",
        "facebook.co.jp",
        "facebook.co.kr",
        "facebook.com.au",
        "facebook.com.mx",
        "facebook.co.in",
        "*.facebook.de",
        "*.facebook.co.uk",
        "*.facebook.fr",
        "*.facebook.es",
        "*.facebook.it",
    ],
    "instagram": [
        "instagram.com",
        "www.instagram.com",
        "*.instagram.com",
        "*.cdninstagram.com",
        "ig.me",
        "*.ig.me",
        "i.instagram.com",
        "graph.instagram.com",
        # Regional Instagram domains
        "instagram.de",
        "instagram.co.uk",
        "instagram.fr",
        "instagram.es",
        "instagram.it",
        "instagram.nl",
        "instagram.ru",
        "instagram.pl",
        "instagram.com.br",
        "instagram.co.jp",
        "instagram.co.kr",
        "*.instagram.de",
        "*.instagram.co.uk",
        "*.instagram.fr",
    ],
    "twitter": [
        "twitter.com",
        "www.twitter.com",
        "*.twitter.com",
        "x.com",
        "www.x.com",
        "*.x.com",
        "*.twimg.com",
        "t.co",
        "*.t.co",
        "api.twitter.com",
        "mobile.twitter.com",
        # Regional Twitter/X domains
        "twitter.de",
        "twitter.co.uk",
        "twitter.fr",
        "twitter.es",
        "twitter.it",
        "twitter.jp",
        "twitter.co.jp",
        "twitter.com.br",
        "twitter.ru",
    ],
    "snapchat": [
        "snapchat.com",
        "www.snapchat.com",
        "*.snapchat.com",
        "*.snapchat.io",
        "*.sc-cdn.net",
        "*.snap.com",
        "*.snapads.com",
        "*.impala-media-production.s3.amazonaws.com",
    ],
    "reddit": [
        "reddit.com",
        "www.reddit.com",
        "*.reddit.com",
        "*.redd.it",
        "*.redditmedia.com",
        "*.redditstatic.com",
        "old.reddit.com",
        "new.reddit.com",
        "i.redd.it",
        # Regional Reddit domains
        "reddit.de",
        "reddit.co.uk",
        "reddit.fr",
        "reddit.es",
        "reddit.it",
        "reddit.nl",
        "reddit.ru",
        "reddit.jp",
    ],
    "pinterest": [
        "pinterest.com",
        "www.pinterest.com",
        "*.pinterest.com",
        "*.pinimg.com",
        "api.pinterest.com",
        # Regional Pinterest domains
        "pinterest.de",
        "pinterest.co.uk",
        "pinterest.fr",
        "pinterest.es",
        "pinterest.it",
        "pinterest.nl",
        "pinterest.ru",
        "pinterest.jp",
        "pinterest.com.au",
        "pinterest.co.kr",
        "pinterest.com.mx",
        "pinterest.ca",
        "pinterest.at",
        "pinterest.ch",
        "pinterest.se",
        "pinterest.dk",
        "pinterest.pt",
        "pinterest.nz",
        "*.pinterest.de",
        "*.pinterest.co.uk",
        "*.pinterest.fr",
    ],
    "linkedin": [
        "linkedin.com",
        "www.linkedin.com",
        "*.linkedin.com",
        "*.licdn.com",
        # Regional LinkedIn domains
        "linkedin.de",
        "linkedin.co.uk",
        "linkedin.fr",
        "linkedin.es",
        "linkedin.it",
        "linkedin.nl",
        "linkedin.ru",
        "linkedin.jp",
        "linkedin.com.br",
        "linkedin.co.in",
        "linkedin.cn",
        "*.linkedin.de",
        "*.linkedin.co.uk",
        "*.linkedin.fr",
    ],
    "tumblr": [
        "tumblr.com",
        "www.tumblr.com",
        "*.tumblr.com",
        "*.media.tumblr.com",
    ],
    
    # === MESSAGING ===
    "whatsapp": [
        "whatsapp.com",
        "www.whatsapp.com",
        "web.whatsapp.com",
        "*.whatsapp.com",
        "*.whatsapp.net",
        "wa.me",
        "*.wa.me",
    ],
    "telegram": [
        "telegram.org",
        "www.telegram.org",
        "*.telegram.org",
        "t.me",
        "*.t.me",
        "web.telegram.org",
        "*.telegram.me",
        "*.tdesktop.com",
    ],
    "discord": [
        "discord.com",
        "www.discord.com",
        "*.discord.com",
        "*.discord.gg",
        "*.discordapp.com",
        "*.discordapp.net",
        "discord.gg",
        "discordapp.com",
        "gateway.discord.gg",
        "cdn.discordapp.com",
    ],
    "signal": [
        "signal.org",
        "*.signal.org",
        "*.signal.art",
        "*.signalcaptchas.org",
    ],
    "viber": [
        "viber.com",
        "*.viber.com",
        "viber.me",
        "*.viber.me",
    ],
    "wechat": [
        "wechat.com",
        "*.wechat.com",
        "wechat.com.cn",
        "weixin.qq.com",
        "*.weixin.qq.com",
        "weixin.com",
        "*.weixin.com",
    ],
    "line": [
        "line.me",
        "*.line.me",
        "line.naver.jp",
        "*.line.naver.jp",
        "lineapp.me",
        "*.lineapp.me",
    ],
    
    # === MUSIC STREAMING ===
    "spotify": [
        "spotify.com",
        "www.spotify.com",
        "*.spotify.com",
        "*.spotifycdn.com",
        "*.scdn.co",
        "*.spotilocal.com",
        "api.spotify.com",
        "apresolve.spotify.com",
        "audio-ak-spotify-com.akamaized.net",
    ],
    "apple_music": [
        "music.apple.com",
        "*.music.apple.com",
    ],
    "soundcloud": [
        "soundcloud.com",
        "*.soundcloud.com",
        "*.sndcdn.com",
        "api.soundcloud.com",
    ],
    "deezer": [
        "deezer.com",
        "*.deezer.com",
        "*.dzcdn.net",
    ],
    "pandora": [
        "pandora.com",
        "*.pandora.com",
        "*.p-cdn.us",
    ],
    
    # === GAMING ===
    "google_play": [
        "play.google.com",
        "*.play.google.com",
        "play.googleapis.com",
        "play-fe.googleapis.com",
        "play-lh.googleusercontent.com",
        "prod-lt-playstoregatewayadapter-pa.googleapis.com",
    ],
    "steam": [
        "steampowered.com",
        "*.steampowered.com",
        "steamcommunity.com",
        "*.steamcommunity.com",
        "*.steamstatic.com",
        "*.steamcontent.com",
        "store.steampowered.com",
        "api.steampowered.com",
    ],
    "epicgames": [
        "epicgames.com",
        "*.epicgames.com",
        "*.unrealengine.com",
        "*.fortnite.com",
        "fortnite.com",
    ],
    "roblox": [
        "roblox.com",
        "*.roblox.com",
        "*.rbxcdn.com",
        "*.robloxlabs.com",
        "*.rbx.com",
    ],
    "minecraft": [
        "minecraft.net",
        "*.minecraft.net",
        "*.mojang.com",
        "mojang.com",
        "minecraft-services.net",
        "*.minecraft-services.net",
        "minecraftservices.com",
        "*.minecraftservices.com",
        "20ca2.playfabapi.com",
        "xforgeassets001.xboxlive.com",
        "xforgeassets002.xboxlive.com",
    ],
    "xbox": [
        "xbox.com",
        "*.xbox.com",
        "*.xboxlive.com",
        "xboxlive.com",
        "xboxservices.com",
        "*.xboxservices.com",
        "gamepass.com",
        "*.gamepass.com",
    ],
    "playstation": [
        "playstation.com",
        "*.playstation.com",
        "playstation.net",
        "*.playstation.net",
        "sonyentertainmentnetwork.com",
        "*.sonyentertainmentnetwork.com",
        "playstationnetwork.com",
        "*.playstationnetwork.com",
    ],
    "origin": [
        "origin.com",
        "*.origin.com",
        "*.ea.com",
        "ea.com",
    ],
    "battlenet": [
        "battle.net",
        "*.battle.net",
        "*.blizzard.com",
        "blizzard.com",
    ],
    
    # === DATING ===
    "tinder": [
        "tinder.com",
        "*.tinder.com",
        "*.gotinder.com",
    ],
    "bumble": [
        "bumble.com",
        "*.bumble.com",
    ],
    "badoo": [
        "badoo.com",
        "*.badoo.com",
        "badoo.app",
        "*.badoo.app",
        "badoocdn.com",
        "*.badoocdn.com",
    ],
    
    # === GAMBLING ===
    "gambling": [
        "*.bet",
        "*.casino",
        "*.poker",
        "*.gambling",
        "*.bet365.com",
        "bet365.com",
        "*.888.com",
        "*.pokerstars.com",
        "pokerstars.com",
        "*.williamhill.com",
        "*.unibet.com",
        "*.betfair.com",
        "*.draftkings.com",
        "*.fanduel.com",
    ],
    
    # === ADULT CONTENT ===
    "pornography": [
        # Heuristic matcher (handled by DeviceProfile.is_blacklisted)
        ADULT_HEURISTIC_MARKER,
        # TLD blocks
        "*.porn",
        "*.xxx",
        "*.adult",
        "*.sex",
        # Brand keyword patterns (match mirrors, AMP caches, and alt TLDs)
        "*pornhub*",
        "*xvideos*",
        "*xnxx*",
        "*xhamster*",
        "*youporn*",
        "*redtube*",
        "*spankbang*",
        "*tube8*",
        "*chaturbate*",
        "*stripchat*",
        "*livejasmin*",
        "*brazzers*",
        "*bangbros*",
        "*realitykings*",
        "*onlyfans*",
        "*fansly*",
        "*manyvids*",
        # Major sites
        "pornhub.com",
        "*.pornhub.com",
        "xvideos.com",
        "*.xvideos.com",
        "xnxx.com",
        "*.xnxx.com",
        "xhamster.com",
        "*.xhamster.com",
        "redtube.com",
        "*.redtube.com",
        "youporn.com",
        "*.youporn.com",
        "spankbang.com",
        "*.spankbang.com",
        "tube8.com",
        "*.tube8.com",
        "xvv1deos.com",
        "*.xvv1deos.com",
        "xvideos3.com",
        "*.xvideos3.com",
        "xvideos2.com",
        "*.xvideos2.com",
        "*.phncdn.com",
        "phncdn.com",
        "brazzersnetwork.com",
        "*.brazzersnetwork.com",
        "yaeby.channel",
        "*.yaeby.channel",
        "yaeby.work",
        "*.yaeby.work",
        "project1content.com",
        "*.project1content.com",
        "project1service.com",
        "*.project1service.com",
        "onlyfans.com",
        "*.onlyfans.com",
    ],
    
    # === NEWS & MEDIA ===
    "news": [
        "cnn.com",
        "*.cnn.com",
        "foxnews.com",
        "*.foxnews.com",
        "bbc.com",
        "*.bbc.com",
        "*.bbc.co.uk",
        "nytimes.com",
        "*.nytimes.com",
    ],
    
    # === BYPASS PROTECTION - VPN SERVICES ===
    "vpn": [
        # Major VPN providers
        "nordvpn.com", "*.nordvpn.com", "*.nordvpn.net",
        "expressvpn.com", "*.expressvpn.com", "*.xvpn.io",
        "surfshark.com", "*.surfshark.com",
        "cyberghostvpn.com", "*.cyberghostvpn.com",
        "privateinternetaccess.com", "*.privateinternetaccess.com", "*.piavpn.com",
        "protonvpn.com", "*.protonvpn.com", "*.protonvpn.net",
        "ipvanish.com", "*.ipvanish.com",
        "mullvad.net", "*.mullvad.net",
        "windscribe.com", "*.windscribe.com",
        "hotspotshield.com", "*.hotspotshield.com",
        "tunnelbear.com", "*.tunnelbear.com",
        "hidemyass.com", "*.hidemyass.com", "*.hma.com",
        "purevpn.com", "*.purevpn.com",
        "vyprvpn.com", "*.vyprvpn.com", "*.goldenfrog.com",
        "strongvpn.com", "*.strongvpn.com",
        "privatevpn.com", "*.privatevpn.com",
        "atlasvpn.com", "*.atlasvpn.com",
        "zenmate.com", "*.zenmate.com",
        "hide.me", "*.hide.me",
        "getoutline.org", "*.getoutline.org",
        "psiphon.ca", "*.psiphon.ca", "*.psiphon3.com",
        "lantern.io", "*.lantern.io", "*.getlantern.org",
        "betternet.co", "*.betternet.co",
        "speedify.com", "*.speedify.com",
        "ivpn.net", "*.ivpn.net",
        "airvpn.org", "*.airvpn.org",
        "astrill.com", "*.astrill.com",
        # Free VPN apps
        "1.1.1.1", "warp.cloudflare.com",
        "touch.vpn", "*.touchvpn.net",
        "freevpn.com", "*.freevpn.com",
        "vpnbook.com", "*.vpnbook.com",
        "openvpn.net", "*.openvpn.net",
        "wireguard.com", "*.wireguard.com",
        # Opera built-in VPN (SurfEasy) real tunnel hostnames.
        # General Opera browser endpoints (*.osp.opera.software, *.opera-api.com,
        # redirector/sitecheck/af.opera.com) are intentionally NOT matched: the browser
        # contacts them routinely even with the VPN OFF, which raised false "VPN bypass"
        # alerts. Only the SurfEasy tunnel hosts below indicate actual Opera VPN use.
        "opera-proxy.net", "*.opera-proxy.net",
        "api.sec-tunnel.com", "*.sec-tunnel.com",
        "surfeasy.com", "*.surfeasy.com",
    ],
    
    # === BYPASS PROTECTION - DNS-over-HTTPS (DoH) ===
    "doh": [
        # Major DoH providers - MUST block to prevent DNS bypass
        "cloudflare-dns.com", "*.cloudflare-dns.com",
        "1.1.1.1", "one.one.one.one",
        "dns.google", "dns.google.com", "*.dns.google",
        "8.8.8.8.dns.google", "8.8.4.4.dns.google",
        "dns.quad9.net", "*.dns.quad9.net",
        "doh.opendns.com", "*.opendns.com",
        "dns.adguard.com", "*.adguard-dns.com",
        "dns.nextdns.io", "*.nextdns.io",
        "doh.cleanbrowsing.org", "*.cleanbrowsing.org",
        "dns.controld.com", "*.controld.com",
        "freedns.controld.com",
        "wikimedia-dns.org", "*.wikimedia-dns.org",
        "mozilla.cloudflare-dns.com",
        "dns.alidns.com", "*.alidns.com",
        "doh.pub", "*.doh.pub",
        "dns.twnic.tw",
        "odvr.nic.cz",
        "doh.xfinity.com",
        "doh.cox.net",
        "dns.switch.ch",
        "dns.dnswarden.com",
    ],
    
    # === BYPASS PROTECTION - Tor & Anonymizers ===
    "tor": [
        # Tor project
        "torproject.org", "*.torproject.org",
        "*.onion",  # Onion addresses
        "*.tor.onion",
        "check.torproject.org",
        "bridges.torproject.org",
        "snowflake.torproject.org",
        "metrics.torproject.org",
        # Tor mirrors
        "tor.eff.org",
        "*.tb-manual.torproject.org",
        # I2P
        "geti2p.net", "*.geti2p.net",
        "*.i2p",
        # Other anonymizers
        "anonymouse.org",
        "anonymizer.com", "*.anonymizer.com",
        "megaproxy.com",
        "kproxy.com", "*.kproxy.com",
        "proxify.com", "*.proxify.com",
        "anonymox.net", "*.anonymox.net",
    ],
    
    # === BYPASS PROTECTION - Web Proxies ===
    "proxy": [
        # Web proxy services
        "hide.me/proxy",
        "hidemy.name", "*.hidemy.name",
        "proxysite.com", "*.proxysite.com",
        "croxyproxy.com", "*.croxyproxy.com",
        "webproxy.to",
        "filterbypass.me", "*.filterbypass.me",
        "unblockvideos.com",
        "unblock-websites.com",
        "unblocksites.online",
        "siteunblocker.co",
        "freeproxy.win",
        "blockaway.net",
        "vpnbook.com/webproxy",
        "4everproxy.com", "*.4everproxy.com",
        "free-proxy.cz",
        "proxylist.me",
        "proxyscrape.com",
        "spys.one",
        "geonode.com",
        "*.proxy-list.download",
        # Opera built-in VPN (SurfEasy) real proxy hostnames.
        # General Opera browser endpoints (*.osp.opera.software etc.) are intentionally
        # NOT matched here — the browser hits them with the VPN OFF (false positives).
        "opera-proxy.net", "*.opera-proxy.net",
        "api.sec-tunnel.com", "*.sec-tunnel.com",
        "surfeasy.com", "*.surfeasy.com",
    ],

    # === BYPASS PROTECTION - Smart DNS ===
    "smartdns": [
        "unlocator.com", "*.unlocator.com",
        "getflix.com.au", "*.getflix.com.au",
        "smartdnsproxy.com", "*.smartdnsproxy.com",
        "unotelly.com", "*.unotelly.com",
        "overplay.net", "*.overplay.net",
        "unblock-us.com", "*.unblock-us.com",
        "ironsocket.com", "*.ironsocket.com",
        "smartdns.com", "*.smartdns.com",
    ],
}

# Category groupings - block entire categories at once
SERVICE_CATEGORIES: Dict[str, List[str]] = {
    # Block ALL video streaming
    "streaming": [
        "youtube",
        "netflix", 
        "disney",
        "hulu",
        "hbo",
        "amazon_video",
        "twitch",
        "vimeo",
        "dailymotion",
    ],
    
    # Block ALL social media
    "social_media": [
        "facebook",
        "instagram", 
        "twitter",
        "tiktok",
        "snapchat",
        "reddit",
        "pinterest",
        "linkedin",
        "tumblr",
    ],
    
    # Block ALL messaging apps
    "messaging": [
        "whatsapp",
        "telegram",
        "discord",
        "signal",
        "messenger",
        "snapchat",
        "wechat",
        "viber",
        "line",
    ],
    
    # Block ALL music streaming
    "music": [
        "spotify",
        "apple_music",
        "soundcloud",
        "deezer",
        "pandora",
    ],
    
    # Block ALL gaming platforms
    "gaming": [
        "steam",
        "epicgames",
        "roblox",
        "minecraft",
        "xbox",
        "playstation",
        "origin",
        "battlenet",
    ],
    
    # Block ALL dating apps
    "dating": [
        "tinder",
        "bumble",
        "badoo",
    ],
    
    # Legacy alias retained for saved policies. Adult content must not
    # implicitly include gambling or dating; those are separate controls.
    "adult": [
        "pornography",
    ],
    
    # Entertainment - streaming + social + music
    "entertainment": [
        "youtube",
        "netflix",
        "disney",
        "hulu",
        "hbo",
        "amazon_video",
        "twitch",
        "spotify",
        "tiktok",
    ],
    
    # Distractions - social + gaming + entertainment
    "distractions": [
        "facebook",
        "instagram",
        "twitter",
        "tiktok",
        "snapchat",
        "reddit",
        "youtube",
        "twitch",
        "discord",
        "steam",
        "epicgames",
        "roblox",
    ],
    
    # ===== BYPASS PROTECTION =====
    # Block ALL methods to bypass parental controls
    "bypass": [
        "vpn",
        "doh",
        "tor",
        "proxy",
        "smartdns",
    ],
    
    # Strict parental mode - blocks all bypass + adult + distractions
    "strict_parental": [
        "vpn",
        "doh", 
        "tor",
        "proxy",
        "smartdns",
        "pornography",
        "gambling",
        "dating",
        "facebook",
        "instagram",
        "twitter",
        "tiktok",
        "snapchat",
        "reddit",
        "youtube",
        "twitch",
        "discord",
        "steam",
        "epicgames",
        "roblox",
    ],
}


def _normalize_service_domains(domains: Set[str]) -> List[str]:
    """
    Normalize service domains for matching.

    - Lowercase
    - Strip trailing dot
    - Preserve wildcard TLDs (e.g., "*.porn") for explicit TLD blocking
    - Collapse wildcard subdomains (e.g., "*.example.com" -> "example.com")

    Note: Profile blacklist matching supports wildcards. We only collapse
    wildcards for normal domains to reduce list size, but keep TLD wildcards
    so adult TLDs like ".porn" still block.
    """
    normalized: Set[str] = set()
    for raw in domains:
        if not raw:
            continue
        domain = raw.strip().lower().rstrip(".")
        if not domain:
            continue
        if domain.startswith("*."):
            base = domain[2:]
            if not base:
                continue
            # Keep wildcard for TLD patterns like "*.porn"
            if "." not in base:
                normalized.add(domain)
            else:
                normalized.add(base)
            continue
        normalized.add(domain)
    return list(normalized)


def get_domains_for_service(service: str) -> List[str]:
    """
    Get all domains for a service or category.
    
    Args:
        service: Service name (e.g., 'youtube', 'netflix') or 
                 category name (e.g., 'streaming', 'social_media')
    
    Returns:
        List of domains to block
    """
    service_lower = service.strip().lower()
    # Normalize IP-only selector to DNS service name
    if service_lower.endswith("_ip"):
        service_lower = service_lower[:-3]
    domains: Set[str] = set()
    
    # Check if it's a category
    if service_lower in SERVICE_CATEGORIES:
        for svc in SERVICE_CATEGORIES[service_lower]:
            if svc in SERVICE_DOMAINS:
                domains.update(SERVICE_DOMAINS[svc])
    
    # Check if it's an individual service
    elif service_lower in SERVICE_DOMAINS:
        domains.update(SERVICE_DOMAINS[service_lower])
    
    return _normalize_service_domains(domains)


def get_all_domains_for_services(services: List[str]) -> List[str]:
    """
    Get all domains for a list of services/categories.
    
    Args:
        services: List of service names or category names
    
    Returns:
        List of unique domains to block
    """
    domains: Set[str] = set()
    
    for service in services:
        domains.update(get_domains_for_service(service))
    
    return list(domains)


def get_available_services() -> Dict[str, List[str]]:
    """Get dictionary of available services."""
    return SERVICE_DOMAINS.copy()


def get_catalog_services() -> List[str]:
    """Return individual services exposed by the parental-control UI/API."""
    return sorted(set(SERVICE_DOMAINS).difference(SERVICE_CATALOG_EXCLUSIONS))


def get_catalog_categories() -> List[str]:
    """Return service groups exposed by the parental-control UI/API."""
    return sorted(
        set(SERVICE_CATEGORIES).difference(SERVICE_CATEGORY_CATALOG_EXCLUSIONS)
    )


def get_available_categories() -> Dict[str, List[str]]:
    """Get dictionary of available categories."""
    return SERVICE_CATEGORIES.copy()


def is_valid_service(service: str) -> bool:
    """Check if service or category exists."""
    service_lower = service.strip().lower()
    return service_lower in SERVICE_DOMAINS or service_lower in SERVICE_CATEGORIES
