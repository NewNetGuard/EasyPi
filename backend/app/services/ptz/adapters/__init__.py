"""Real PTZ adapters. Importing this package registers them with the registry.

Kept out of the registry's import path (loaded lazily by
``registry._ensure_adapters_loaded``) to avoid an import cycle.
"""
from app.services.ptz.adapters.onvif import OnvifPTZAdapter
from app.services.ptz.adapters.thingino import ThinginoPTZAdapter
from app.services.ptz.registry import register_adapter

register_adapter("onvif", OnvifPTZAdapter)
register_adapter("thingino", ThinginoPTZAdapter)

__all__ = ["OnvifPTZAdapter", "ThinginoPTZAdapter"]
