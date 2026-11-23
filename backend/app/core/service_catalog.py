"""Service catalog loader from JSON file."""
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.paths import get_backend_data_dir

logger = logging.getLogger(__name__)


class ServiceCatalog:
    """Load and manage service metadata from a JSON catalog file."""

    def __init__(self, catalog_path: Optional[str] = None):
        """Initialize the catalog from a JSON file.
        
        Args:
            catalog_path: Path to the services.json file. If None, uses SERVICES_CATALOG env or default.
        """
        if catalog_path is None:
            catalog_path = os.getenv(
                "SERVICES_CATALOG",
                str(get_backend_data_dir() / "services.json"),
            )
        
        self.catalog_path = Path(catalog_path)
        self._data: List[Dict[str, Any]] = []
        self._loaded = False
        self._load()

    def _load(self) -> None:
        """Load services from JSON file."""
        if not self.catalog_path.exists():
            logger.warning("Services catalog not found at %s", self.catalog_path)
            return
        
        try:
            with open(self.catalog_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Expect a list of service objects
                if isinstance(data, list):
                    self._data = data
                elif isinstance(data, dict) and 'services' in data:
                    self._data = data['services']
                else:
                    self._data = []
            self._loaded = True
            logger.info("Loaded %d services from catalog", len(self._data))
        except json.JSONDecodeError as e:
            logger.error("Failed to parse services catalog: %s", e)
        except Exception as e:
            logger.error("Failed to load services catalog: %s", e)

    def all(self) -> List[Dict[str, Any]]:
        """Return all services."""
        return self._data

    def get(self, slug: str) -> Optional[Dict[str, Any]]:
        """Get a service by slug (id field)."""
        for entry in self._data:
            if entry.get('id') == slug:
                return entry
        return None
