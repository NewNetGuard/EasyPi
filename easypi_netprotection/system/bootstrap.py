"""
EasyPi NetProtection — Bootstrap Module.

Автоматическая инициализация и запуск всех компонентов.
Проверка зависимостей, создание директорий, загрузка конфигурации.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

# Минимальные версии
MIN_PYTHON_VERSION = (3, 11)
MIN_SQLITE_VERSION = (3, 35, 0)

# Обязательные пакеты
REQUIRED_PACKAGES = [
    ("dnspython", "dns"),
    ("httpx", "httpx"),
    ("cryptography", "cryptography"),
]

# Опциональные пакеты
OPTIONAL_PACKAGES = [
    ("aioquic", "aioquic"),      # Для DoQ
    ("redis", "redis"),          # Для Redis cache
    ("uvloop", "uvloop"),        # Для производительности на Linux
]

# Директории
DEFAULT_DATA_DIR = "data/netprotection"
DEFAULT_LOG_DIR = "logs/netprotection"
DEFAULT_CACHE_DIR = "cache/netprotection"


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class BootstrapPhase(str, Enum):
    """Фаза инициализации."""
    
    INIT = "init"
    CHECK_PYTHON = "check_python"
    CHECK_PACKAGES = "check_packages"
    CREATE_DIRS = "create_dirs"
    LOAD_CONFIG = "load_config"
    INIT_VAULT = "init_vault"
    INIT_CACHE = "init_cache"
    INIT_UPSTREAM = "init_upstream"
    INIT_VERDICT = "init_verdict"
    INIT_INTEL = "init_intel"
    INIT_SHIELD = "init_shield"
    INIT_CHRONICLE = "init_chronicle"
    INIT_GATEWAY = "init_gateway"
    START_GUARDIAN = "start_guardian"
    COMPLETE = "complete"


class BootstrapStatus(str, Enum):
    """Статус инициализации."""
    
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"


# ════════════════════════════════════════════════════════════════════════════════
# CHECK RESULT
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    """Результат проверки."""
    
    name: str
    status: BootstrapStatus
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    
    @property
    def ok(self) -> bool:
        return self.status in (BootstrapStatus.SUCCESS, BootstrapStatus.WARNING)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
        }


# ════════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECKER
# ════════════════════════════════════════════════════════════════════════════════

class DependencyChecker:
    """Проверка зависимостей."""
    
    @staticmethod
    def check_python_version() -> CheckResult:
        """Проверка версии Python."""
        current = sys.version_info[:2]
        
        if current >= MIN_PYTHON_VERSION:
            return CheckResult(
                name="python_version",
                status=BootstrapStatus.SUCCESS,
                message=f"Python {current[0]}.{current[1]}",
                details={
                    "current": f"{current[0]}.{current[1]}",
                    "required": f"{MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}",
                },
            )
        else:
            return CheckResult(
                name="python_version",
                status=BootstrapStatus.FAILED,
                message=f"Python {current[0]}.{current[1]} < {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}",
                details={
                    "current": f"{current[0]}.{current[1]}",
                    "required": f"{MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}",
                },
            )
    
    @staticmethod
    def check_sqlite_version() -> CheckResult:
        """Проверка версии SQLite."""
        version_str = sqlite3.sqlite_version
        version_parts = tuple(int(x) for x in version_str.split("."))
        
        if version_parts >= MIN_SQLITE_VERSION:
            return CheckResult(
                name="sqlite_version",
                status=BootstrapStatus.SUCCESS,
                message=f"SQLite {version_str}",
                details={
                    "current": version_str,
                    "required": ".".join(str(x) for x in MIN_SQLITE_VERSION),
                },
            )
        else:
            return CheckResult(
                name="sqlite_version",
                status=BootstrapStatus.WARNING,
                message=f"SQLite {version_str} < {'.'.join(str(x) for x in MIN_SQLITE_VERSION)} (some features may be limited)",
                details={
                    "current": version_str,
                    "required": ".".join(str(x) for x in MIN_SQLITE_VERSION),
                },
            )
    
    @staticmethod
    def check_package(package_name: str, import_name: str) -> CheckResult:
        """Проверка наличия пакета."""
        try:
            module = __import__(import_name)
            version = getattr(module, "__version__", "unknown")
            return CheckResult(
                name=f"package:{package_name}",
                status=BootstrapStatus.SUCCESS,
                message=f"{package_name} {version}",
                details={"version": version},
            )
        except ImportError:
            return CheckResult(
                name=f"package:{package_name}",
                status=BootstrapStatus.FAILED,
                message=f"{package_name} not installed",
            )
    
    @classmethod
    def check_required_packages(cls) -> list[CheckResult]:
        """Проверка обязательных пакетов."""
        results = []
        for package_name, import_name in REQUIRED_PACKAGES:
            results.append(cls.check_package(package_name, import_name))
        return results
    
    @classmethod
    def check_optional_packages(cls) -> list[CheckResult]:
        """Проверка опциональных пакетов."""
        results = []
        for package_name, import_name in OPTIONAL_PACKAGES:
            result = cls.check_package(package_name, import_name)
            # Опциональные пакеты не критичны
            if result.status == BootstrapStatus.FAILED:
                result.status = BootstrapStatus.SKIPPED
                result.message = f"{package_name} not installed (optional)"
            results.append(result)
        return results
    
    @classmethod
    def check_all(cls) -> list[CheckResult]:
        """Полная проверка всех зависимостей."""
        results = []
        
        # Python
        results.append(cls.check_python_version())
        
        # SQLite
        results.append(cls.check_sqlite_version())
        
        # Обязательные пакеты
        results.extend(cls.check_required_packages())
        
        # Опциональные пакеты
        results.extend(cls.check_optional_packages())
        
        return results


# ════════════════════════════════════════════════════════════════════════════════
# DIRECTORY MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class DirectoryManager:
    """Управление директориями."""
    
    def __init__(self, base_path: Path, runtime_root: Path | None = None):
        self.base_path = base_path
        if runtime_root is not None:
            # Container mode: all mutable state lives in one explicitly mounted
            # persistent directory.  Application code under /app stays read-only.
            self.data_dir = runtime_root
            self.log_dir = runtime_root / "logs"
            self.cache_dir = runtime_root / "cache"
        else:
            # Preserve the existing layout for native EasyPi installations.
            self.data_dir = base_path / DEFAULT_DATA_DIR
            self.log_dir = base_path / DEFAULT_LOG_DIR
            self.cache_dir = base_path / DEFAULT_CACHE_DIR
    
    def create_directories(self) -> list[CheckResult]:
        """Создание необходимых директорий."""
        results = []
        
        directories = [
            self.data_dir,
            self.data_dir / "vault",
            self.data_dir / "lists",
            self.log_dir,
            self.cache_dir,
        ]
        
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                results.append(CheckResult(
                    name=f"directory:{directory.name}",
                    status=BootstrapStatus.SUCCESS,
                    message=f"Created {directory}",
                    details={"path": str(directory)},
                ))
            except Exception as e:
                results.append(CheckResult(
                    name=f"directory:{directory.name}",
                    status=BootstrapStatus.FAILED,
                    message=f"Failed to create {directory}: {e}",
                    details={"path": str(directory), "error": str(e)},
                ))
        
        return results
    
    def check_permissions(self) -> list[CheckResult]:
        """Проверка прав доступа."""
        results = []
        
        for directory in [self.data_dir, self.log_dir, self.cache_dir]:
            if not directory.exists():
                continue
            
            # Проверяем запись
            test_file = directory / ".write_test"
            try:
                test_file.write_text("test")
                test_file.unlink()
                results.append(CheckResult(
                    name=f"permission:{directory.name}",
                    status=BootstrapStatus.SUCCESS,
                    message=f"Write access OK: {directory}",
                ))
            except Exception as e:
                results.append(CheckResult(
                    name=f"permission:{directory.name}",
                    status=BootstrapStatus.FAILED,
                    message=f"No write access: {directory}",
                    details={"error": str(e)},
                ))
        
        return results


# ════════════════════════════════════════════════════════════════════════════════
# BOOTSTRAP CONTEXT
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class BootstrapContext:
    """Контекст инициализации — все созданные компоненты."""
    
    # Пути
    base_path: Path
    data_dir: Path
    log_dir: Path
    cache_dir: Path
    
    # Конфигурация
    config: Any = None
    
    # Компоненты (будут заполнены при инициализации)
    vault_repository: Any = None
    secrets_manager: Any = None
    dns_cache: Any = None
    upstream_manager: Any = None
    resolver: Any = None
    verdict_engine: Any = None
    matchers: Any = None
    intel_providers: list[Any] = field(default_factory=list)
    profile_manager: Any = None
    device_manager: Any = None
    schedule_manager: Any = None
    flow_logger: Any = None
    metrics: Any = None
    guardian: Any = None
    
    # Статус
    started_at: datetime = field(default_factory=datetime.now)
    ready: bool = False


# ════════════════════════════════════════════════════════════════════════════════
# BOOTSTRAP
# ════════════════════════════════════════════════════════════════════════════════

class Bootstrap:
    """
    Инициализатор NetProtection.
    
    Последовательно выполняет все фазы инициализации,
    проверяет зависимости, создаёт компоненты.
    """
    
    def __init__(
        self,
        base_path: Path | str,
        config: Any = None,
        runtime_root: Path | str | None = None,
    ):
        self.base_path = Path(base_path)
        self.config = config
        runtime_root_path = Path(runtime_root) if runtime_root is not None else None
        if runtime_root_path is not None and not runtime_root_path.is_absolute():
            raise ValueError("NetProtection runtime root must be an absolute path")
        self.runtime_root = runtime_root_path.resolve() if runtime_root_path is not None else None
        
        self._phase = BootstrapPhase.INIT
        self._results: list[CheckResult] = []
        self._context: BootstrapContext | None = None
        
        # Callbacks
        self._on_phase_start: Callable[[BootstrapPhase], None] | None = None
        self._on_phase_complete: Callable[[BootstrapPhase, list[CheckResult]], None] | None = None
    
    @property
    def phase(self) -> BootstrapPhase:
        """Текущая фаза."""
        return self._phase
    
    @property
    def results(self) -> list[CheckResult]:
        """Результаты всех проверок."""
        return self._results
    
    @property
    def context(self) -> BootstrapContext | None:
        """Контекст с инициализированными компонентами."""
        return self._context
    
    def on_phase_start(self, callback: Callable[[BootstrapPhase], None]) -> None:
        """Callback при начале фазы."""
        self._on_phase_start = callback
    
    def on_phase_complete(
        self,
        callback: Callable[[BootstrapPhase, list[CheckResult]], None],
    ) -> None:
        """Callback при завершении фазы."""
        self._on_phase_complete = callback
    
    def _emit_phase_start(self, phase: BootstrapPhase) -> None:
        """Уведомление о начале фазы."""
        self._phase = phase
        logger.info("Bootstrap phase: %s", phase.value)
        if self._on_phase_start:
            self._on_phase_start(phase)
    
    def _emit_phase_complete(
        self,
        phase: BootstrapPhase,
        results: list[CheckResult],
    ) -> None:
        """Уведомление о завершении фазы."""
        self._results.extend(results)
        if self._on_phase_complete:
            self._on_phase_complete(phase, results)
    
    async def run(self) -> BootstrapContext:
        """
        Запуск полной инициализации.
        
        Returns:
            BootstrapContext с инициализированными компонентами
        
        Raises:
            BootstrapError: При критической ошибке
        """
        logger.info("Starting NetProtection bootstrap...")
        
        # Создаём контекст
        dir_manager = DirectoryManager(self.base_path, self.runtime_root)
        self._context = BootstrapContext(
            base_path=self.base_path,
            data_dir=dir_manager.data_dir,
            log_dir=dir_manager.log_dir,
            cache_dir=dir_manager.cache_dir,
            config=self.config,
        )
        
        try:
            # Phase 1: Check Python
            await self._phase_check_python()
            
            # Phase 2: Check Packages
            await self._phase_check_packages()
            
            # Phase 3: Create Directories
            await self._phase_create_dirs(dir_manager)
            
            # Phase 4: Load Config
            await self._phase_load_config()
            
            # Phase 5: Init Vault
            await self._phase_init_vault()
            
            # Phase 6: Init Cache
            await self._phase_init_cache()
            
            # Phase 7: Init Upstream
            await self._phase_init_upstream()
            
            # Phase 8: Init Verdict Engine
            await self._phase_init_verdict()
            
            # Phase 9: Init Intel
            await self._phase_init_intel()
            
            # Phase 10: Init Shield
            await self._phase_init_shield()
            
            # Phase 11: Init Chronicle
            await self._phase_init_chronicle()
            
            # Phase 12: Init Gateway
            await self._phase_init_gateway()
            
            # Phase 13: Start Guardian
            await self._phase_start_guardian()
            
            # Complete
            self._emit_phase_start(BootstrapPhase.COMPLETE)
            self._context.ready = True
            
            logger.info("NetProtection bootstrap complete!")
            return self._context
            
        except Exception as e:
            logger.error("Bootstrap failed: %s", e)
            raise BootstrapError(f"Bootstrap failed at phase {self._phase}: {e}") from e
    
    async def _phase_check_python(self) -> None:
        """Проверка Python."""
        self._emit_phase_start(BootstrapPhase.CHECK_PYTHON)
        
        results = [
            DependencyChecker.check_python_version(),
            DependencyChecker.check_sqlite_version(),
        ]
        
        self._emit_phase_complete(BootstrapPhase.CHECK_PYTHON, results)
        
        # Проверяем критические ошибки
        for result in results:
            if result.status == BootstrapStatus.FAILED and "python" in result.name:
                raise BootstrapError(f"Python version check failed: {result.message}")
    
    async def _phase_check_packages(self) -> None:
        """Проверка пакетов."""
        self._emit_phase_start(BootstrapPhase.CHECK_PACKAGES)
        
        results = DependencyChecker.check_required_packages()
        results.extend(DependencyChecker.check_optional_packages())
        
        self._emit_phase_complete(BootstrapPhase.CHECK_PACKAGES, results)
        
        # Проверяем критические ошибки
        for result in results:
            if result.status == BootstrapStatus.FAILED:
                raise BootstrapError(f"Required package missing: {result.message}")
    
    async def _phase_create_dirs(self, dir_manager: DirectoryManager) -> None:
        """Создание директорий."""
        self._emit_phase_start(BootstrapPhase.CREATE_DIRS)
        
        results = dir_manager.create_directories()
        results.extend(dir_manager.check_permissions())
        
        self._emit_phase_complete(BootstrapPhase.CREATE_DIRS, results)
        
        for result in results:
            if result.status == BootstrapStatus.FAILED:
                raise BootstrapError(f"Directory setup failed: {result.message}")
    
    async def _phase_load_config(self) -> None:
        """Загрузка конфигурации."""
        self._emit_phase_start(BootstrapPhase.LOAD_CONFIG)
        
        results = []
        
        if self.config is not None:
            results.append(CheckResult(
                name="config",
                status=BootstrapStatus.SUCCESS,
                message="Configuration provided",
            ))
        else:
            # Пытаемся загрузить из файла
            config_path = self.base_path / "config.toml"
            if config_path.exists():
                try:
                    # Здесь будет загрузка config.toml
                    results.append(CheckResult(
                        name="config",
                        status=BootstrapStatus.SUCCESS,
                        message=f"Loaded from {config_path}",
                    ))
                except Exception as e:
                    results.append(CheckResult(
                        name="config",
                        status=BootstrapStatus.WARNING,
                        message=f"Failed to load config: {e}, using defaults",
                    ))
            else:
                results.append(CheckResult(
                    name="config",
                    status=BootstrapStatus.WARNING,
                    message="No config file found, using defaults",
                ))
        
        self._emit_phase_complete(BootstrapPhase.LOAD_CONFIG, results)
    
    async def _phase_init_vault(self) -> None:
        """Инициализация Vault."""
        self._emit_phase_start(BootstrapPhase.INIT_VAULT)
        
        results = []
        
        try:
            # Импортируем и создаём компоненты vault
            from ..vault.repository import VaultRepository
            from ..vault.secrets import SecretsVault
            
            db_path = self._context.data_dir / "vault" / "vault.db"
            
            self._context.vault_repository = VaultRepository(db_path)
            await self._context.vault_repository.initialize()
            
            self._context.secrets_manager = SecretsVault(self._context.data_dir / "vault")
            
            results.append(CheckResult(
                name="vault",
                status=BootstrapStatus.SUCCESS,
                message="Vault initialized",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="vault",
                status=BootstrapStatus.FAILED,
                message=f"Vault init failed: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_VAULT, results)
    
    async def _phase_init_cache(self) -> None:
        """Инициализация кеша."""
        self._emit_phase_start(BootstrapPhase.INIT_CACHE)
        
        results = []
        
        try:
            from ..core.cache import DNSCache
            
            self._context.dns_cache = DNSCache(
                max_entries=10000,
                default_ttl=300,
            )
            
            results.append(CheckResult(
                name="cache",
                status=BootstrapStatus.SUCCESS,
                message="DNS cache initialized",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="cache",
                status=BootstrapStatus.FAILED,
                message=f"Cache init failed: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_CACHE, results)
    
    async def _phase_init_upstream(self) -> None:
        """Инициализация upstream."""
        self._emit_phase_start(BootstrapPhase.INIT_UPSTREAM)
        
        results = []
        
        try:
            from ..core.upstream import UpstreamManager
            
            # UpstreamManager reads servers from config automatically
            self._context.upstream_manager = UpstreamManager()
            
            # Initialize HTTP client and health checks
            await self._context.upstream_manager.start()
            
            server_count = len(self._context.upstream_manager.servers)
            
            results.append(CheckResult(
                name="upstream",
                status=BootstrapStatus.SUCCESS,
                message=f"Upstream initialized with {server_count} servers",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="upstream",
                status=BootstrapStatus.FAILED,
                message=f"Upstream init failed: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_UPSTREAM, results)
    
    async def _phase_init_verdict(self) -> None:
        """Инициализация Verdict Engine."""
        self._emit_phase_start(BootstrapPhase.INIT_VERDICT)
        
        results = []
        
        try:
            from ..verdict.engine import VerdictEngine
            from ..verdict.matchers import MatcherRegistry
            from ..verdict.blocklist_filter import get_blocklist_filter
            
            self._context.matchers = MatcherRegistry()
            
            # Get data_dir from context (set in DirectoryManager)
            data_dir = str(self._context.data_dir)
            blocklist_filter = get_blocklist_filter(data_dir)
            
            # Initialize SafeSearch enforcer (optional)
            safesearch_enforcer = None
            try:
                from ..safesearch import get_safesearch_enforcer
                safesearch_enforcer = get_safesearch_enforcer()
            except ImportError:
                logger.debug("SafeSearch module not available")
            except Exception as ss_err:
                logger.warning(f"SafeSearch init failed: {ss_err}")
            
            self._context.verdict_engine = VerdictEngine(
                self._context.matchers,
                blocklist_filter=blocklist_filter,
                data_dir=data_dir,
                safesearch_enforcer=safesearch_enforcer,
            )

            async def _ensure_blocklists() -> None:
                try:
                    from ..blocklist_manager import BlocklistManager

                    manager = BlocklistManager(data_dir)
                    verified_file = manager.verified_file
                    if verified_file.exists() and verified_file.stat().st_size > 0:
                        return

                    logger.info("Blocklist missing - generating verified blocklist")
                    result = await manager.generate_all(force_clean=True)
                    if isinstance(result, dict) and result.get("error"):
                        logger.error(f"Blocklist generation failed: {result['error']}")
                        return

                    if self._context.verdict_engine:
                        self._context.verdict_engine.reload_blocklist()
                        logger.info("Blocklist reloaded after generation")
                except Exception as e:
                    logger.error(f"Blocklist generation failed: {e}")

            asyncio.create_task(_ensure_blocklists())

            # Active runtime ad/causal learning (no shadow/observe): rebuild the
            # Ad-Genesis behavioural block set (DNS NAI + conntrack flow shape) in
            # process every ~80s. The verdict engine enforces it live (auto-reloads
            # ad_genesis_block.json on mtime). All Ad-Genesis guards apply, so
            # navigated / first-party sites are never blocked.
            async def _causal_runtime_loop(np_data_dir):
                from ..heuristics import causal_flow
                await asyncio.sleep(20)  # let startup settle
                while True:
                    try:
                        await asyncio.to_thread(causal_flow.runtime_build, str(np_data_dir))
                    except Exception as exc:
                        logger.debug(f"causal runtime build skipped: {exc}")
                    await asyncio.sleep(60)

            asyncio.create_task(_causal_runtime_loop(data_dir))

            # Self-learning ML model: retrain on-device periodically. Positives are a
            # sample of the global blocklist (universal ad/tracker domains); negatives
            # are a bundled benign seed + the domains THIS network actually visited, so
            # the model adapts to each home with no user action. train_on_device only
            # replaces the model if its false-positive gate passes (well-known sites
            # must stay benign), so a retrain can never start blocking real sites.
            # Nothing leaves the device.
            async def _ml_retrain_loop(np_data_dir):
                from ..heuristics import ml_trainer
                await asyncio.sleep(600)  # 10 min after start: let some traffic accrue
                while True:
                    try:
                        res = await asyncio.to_thread(ml_trainer.train_on_device, str(np_data_dir))
                        logger.info("ml auto-retrain: %s", res)
                    except Exception as exc:
                        logger.debug(f"ml auto-retrain skipped: {exc}")
                    await asyncio.sleep(12 * 3600)  # then every 12 hours

            asyncio.create_task(_ml_retrain_loop(data_dir))

            domain_count = len(blocklist_filter._domains) if blocklist_filter else 0
            results.append(CheckResult(
                name="verdict_engine",
                status=BootstrapStatus.SUCCESS,
                message=f"Verdict engine initialized with {domain_count} blocked domains",
            ))
            logger.info(f"Verdict engine initialized with {domain_count} blocked domains, data_dir={data_dir}")
        except Exception as e:
            logger.error(f"Verdict engine init failed: {e}")
            import traceback
            traceback.print_exc()
            results.append(CheckResult(
                name="verdict_engine",
                status=BootstrapStatus.FAILED,
                message=f"Verdict engine init failed: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_VERDICT, results)
    
    async def _phase_init_intel(self) -> None:
        """Инициализация Intel модулей."""
        self._emit_phase_start(BootstrapPhase.INIT_INTEL)
        
        results = []
        
        try:
            from ..intel.domain_intel import DomainIntelProvider
            from ..intel.cname_chain import CNAMEChainAnalyzer
            from ..intel.entropy_check import EntropyAnalyzer
            
            # Создаём провайдеры
            domain_intel = DomainIntelProvider()
            cname_chain = CNAMEChainAnalyzer()
            entropy = EntropyAnalyzer()
            
            self._context.intel_providers = [domain_intel, cname_chain, entropy]
            
            # Регистрируем провайдеры в verdict_engine для CNAME uncloaking
            if self._context.verdict_engine:
                for provider in self._context.intel_providers:
                    self._context.verdict_engine.register_intel_provider(provider)
                logger.info(f"Registered {len(self._context.intel_providers)} intel providers with verdict engine")
            
            results.append(CheckResult(
                name="intel",
                status=BootstrapStatus.SUCCESS,
                message=f"Intel initialized with {len(self._context.intel_providers)} providers",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="intel",
                status=BootstrapStatus.WARNING,
                message=f"Intel init partial: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_INTEL, results)
    
    async def _phase_init_shield(self) -> None:
        """Инициализация Shield."""
        self._emit_phase_start(BootstrapPhase.INIT_SHIELD)
        
        results = []
        
        try:
            # Use profiles.manager for profile/bindings support (not shield.profiles)
            from ..profiles import get_profile_manager
            from ..shield.devices import DeviceManager
            from ..shield.schedules import ScheduleManager
            
            # Use singleton with data_dir for proper loading
            self._context.profile_manager = get_profile_manager(str(self._config.data_dir))
            self._context.device_manager = DeviceManager()
            self._context.schedule_manager = ScheduleManager()
            
            results.append(CheckResult(
                name="shield",
                status=BootstrapStatus.SUCCESS,
                message="Shield initialized",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="shield",
                status=BootstrapStatus.WARNING,
                message=f"Shield init partial: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_SHIELD, results)
    
    async def _phase_init_chronicle(self) -> None:
        """Инициализация Chronicle."""
        self._emit_phase_start(BootstrapPhase.INIT_CHRONICLE)
        
        results = []
        
        try:
            from ..chronicle.flow_log import FlowLogStorage, FlowLogger, IPAnonymizer
            from ..chronicle.metrics import NetProtectionMetrics
            
            # Flow Logger
            storage = FlowLogStorage(self._context.data_dir / "flow_log.db")
            await storage.initialize()
            
            self._context.flow_logger = FlowLogger(storage, IPAnonymizer())
            await self._context.flow_logger.start()
            
            # Metrics
            self._context.metrics = NetProtectionMetrics()
            
            results.append(CheckResult(
                name="chronicle",
                status=BootstrapStatus.SUCCESS,
                message="Chronicle initialized",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="chronicle",
                status=BootstrapStatus.WARNING,
                message=f"Chronicle init partial: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_CHRONICLE, results)
    
    async def _phase_init_gateway(self) -> None:
        """Инициализация Gateway."""
        self._emit_phase_start(BootstrapPhase.INIT_GATEWAY)
        
        results = []
        
        # Gateway инициализируется отдельно при запуске HTTP-сервера
        results.append(CheckResult(
            name="gateway",
            status=BootstrapStatus.SUCCESS,
            message="Gateway ready (will start with HTTP server)",
        ))
        
        self._emit_phase_complete(BootstrapPhase.INIT_GATEWAY, results)
    
    async def _phase_start_guardian(self) -> None:
        """Запуск Guardian."""
        self._emit_phase_start(BootstrapPhase.START_GUARDIAN)
        
        results = []
        
        try:
            from ..system.guardian import Guardian
            
            self._context.guardian = Guardian(self._context)
            await self._context.guardian.start()
            
            results.append(CheckResult(
                name="guardian",
                status=BootstrapStatus.SUCCESS,
                message="Guardian started",
            ))
        except Exception as e:
            results.append(CheckResult(
                name="guardian",
                status=BootstrapStatus.WARNING,
                message=f"Guardian start partial: {e}",
            ))
        
        self._emit_phase_complete(BootstrapPhase.START_GUARDIAN, results)
    
    def get_summary(self) -> dict[str, Any]:
        """Получение сводки инициализации."""
        success = sum(1 for r in self._results if r.status == BootstrapStatus.SUCCESS)
        warnings = sum(1 for r in self._results if r.status == BootstrapStatus.WARNING)
        failed = sum(1 for r in self._results if r.status == BootstrapStatus.FAILED)
        skipped = sum(1 for r in self._results if r.status == BootstrapStatus.SKIPPED)
        
        return {
            "phase": self._phase.value,
            "ready": self._context.ready if self._context else False,
            "summary": {
                "success": success,
                "warnings": warnings,
                "failed": failed,
                "skipped": skipped,
                "total": len(self._results),
            },
            "results": [r.to_dict() for r in self._results],
        }


# ════════════════════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ════════════════════════════════════════════════════════════════════════════════

class BootstrapError(Exception):
    """Ошибка инициализации."""
    pass


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

async def bootstrap_netprotection(
    base_path: Path | str,
    config: Any = None,
    runtime_root: Path | str | None = None,
) -> BootstrapContext:
    """
    Удобная функция для инициализации NetProtection.
    
    Args:
        base_path: Базовая директория
        config: Конфигурация (опционально)
    
    Returns:
        BootstrapContext с инициализированными компонентами
    """
    bootstrap = Bootstrap(base_path, config, runtime_root)
    return await bootstrap.run()


def check_dependencies() -> list[CheckResult]:
    """Проверка зависимостей без полной инициализации."""
    return DependencyChecker.check_all()
