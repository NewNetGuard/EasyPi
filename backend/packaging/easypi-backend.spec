# EasyPi Backend Binary Build - PyInstaller spec
# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for EasyPi Backend.

This spec file defines how to build the native binary.
Run with: pyinstaller easypi-backend.spec
"""

import sys
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# Project paths - find them relative to this spec file's original location
# When spec is in backend/packaging/, we need to go up to find backend/
if 'BACKEND_DIR' in os.environ:
    BACKEND_DIR = Path(os.environ['BACKEND_DIR'])
    PROJECT_ROOT = BACKEND_DIR.parent
else:
    # Fallback: assume we're somewhere in the build tree
    # Look for backend directory by searching upwards
    current = Path(SPECPATH).parent
    while current != current.parent:
        if (current / 'app').exists() and (current / 'main.py').exists():
            BACKEND_DIR = current
            PROJECT_ROOT = current.parent
            break
        current = current.parent
    else:
        # Last resort: hardcoded relative path
        BACKEND_DIR = Path(SPECPATH).parent.parent.parent / 'backend'
        PROJECT_ROOT = BACKEND_DIR.parent

# Hidden-module discovery happens before Analysis(pathex=...). Ensure isolated
# hook discovery can see reviewed repository-root packages from backend cwd.
sys.path[:0] = [str(PROJECT_ROOT), str(BACKEND_DIR)]

block_cipher = None

# Hidden imports that PyInstaller might miss
hidden_imports = [
    # Uvicorn internals
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.loops.asyncio',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.http.httptools_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.websockets_impl',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'uvicorn.lifespan.off',
    
    # ASGI/HTTP
    'httptools',
    'watchfiles',
    'websockets',
    'h11',
    
    # Database
    'sqlalchemy',
    'sqlalchemy.dialects.sqlite',
    'sqlalchemy.sql.default_comparator',
    'aiosqlite',
    
    # FastAPI/Pydantic
    'pydantic',
    'pydantic_settings',
    'pydantic.deprecated.decorator',
    'fastapi',
    'starlette',
    'starlette.routing',
    'starlette.middleware',
    
    # HTTP client
    'httpx',
    'httpx._transports',
    'httpx._transports.default',
    
    # Image processing
    'PIL',
    'PIL.Image',
    'PIL.ImageFile',
    
    # Security
    'bcrypt',
    'passlib',
    'passlib.handlers',
    'passlib.handlers.bcrypt',
    'python_multipart',
    
    # Validation
    'email_validator',
    
    # DNS
    'dns',
    'dns.resolver',
    'dns.rdatatype',
    
    # Async
    'anyio',
    'anyio._backends',
    'anyio._backends._asyncio',
    'sniffio',
    
    # Logging
    'logging.handlers',
    
    # App modules
    'app',
    'app.core',
    'app.core.paths',
    'app.api',
    'app.db',
    'app.models',
    'app.schemas',
    'app.services',
    'app.services.prism_identity_service',
    'app.services.unknown_device_admission_service',
    'config',
    'main',
]

# Include full NetProtection and cryptography stacks (used at runtime)
hidden_imports += collect_submodules('easypi_netprotection')
hidden_imports += collect_submodules('cryptography')
hidden_imports += collect_submodules('prism_dpi')
hidden_imports += collect_submodules('prism_tls_bridge')
hidden_imports += collect_submodules('aioquic')
hidden_imports += collect_submodules('pylsqpack')
hidden_imports += collect_submodules('hpack')

# Collect data files
datas = [
    (str(BACKEND_DIR / 'app'), 'app'),
]

# Bundle NetProtection package (repo root)
netprotection_path = PROJECT_ROOT / 'easypi_netprotection'
if netprotection_path.exists():
    datas.append((str(netprotection_path), 'easypi_netprotection'))

# The backend imports PRISM flow policies during startup. Bundle them into the
# frozen application so a clean binary release cannot depend on stale source
# files left behind in /opt/EasyPi.
prism_path = PROJECT_ROOT / 'prism_dpi'
if prism_path.exists():
    datas.append((str(prism_path), 'prism_dpi'))

# Only include templates if they exist
templates_path = BACKEND_DIR / 'templates'
if templates_path.exists():
    datas.append((str(templates_path), 'templates'))

# Analysis
a = Analysis(
    [str(BACKEND_DIR / 'packaging' / 'run_backend.py')],
    pathex=[str(BACKEND_DIR), str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'scipy',
        'numpy.testing',
        'IPython',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='easypi-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
