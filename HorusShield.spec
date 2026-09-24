# -*- mode: python ; coding: utf-8 -*-
# HorusShield 2.0 — PyInstaller spec
# Fixed: threading async_mode + all hidden imports

block_cipher = None

a = Analysis(
    ['backend\\app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('HorusShield_UI.html', '.'),
        ('icon.ico', '.'),
        ('backend\\.env', '.'),
        ('backend\\database', 'database'),
        ('backend\\ai\\models', 'ai\\models'),
        ('backend\\logs', 'logs'),
    ],
    hiddenimports=[
        # ─ THE KEY FIX: threading mode for SocketIO ─
        'engineio.async_drivers.threading',
        'engineio.async_threading',
        # Flask & Web
        'flask_socketio', 'flask_cors', 'flask.templating',
        'werkzeug.serving', 'werkzeug.debug',
        # Rate Limiting (Flask-Limiter / Limits)
        'flask_limiter', 'flask_limiter.util',
        'limits', 'limits.storage', 'limits.strategies', 'limits.aio',
        'ordered_set', 'redis',
        # WebView
        'webview', 'webview.platforms.winforms',
        'webview.platforms.gtk', 'clr',
        # Network
        'psutil', 'psutil._pswindows',
        'requests', 'requests.adapters',
        'scapy', 'scapy.all',
        'scapy.layers.inet', 'scapy.layers.l2',
        'scapy.layers.dns',
        # AI / ML
        'sklearn', 'sklearn.ensemble', 'sklearn.preprocessing',
        'sklearn.pipeline', 'sklearn.tree', 'sklearn.utils',
        'joblib', 'numpy', 'pandas',
        # Graph
        'networkx', 'networkx.algorithms',
        # PDF
        'fpdf2', 'fpdf',
        # Utils & Security
        'colorama', 'ipwhois', 'mac_vendor_lookup',
        'sqlite3', 'threading', 'concurrent.futures',
        'subprocess', 'difflib', 'json', 'hashlib',
        'defusedxml', 'defusedxml.ElementTree',
        # Google Sign-In (OAuth token verification)
        'dotenv',
        'google.auth', 'google.auth.transport', 'google.auth.transport.requests',
        'google.oauth2', 'google.oauth2.id_token',
        'cachetools', 'pyasn1', 'pyasn1_modules', 'rsa',
        'security.ssrf',
        # Blueprints & Engines
        'api.rate_limit',
        'api.routes_terminal',
        'api.routes_auth',
        'api.routes_vscanner',
        'api.routes_devices',
        'api.routes_attacks',
        'api.routes_ai',
        'api.routes_reports',
        'api.routes_settings',
        'api.routes_dashboard',
        'api.routes_audit',
        'api.routes_honeypot',
        'api.routes_mesh',
        'api.routes_horus',
        'vscanner.orchestrator',
        'vscanner.nmap_runner',
        'vscanner.nikto_runner',
        'vscanner.zap_client',
        'vscanner.tool_discovery',
        'vscanner.domain_reputation',
        'vscanner.fast_web_scanner',
        'ai.vscanner_cortex',
        'services.threat_map',
        'services.system_monitor',
        'api.routes_sysmon',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['eventlet', 'gevent', 'tornado', 'pytest'],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HorusShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
    uac_admin=True,
    version_file=None,
)
