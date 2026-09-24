"""HorusShield Logger — Fixed version"""
import logging, os, sys
from logging.handlers import RotatingFileHandler
from datetime import datetime

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        CYAN=GREEN=YELLOW=RED=WHITE=''; RESET=''
    class Style:
        DIM=BRIGHT=RESET_ALL=''

import sys as _sys
if getattr(_sys, 'frozen', False):
    LOG_DIR = os.path.join(os.path.dirname(_sys.executable), 'logs')
else:
    LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

LEVEL_COLORS = {'DEBUG':Fore.CYAN,'INFO':Fore.GREEN,'WARNING':Fore.YELLOW,'ERROR':Fore.RED,'CRITICAL':Fore.RED}
MODULE_ICONS = {'engine':'⚙️','ai':'🧠','honeypot':'🍯','mesh':'🕸️','attack':'⚔️','device':'📱','network':'🌐','system':'🖥️','api':'🔌','report':'📄','horus':'🦅'}

class HorusFormatter(logging.Formatter):
    def format(self, record):
        level = record.levelname
        color = LEVEL_COLORS.get(level,'') if HAS_COLOR else ''
        module = getattr(record,'module_name','system')
        icon = MODULE_ICONS.get(module,'📋')
        ts = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        msg = record.getMessage()
        if HAS_COLOR and sys.stdout.isatty():
            return f"{Fore.WHITE}{Style.DIM}{ts}{Style.RESET_ALL} {icon} {color}[{level:>8}]{Style.RESET_ALL} {Fore.CYAN}{module:>12}{Style.RESET_ALL} | {msg}"
        return f"{ts} [{level:>8}] {module:>12} | {msg}"

class FileFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        module = getattr(record,'module_name','system')
        return f"{ts} [{record.levelname:>8}] {module:>12} | {record.getMessage()}"


class SafeStreamHandler(logging.StreamHandler):
    """Ignore writes after a captured application stream has been closed."""

    def handleError(self, record):
        exc_type, exc_value, _ = sys.exc_info()
        if isinstance(exc_value, (OSError, ValueError)):
            return
        super().handleError(record)


def get_logger(name="horus", module_name="system"):
    logger = logging.getLogger(f"horus.{name}")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        ch = SafeStreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(HorusFormatter())
        logger.addHandler(ch)
        fh = RotatingFileHandler(os.path.join(LOG_DIR,"horus.log"), maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(FileFormatter())
        logger.addHandler(fh)
        logger.propagate = False

    class ModuleLogger:
        def __init__(self, lg, mod):
            self._lg = lg; self._mod = mod
        def _log(self, level, msg, *args, **kwargs):
            getattr(self._lg, level)(msg, *args, extra={'module_name': self._mod}, **kwargs)
        def debug(self,m,*a,**k): self._log('debug',m,*a,**k)
        def info(self,m,*a,**k): self._log('info',m,*a,**k)
        def warning(self,m,*a,**k): self._log('warning',m,*a,**k)
        def error(self,m,*a,**k): self._log('error',m,*a,**k)
        def critical(self,m,*a,**k): self._log('critical',m,*a,**k)

    return ModuleLogger(logger, module_name)

system_logger = get_logger("system","system")
engine_logger = get_logger("engine","engine")
ai_logger     = get_logger("ai","ai")
api_logger    = get_logger("api","api")
