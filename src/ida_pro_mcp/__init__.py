# IDA Pro MCP 智能逆向分析平台（增强版）
# 基于 mrexodia/ida-pro-mcp 二次开发增强

__version__ = "1.4.0"
__author__ = "namename333"
__description__ = "IDA Pro MCP 智能逆向分析平台，支持多客户端和自动化分析"


def server_main(*args, **kwargs):
    """Lazy entrypoint to avoid importing heavy runtime at package import time."""
    from .server import main as _main

    return _main(*args, **kwargs)


def idalib_main(*args, **kwargs):
    """Lazy entrypoint; raises ImportError only when actually invoked."""
    from .idalib_server import main as _main

    return _main(*args, **kwargs)


__all__ = [
    "__version__",
    "__author__",
    "__description__",
    "server_main",
    "idalib_main",
]
