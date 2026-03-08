# IDA Pro MCP 插件（增强版）

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![IDA Pro Version](https://img.shields.io/badge/IDA%20Pro-7.5%2B-green.svg)](https://www.hex-rays.com/products/ida/)

## 1. 项目简介

`ida-pro-mcp` 是一个面向 IDA Pro 的 MCP 服务端/插件项目，用于把 IDA 分析能力暴露给 MCP 客户端（如 Cline、Roo Code、Claude Desktop 等）。

当前仓库包含两条运行路径：

- `server`：连接 IDA 内插件提供的 JSON-RPC 能力（常用模式）
- `idalib_server`：基于 `idalib` 的无界面模式（需要本机 IDA 运行库）

## 2. 主要能力

- 暴露 IDA 反汇编/反编译与符号信息查询能力
- 支持批量重命名、注释、类型相关操作（含 unsafe 工具）
- 支持脚本辅助能力（如 Frida/Angr 脚本生成与保存）
- 支持自动安装 MCP 客户端配置与 IDA 插件入口

## 3. 项目结构

```text
src/ida_pro_mcp/
├── __init__.py
├── server.py            # MCP 主服务（连接 IDA 插件 JSON-RPC）
├── idalib_server.py     # idalib 模式 MCP 服务
├── mcp-plugin.py        # IDA 侧插件（JSON-RPC 服务）
├── script_utils.py      # 脚本生成辅助
├── mcp_config.json      # 默认配置
└── server_generated.py  # 自动生成（请勿手改）
```

## 4. 环境要求

### 4.1 通用

- Python `>= 3.10`（以 `pyproject.toml` 为准）
- IDA Pro `>= 7.5`（插件模式）

### 4.2 idalib 模式额外要求

- IDA Pro `>= 9.0`（`idapro`/`idalib` 运行库可用）
- 设置 `IDADIR` 到有效 IDA 安装目录

## 5. 安装

```bash
pip install -e .
```

可选依赖（按需）：

```bash
pip install angr frida-tools
```

## 6. 配置说明

默认配置文件：`src/ida_pro_mcp/mcp_config.json`

当前仓库内默认值：

```json
{
  "host": "127.0.0.1",
  "port": 13338,
  "plugin": { "port": 13338 },
  "simple_server": { "port": 13338 },
  "idalib_server": { "port": 8746 }
}
```

配置优先级（高到低）：

1. 环境变量
2. 配置文件
3. 代码内默认值

环境变量：

- `MCP_HOST`：覆盖监听地址
- `MCP_PORT`：覆盖 `server.py` 的 RPC 目标端口
- `IDALIB_MCP_PORT`：覆盖 `idalib_server.py` 端口（优先于 `MCP_PORT`）

说明：若缺少配置文件，`server.py` 内置端口默认是 `13337`；仓库自带配置将其覆盖为 `13338`。

## 7. 使用方法

### 7.1 安装 MCP 客户端配置与 IDA 插件

```bash
ida-pro-mcp --install
```

卸载：

```bash
ida-pro-mcp --uninstall
```

### 7.2 启动主 MCP 服务（连接 IDA 插件）

```bash
python -m ida_pro_mcp.server
```

常用参数：

- `--transport`：`stdio`（默认）或 `http://127.0.0.1:8744`
- `--ida-rpc`：指定 IDA 插件 RPC 地址（默认读取配置后通常为 `http://127.0.0.1:13338`）
- `--unsafe`：启用危险工具
- `--config`：打印 MCP 客户端配置 JSON
- `--auto-run-ida <binary>`：自动启动 IDA 并加载指定样本（Windows 体验更完整）

### 7.3 启动 idalib 模式

```bash
python -m ida_pro_mcp.idalib_server <binary_path> --host 127.0.0.1 --port 8746
```

如果报错 `Cannot load IDA library file idalib.dll`，请先检查：

- IDA 版本是否为 9.0+
- `IDADIR` 是否指向有效 IDA 安装目录

### 7.4 直连插件 JSON-RPC（调试）

IDA 插件启动后，可对以下路径发起请求：

- `http://127.0.0.1:13338/mcp`
- `http://127.0.0.1:13338/jsonrpc`

示例：

```python
import json
import requests

resp = requests.post(
    "http://127.0.0.1:13338/mcp",
    headers={"Content-Type": "application/json"},
    data=json.dumps({
        "jsonrpc": "2.0",
        "method": "check_connection",
        "params": [],
        "id": 1
    })
)
print(resp.json())
```

## 8. 项目完整性检查（本地）

最近一次检查项：

- `python -m compileall src`：通过
- `python -m ida_pro_mcp.server --help`：通过
- `python -m ida_pro_mcp.server --config`：通过

说明：

- 当前仓库未包含可直接执行的单元测试集合，`pytest` 依赖存在但本地环境需自行安装并补充测试用例。
- `idalib_server` 在无 IDA 运行库环境下无法直接导入，属于预期行为。

## 9. 常见问题

### 9.1 MCP 无法连接 IDA

- 确认 IDA 已加载样本
- 在 IDA 中手动启动插件：`Edit -> Plugins -> MCP`（默认热键 `Ctrl+Alt+M`）
- 检查端口占用与 `mcp_config.json` 端口一致性

### 9.2 端口冲突

- 修改 `mcp_config.json` 中 `port` / `plugin.port` / `idalib_server.port`
- 或通过环境变量 `MCP_PORT` / `IDALIB_MCP_PORT` 覆盖

### 9.3 Frida/Angr 相关工具不可用

- 按需安装额外依赖：`pip install frida-tools angr`

## 10. 开发说明

- 入口脚本：
  - `ida-pro-mcp = ida_pro_mcp.server:main`
  - `idalib-mcp = ida_pro_mcp.idalib_server:main`
- 生成文件 `server_generated.py` 由 `server.py` 动态生成，不建议手工维护。

## 11. 许可证

MIT License

