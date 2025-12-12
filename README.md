# IDA Pro MCP 插件

MCP (Modding and Code Analysis Plugin) 是一个功能强大的 IDA Pro 插件，旨在提供丰富的代码分析、自动化和修改功能，帮助逆向工程师和安全研究人员更高效地进行二进制分析。此插件现已升级支持最新的 MCP 协议标准。

GitHub 项目地址：https://github.com/namename333/idapromcp_333

本项目基于 mrexodia/ida-pro-mcp（https://github.com/mrexodia/ida-pro-mcp）

 二次开发增强，保留原核心功能并自行diy扩展了一些功能。

十分建议大家去下载原项目，我本意是自己根据原项目自己加一点trace功能什么的和优化一些操作方便我自己使用，但是原项目更新太快太厉害了，我如果要更新要么功能远不如，要么就基本上照抄。。

## 开发者

* **name** - 开发者（QQ：1559820232）
* **grand** - 开发者 (QQ: 3527424707)
* **Britney** - 开发者 (QQ: 2855057900)

## 版本更新 (v2.0)

- **新增 script_utils 模块** - 提供脚本生成辅助函数库，包含地址检测、目标表达式生成、脚本内容构建等功能，大幅提升代码可维护性和重用性
- **优化 Frida 脚本生成** - 重构 generate_frida_script 函数，使用 script_utils 模块提供的标准化辅助函数，提供更可靠的地址检测和目标表达式生成
- **增强错误处理** - 添加完善的异常处理和回退机制，确保即使 script_utils 模块出现问题，仍可使用内置实现继续工作
- **改进安装脚本** - 支持更多平台和IDA版本，提供更详细的安装信息，确保 script_utils 模块正确安装
- **添加日志记录** - 优化日志系统，便于调试和问题排查，记录 script_utils 模块的使用情况和潜在问题
- **扩展功能支持** - 增强对 Java 应用、Windows 平台和不同架构的支持

## script_utils 模块详解

### 模块概述

script_utils 是 v2.0 版本新增的核心组件，专门用于辅助生成和管理 Frida 脚本。该模块提供了一系列标准化的函数，使脚本生成过程更加一致、可靠和可维护。

### 主要功能函数

#### 1. _is_address_string

```python
def _is_address_string(text: str) -> bool:
    """
    检查字符串是否为有效的十六进制地址格式
    参数：
        text: 要检查的字符串
    返回：
        bool: 如果是有效地址则返回 True，否则返回 False
    """
```

#### 2. _get_target_expression

```python
def _get_target_expression(target: str, is_address: bool) -> str:
    """
    根据目标类型生成 Frida 表达式
    参数：
        target: 目标函数名或地址
        is_address: 是否为地址
    返回：
        str: 适用于 Frida 脚本的目标表达式
    """
```

#### 3. _get_app_environment

```python
def _get_app_environment(app_type: str) -> tuple:
    """
    根据应用类型获取环境前缀和后缀
    参数：
        app_type: 应用类型（'native' 或 'java'）
    返回：
        tuple: (script_prefix, script_suffix) - 脚本的前缀和后缀
    """
```

#### 4. _generate_hook_script

```python
def _generate_hook_script(target: str, options: dict = None) -> str:
    """
    生成函数 Hook 脚本
    参数：
        target: 目标函数名或地址
        options: 配置选项，包括 app_type、log_args、log_return 等
    返回：
        str: 生成的 Hook 脚本代码
    """
```

#### 5. _generate_memory_dump_script

```python
def _generate_memory_dump_script(target: str, options: dict = None) -> str:
    """
    生成内存监控脚本
    参数：
        target: 要监控的内存地址
        options: 配置选项，包括 size、interval、compare_before_after 等
    返回：
        str: 生成的内存监控脚本代码
    """
```

#### 6. _generate_string_hook_script

```python
def _generate_string_hook_script(target: str, options: dict = None) -> str:
    """
    生成字符串监控脚本
    参数：
        target: 目标地址（可选）
        options: 配置选项，包括 string_functions、address_monitor、capture_callstack 等
    返回：
        str: 生成的字符串监控脚本代码
    """
```

#### 7. _get_usage_notes

```python
def _get_usage_notes() -> str:
    """
    获取脚本使用说明
    返回：
        str: 详细的使用说明文本
    """
```

### 使用 script_utils 生成 Frida 脚本

通过 MCP 插件的 generate_frida_script 方法可以使用 script_utils 模块生成三种类型的 Frida 脚本：

#### 1. 函数 Hook 脚本

```python
# 生成函数 Hook 脚本的示例
hook_script = ida_pro_mcp.generate_frida_script(
    target="main",            # 目标函数名
    script_type="hook",       # 脚本类型为 hook
    options={
        "app_type": "native",  # 应用类型为原生二进制
        "log_args": True,       # 记录函数参数
        "log_return": True,     # 记录返回值
        "detailed_log": False   # 简洁日志输出
    }
)
```

#### 2. 内存监控脚本

```python
# 生成内存监控脚本的示例
memory_script = ida_pro_mcp.generate_frida_script(
    target="0x12345678",      # 要监控的内存地址
    script_type="memory_dump", # 脚本类型为内存监控
    options={
        "size": 1024,           # 监控内存大小（字节）
        "interval": 100,        # 监控间隔（毫秒）
        "compare_before_after": True # 比较内存前后变化
    }
)
```

#### 3. 字符串监控脚本

```python
# 生成字符串监控脚本的示例
string_script = ida_pro_mcp.generate_frida_script(
    target="",                 # 不需要特定目标函数
    script_type="string_hook",  # 脚本类型为字符串监控
    options={
        "string_functions": True,     # Hook 常见字符串函数
        "address_monitor": "0x10000000", # 监控特定内存区域
        "capture_callstack": True    # 捕获调用栈
    }
)
```

### 配置选项详解

#### hook 类型选项

- **app_type**: 应用类型（"native" 或 "java"）
- **log_args**: 是否记录参数（默认：true）
- **log_return**: 是否记录返回值（默认：true）
- **detailed_log**: 是否输出详细日志（默认：false）
- **custom_prefix**: 自定义日志前缀
- **callstack_depth**: 调用栈记录深度（默认：5）

#### memory_dump 类型选项

- **size**: 监控内存大小（字节）
- **interval**: 监控间隔（毫秒）
- **compare_before_after**: 是否比较内存前后变化（默认：true）
- **dump_to_file**: 是否将内存转储保存到文件
- **file_path**: 保存路径（当 dump_to_file 为 true 时有效）

#### string_hook 类型选项

- **string_functions**: 是否 Hook 常见字符串函数（默认：true）
- **address_monitor**: 要监控的特定地址（可选）
- **capture_callstack**: 是否捕获调用栈（默认：true）
- **monitor_strlen**: 监控字符串长度阈值（默认：0，监控所有长度）
- **string_encoding**: 字符串编码（"utf8"、"utf16" 等）

### 故障排除

#### 脚本生成错误

如果 generate_frida_script 函数返回错误或生成的脚本无法正常工作：

1. **检查目标函数名或地址**：确保提供的目标是有效的
2. **验证脚本类型**：确认脚本类型为支持的类型（hook、memory_dump、string_hook）
3. **检查配置选项**：确保配置选项正确且类型匹配
4. **查看 IDA 控制台**：插件会输出 [MCP] 前缀的日志，帮助排查问题
5. **验证 script_utils 模块**：确认 script_utils 模块已正确安装

#### script_utils 模块加载失败

如果 IDA 控制台显示 script_utils 模块加载失败：

1. **检查配置文件**：确认 config.json 中的 script_utils_path 配置正确
2. **重新安装**：运行 `python install.py --script-lib "path_to_script_lib"` 重新安装
3. **检查权限**：确保 IDA Pro 有权限访问 script_utils.py 文件

## 标准 MCP 协议支持

- 支持 `/jsonrpc` 和 `/mcp` 两种访问路径
- 实现标准 `check_connection` 和 `get_methods` 接口
- MCP 协议版本 1.6.0
- 自描述 API 功能

## 目录

- [项目简介](#项目简介)
- [主要功能](#主要功能)
- [安装步骤](#安装步骤)
- [使用方法](#使用方法)
- [详细功能文档](#详细功能文档)
  - [基础架构](#基础架构)
  - [元数据和基本信息获取](#元数据和基本信息获取)
  - [函数和变量分析](#函数和变量分析)
  - [反汇编和反编译](#反汇编和反编译)
  - [调用图分析](#调用图分析)
  - [混淆检测](#混淆检测)
  - [算法识别](#算法识别)
  - [Patch点定位](#patch点定位)
  - [批量处理功能](#批量处理功能)
  - [动态分析辅助](#动态分析辅助)
- [典型工作流](#典型工作流)
- [高级用法](#高级用法)
- [版本要求](#版本要求)
- [许可证](#许可证)

## 项目简介

MCP 插件通过 JSON-RPC 协议提供了一个强大的 API，允许用户通过 HTTP 请求调用 IDA Pro 的各种功能。该插件特别关注以下几个方面：

- 自动化分析流程
- 增强的函数和变量分析
- 批量处理功能
- 动态分析辅助工具
- 混淆代码检测
- 常见算法识别
- 标准 MCP 协议兼容

## 主要功能

### 1. 批量处理功能

- **批量重命名函数**：根据命名规则或模式批量重命名函数
- **批量添加注释**：自动为函数和变量添加描述性注释
- **批量设置变量类型**：根据分析结果自动设置本地变量类型
- **批量设置函数原型**：统一设置函数的参数和返回类型

### 2. 混淆检测功能

- **控制流平坦化检测**：识别控制流混淆
- **字符串加密检测**：检测字符串加密和动态解密模式
- **反调试检测**：识别常见的反调试技术
- **死代码检测**：发现无用的代码块

### 3. 算法识别功能

自动识别常见加密算法、哈希函数和编码方式

### 4. 动态分析辅助功能

- **生成 Angr 符号执行脚本**：辅助进行符号执行和爆破
- **生成 Frida 动态分析脚本**：支持函数 Hook、内存监控和字符串监控
- **脚本保存和运行**：便捷地保存和执行生成的分析脚本
- **Windows 平台兼容性优化**：特别优化了在 Windows 环境下的使用体验

### 5. 调用图分析

生成函数调用关系图，支持可视化展示

## 安装步骤

### 系统要求

- IDA Pro 7.5+（支持 Python 3.8+）
- Python 3.8 或更高版本
- 支持 Windows、macOS 和 Linux 操作系统
- 推荐使用 Python 3.11+ 以获得最佳体验

### 方法一：使用 pip 安装（推荐）

1. 直接通过 pip 安装插件：

   ```
   pip install ida-pro-mcp
   ```
2. 将插件安装到 IDA Pro：

   ```
   # 找到您的 IDA Pro 插件目录
   # Windows 通常位于: C:\Program Files\IDA Pro 7.xx\plugins\
   # 复制插件文件到该目录
   python -m ida_pro_mcp.install
   ```

### 方法二：手动安装

1. 克隆或下载本项目代码：

   ```
   git clone https://github.com/namename333/idapromcp_333.git
   cd idapromcp_333
   ```
2. 使用提供的安装脚本（推荐）：

   ```
   python install.py
   ```

   - 该脚本会自动安装依赖并将插件复制到 IDA Pro 的插件目录
   - 如果需要指定 IDA Pro 路径：
     ```
     python install.py --ida-path "C:\Program Files\IDA Pro 7.7"
     ```
   - 如果要跳过依赖安装：
     ```
     python install.py --skip-deps
     ```
   - 如果需要指定自定义Python解释器路径：
     ```
     python install.py --python-exe "C:\Python311\python.exe"
     ```
   - 如果需要指定自定义IDA插件目录路径：
     ```
     python install.py --plugin-dir "D:\MyPlugins\ida_pro_mcp"
     ```
   - 如果需要指定自定义script库路径（用于存储生成的脚本和script_utils模块）：
     ```
     python install.py --script-lib "D:\MyScripts"
     ```

   注意：确保 script_utils 模块正确安装，它是v2.0版本中新增的重要组件，用于增强代码生成和脚本功能。

   所有选项可以组合使用：

   ```
   python install.py --ida-path "C:\Program Files\IDA Pro 7.7" --python-exe "C:\Python311\python.exe" --plugin-dir "D:\MyPlugins\ida_pro_mcp" --script-lib "D:\MyScripts"
   ```
3. 手动安装（可选）：

   - 安装依赖：
     ```
     pip install -r requirements.txt
     # 安装额外的动态分析工具（推荐）
     pip install angr frida-tools
     ```
   - 复制 `src/ida_pro_mcp` 目录到 IDA Pro 的插件目录：
     ```
     # Windows 示例
     xcopy /E src\ida_pro_mcp "C:\Program Files\IDA Pro 7.xx\plugins\ida_pro_mcp"
     ```
   - 复制 `ida-plugin.json` 到 IDA Pro 的插件目录：
     ```
     # Windows 示例
     copy ida-plugin.json "C:\Program Files\IDA Pro 7.xx\plugins"
     ```

### 验证安装

1. 启动 IDA Pro，通过以下方式启动 MCP 服务器：

   - 菜单：Edit -> Plugins -> MCP
   - 快捷键：Ctrl-Alt-M
2. 服务器启动后，将在端口 13337 上监听 JSON-RPC 请求
3. 可以使用以下命令测试连接：

   ```python
   import requests
   import json

   url = "http://localhost:13337/mcp"
   headers = {"Content-Type": "application/json"}

   payload = {
       "jsonrpc": "2.0",
       "method": "check_connection",
       "params": [],
       "id": 1
   }

   response = requests.post(url, data=json.dumps(payload), headers=headers)
   print(response.json())
   ```

### 故障排除

- **端口 13337 已被占用**：修改 `mcp-plugin.py` 中的端口设置
- **找不到插件**：确保插件文件放置在正确的 IDA Pro 插件目录中
- **Python 版本不匹配**：确认 IDA Pro 使用的 Python 版本为 3.11+，可以通过 IDA 控制台执行 `import sys; print(sys.version)` 检查
- **依赖错误**：确保所有依赖已正确安装，可以再次运行 `pip install -r requirements.txt`
- **script_utils 模块错误**：
  - 检查 config.json 中的 script_utils_path 配置
  - 确认 script_utils.py 文件存在且权限正确
  - 尝试重新运行安装脚本 `python install.py --script-lib "path_to_script_lib"`
- **Frida 脚本生成失败**：
  - 检查目标函数名或地址是否有效
  - 确认脚本类型是否为支持的类型
  - 查看 IDA 控制台的 [MCP] 前缀日志获取详细错误信息

## 使用方法

### 示例脚本

我们提供了一个完整的示例脚本 `example_usage.py`，展示了如何使用 MCP 插件的核心功能：

1. 运行示例脚本：

   ```
   python example_usage.py
   ```
2. 脚本功能包括：

   - 连接到 MCP 服务器
   - 获取元数据信息
   - 查询函数详情
   - 生成函数调用图
   - 创建 Angr 符号执行脚本

### API 基本用法

MCP 插件通过 JSON-RPC 协议提供 API，您可以使用任何支持 HTTP 请求的工具或编程语言与之交互。以下是一个基本的请求示例：

```python
import requests
import json

url = "http://localhost:13337/jsonrpc"
headers = {"Content-Type": "application/json"}

payload = {
    "jsonrpc": "2.0",
    "method": "get_function",
    "params": ["0x401000"],
    "id": 1
}

response = requests.post(url, data=json.dumps(payload), headers=headers)
result = response.json()
print(result)
```

## 详细功能文档

### 基础架构

MCP 插件的基础架构包括 RPC 服务器、线程安全机制和错误处理系统。

#### RPCRegistry 类

**功能**：注册和分发 JSON-RPC 方法的核心类

**主要方法**：

- `register(name, func, args=None)`: 注册新的 RPC 方法
- `dispatch(method, params)`: 分发 RPC 请求到对应的处理函数

#### JSONRPCRequestHandler 类

**功能**：处理 HTTP 请求并解析 JSON-RPC 协议

**主要方法**：

- `do_POST()`: 处理 POST 请求并执行相应的 RPC 方法

#### MCPHTTPServer 类

**功能**：实现 HTTP 服务器，提供 JSON-RPC 接口

**主要方法**：

- `__init__(port)`: 初始化服务器并设置端口
- `run()`: 启动服务器并开始监听请求
- `stop()`: 停止服务器

#### 线程安全装饰器

- `@idaread`: 确保函数在读取操作时线程安全
- `@idawrite`: 确保函数在写入操作时线程安全

### 元数据和基本信息获取

#### get_image_size()

**功能**：获取当前加载的镜像文件大小

**返回**：整数，表示文件大小（字节）

#### get_metadata()

**功能**：获取当前 IDB 文件的元数据信息

**返回**：包含元数据的字典

```python
  {
      "file_path": "",  # 文件路径
      "file_size": 0,   # 文件大小（字节）
      "arch": "",       # 架构信息
      "bits": 0,        # 位数（32/64）
      "compiler": ""    # 编译器信息（如果可识别）
  }
```

#### get_prototype(function_address)

**功能**：获取函数的原型信息

**参数**：

- `function_address`: 函数地址（字符串格式）

**返回**：函数原型字符串

### 函数和变量分析

#### get_function(function_address)

**功能**：获取函数的详细信息

**参数**：

- `function_address`: 函数地址（字符串格式）

**返回**：包含函数信息的字典

```python
  {
      "name": "",              # 函数名称
      "address": "",           # 函数地址
      "size": 0,               # 函数大小（字节）
      "prototype": "",         # 函数原型
      "is_imported": False,    # 是否为导入函数
      "is_thunk": False,       # 是否为 thunk 函数
      "callers": [],           # 调用此函数的函数列表
      "callees": []            # 此函数调用的函数列表
  }
```

#### parse_address(address)

**功能**：解析地址字符串为整数形式

**参数**：

- `address`: 地址字符串（支持多种格式，如 "0x401000"）

**返回**：整数形式的地址

#### get_function_by_name(function_name)

**功能**：通过名称查找函数

**参数**：

- `function_name`: 函数名称

**返回**：包含函数信息的字典（与 get_function 相同）

#### get_function_by_address(function_address)

**功能**：通过地址查找函数

**参数**：

- `function_address`: 函数地址

**返回**：包含函数信息的字典（与 get_function 相同）

#### list_functions()

**功能**：列出数据库中的所有函数

**返回**：函数信息列表（每个元素与 get_function 返回格式相同）

#### get_current_address()

**功能**：获取当前光标位置的地址

**返回**：字符串格式的地址

#### get_current_function()

**功能**：获取当前光标所在的函数信息

**返回**：包含函数信息的字典（与 get_function 相同）

### 反汇编和反编译

#### decompile_checked(function_address)

**功能**：安全地反编译函数，包含错误处理

**参数**：

- `function_address`: 函数地址

**返回**：反编译得到的伪代码字符串

#### decompile_function(function_address)

**功能**：反编译函数并获取伪代码

**参数**：

- `function_address`: 函数地址

**返回**：反编译得到的伪代码字符串

#### disassemble_function(function_address)

**功能**：获取函数的汇编代码信息

**参数**：

- `function_address`: 函数地址

**返回**：包含汇编代码信息的字典

```python
  {
      "address": "",       # 函数地址
      "name": "",          # 函数名称
      "instructions": [     # 指令列表
          {
              "address": "",  # 指令地址
              "mnem": "",     # 指令助记符
              "op_str": "",   # 操作数字符串
              "bytes": ""     # 指令字节码
          }
          # ...更多指令
      ]
  }
```

### 调用图分析

#### get_function_call_graph(start_address, depth=3, mermaid=False)

**功能**：生成函数调用图

**参数**：

- `start_address`: 起始函数地址
- `depth`: 递归深度（默认 3）
- `mermaid`: 是否返回 mermaid 格式的图表定义（默认 False）

**返回**：包含调用图信息的字典

```python
  {
      "graph": {},     # 邻接表或 mermaid 字符串
      "nodes": [],     # 节点列表（函数地址）
      "edges": []      # 边列表（调用关系）
  }
```

**调用示例**：

```python
# 获取调用图（邻接表格式）
call_graph = get_function_call_graph("0x401000", depth=2)

# 获取 mermaid 格式调用图（可用于可视化）
mermaid_graph = get_function_call_graph("0x401000", depth=2, mermaid=True)
```

### 混淆检测

#### detect_obfuscation(function_address)

**功能**：检测常见混淆模式

**参数**：

- `function_address`: 要检测混淆的函数地址

**返回**：包含混淆检测结果的字典

```python
  {
      "flattening": False,         # 是否存在控制流平坦化
      "string_encryption": False,  # 是否存在字符串加密
      "anti_debug": False,         # 是否存在反调试技术
      "dead_code": False,          # 是否存在死代码
      "details": ""                # 详细信息
  }
```

**调用示例**：

```python
obfuscation_result = detect_obfuscation("0x401234")
if obfuscation_result["flattening"]:
    print(f"函数 {obfuscation_result['details']} 可能存在控制流平坦化")
```

### 算法识别

#### get_algorithm_signature(function_address)

**功能**：自动识别常见算法

**参数**：

- `function_address`: 要识别算法的函数地址

**返回**：包含算法识别结果的字典

```python
  {
      "algorithm": "unknown",  # 识别出的算法名称（多个用逗号分隔）
      "confidence": 0.0         # 置信度（0.0-1.0）
  }
```

**支持的算法**：

- 加密算法：AES、DES、RC4、TEA、XOR 等
- 哈希函数：MD5、SHA1、SHA256、CRC32 等
- 编码方式：Base64、Base32、Base58、Base85、Rot13 等
- 压缩算法：zlib、LZMA 等
- 随机数生成：Mersenne Twister 等

**调用示例**：

```python
algo_result = get_algorithm_signature("0x401567")
if algo_result["confidence"] > 0.5:
    print(f"识别到算法: {algo_result['algorithm']}, 置信度: {algo_result['confidence']}")
```

### Patch点定位

#### get_patch_points(function_address)

**功能**：自动定位可 Patch 位置

**参数**：

- `function_address`: 要定位 patch 点的函数地址

**返回**：Patch 点列表

```python
  [
      {
          "address": "",  # patch 点地址
          "mnem": ""       # 指令助记符或类型
      }
      # ...更多 patch 点
  ]
```

**调用示例**：

```python
patch_points = get_patch_points("0x401890")
for point in patch_points:
    print(f"建议 patch 点: {point['address']} ({point['mnem']})")
```

### 批量处理功能

#### batch_rename_functions(name_pattern, target_functions=None)

**功能**：批量重命名函数

**参数**：

- `name_pattern`: 命名模式（可以包含 {index}、{old_name} 等占位符）
- `target_functions`: 目标函数列表（可选，默认处理所有函数）

**返回**：重命名结果的字典

```python
  {
      "success_count": 0,   # 成功重命名的函数数量
      "failed_count": 0,    # 重命名失败的函数数量
      "failed_functions": []  # 重命名失败的函数列表
  }
```

**调用示例**：

```python
# 为所有函数添加前缀
result = batch_rename_functions("func_{index}")

# 为特定函数重命名
result = batch_rename_functions("custom_{old_name}", ["0x401000", "0x401100"])
```

#### batch_add_comments(comments, target_functions=None)

**功能**：批量添加函数注释

**参数**：

- `comments`: 注释内容或注释映射字典
- `target_functions`: 目标函数列表（可选）

**返回**：添加注释结果的字典

```python
  {
      "success_count": 0,   # 成功添加注释的函数数量
      "failed_count": 0,    # 添加注释失败的函数数量
      "failed_functions": []  # 添加注释失败的函数列表
  }
```

**调用示例**：

```python
# 为所有函数添加相同的注释
result = batch_add_comments("需要进一步分析")

# 为不同函数添加不同的注释
comments_map = {
    "0x401000": "初始化函数",
    "0x401100": "加密函数"
}
result = batch_add_comments(comments_map)
```

#### batch_set_local_variable_types(function_address, type_map)

**功能**：批量设置函数内本地变量的类型

**参数**：

- `function_address`: 函数地址
- `type_map`: 变量名到类型的映射

**返回**：设置变量类型结果的字典

```python
  {
      "success_count": 0,   # 成功设置类型的变量数量
      "failed_count": 0,    # 设置类型失败的变量数量
      "failed_variables": []  # 设置类型失败的变量列表
  }
```

**调用示例**：

```python
types = {
    "var_4": "int *",
    "var_8": "char *"
}
result = batch_set_local_variable_types("0x401000", types)
```

#### batch_set_function_prototypes(prototype_map)

**功能**：批量设置函数原型

**参数**：

- `prototype_map`: 函数地址到原型的映射

**返回**：设置函数原型结果的字典

```python
  {
      "success_count": 0,   # 成功设置原型的函数数量
      "failed_count": 0,    # 设置原型失败的函数数量
      "failed_functions": []  # 设置原型失败的函数列表
  }
```

**调用示例**：

```python
prototypes = {
    "0x401000": "int __cdecl init(void)",
    "0x401100": "int __cdecl encrypt(char *data, int len)"
}
result = batch_set_function_prototypes(prototypes)
```

### 动态分析辅助

#### generate_angr_script(target, script_type, options=None)

**功能**：生成 angr 符号执行或爆破脚本

**参数**：

- `target`: 目标函数名或地址
- `script_type`: 脚本类型（'symbolic_exec', 'brute_force', 'control_flow'）
- `options`: 可选配置参数

**返回**：生成的 Python 脚本代码

**调用示例**：

```python
# 生成符号执行脚本
script = generate_angr_script("0x401000", "symbolic_exec")

# 生成密码爆破脚本
brute_script = generate_angr_script("0x401234", "brute_force", {"input_size": 32})
```

#### generate_frida_script(target, script_type, options=None)

**功能**：生成 Frida 动态分析脚本，完全集成 script_utils 模块，提供强大的脚本生成能力

**参数**：

- `target`: 目标函数名或地址（支持十六进制字符串格式如 "0x401000" 或十进制数字）
- `script_type`: 脚本类型，支持：
  - `hook`: 函数调用拦截和参数监控
  - `memory_dump`: 内存读写监控和数据捕获
  - `string_hook`: 字符串操作监控和过滤
- `options`: 可选配置字典，支持：
  - `app_type`: 应用类型（'native' 或 'java'，默认为 'native'）
  - `module`: 目标模块名称，用于更精确的函数定位
  - `arg_count`: Hook 函数时参数数量
  - `size`: 内存监控大小时使用
  - `string_pattern`: 字符串监控的过滤模式
  - `monitor_read`: 是否监控内存读取操作
  - `monitor_write`: 是否监控内存写入操作

**返回**：生成的 JavaScript 脚本代码，包含完整的导入语句、函数定义和使用示例

**内部工作原理**：

- 优先调用 `script_utils` 模块中的专用函数生成脚本内容：
  - `_generate_hook_script`: 生成函数 Hook 脚本
  - `_generate_memory_dump_script`: 生成内存监控脚本
  - `_generate_string_hook_script`: 生成字符串监控脚本
  - `_get_usage_notes`: 获取脚本使用说明
- 集成 script_utils 的地址检查和目标表达式生成功能
- 实现优雅的异常处理和回退机制，确保即使 script_utils 模块不可用，仍可使用内置实现

**调用示例**：

```python
# 生成基本函数 Hook 脚本
hook_script = generate_frida_script("0x401000", "hook", {"arg_count": 3})

# 生成内存监控脚本，指定监控大小和读写操作
mem_script = generate_frida_script("0x402000", "memory_dump", 
    {"size": 2048, "monitor_read": True, "monitor_write": True})

# 为 Java 应用生成函数 Hook 脚本
java_script = generate_frida_script("com.example.TargetClass.targetMethod", "hook", 
    {"app_type": "java"})

# 生成字符串监控脚本，使用过滤模式
string_script = generate_frida_script("0x403000", "string_hook", 
    {"string_pattern": "password"})
```

**典型应用场景**：

- 分析程序执行流程和参数传递
- 监控敏感内存区域的数据变化
- 捕获和分析程序中的字符串操作
- 调试和逆向工程复杂应用程序
- 安全研究和漏洞分析

#### save_generated_script(script_content, script_type, file_name=None)

**功能**：保存生成的脚本到文件

**参数**：

- `script_content`: 脚本内容
- `script_type`: 脚本类型（'angr' 或 'frida'）
- `file_name`: 保存的文件名（可选，默认生成带时间戳的文件名）

**返回**：保存结果信息，包含文件路径和运行命令提示

**调用示例**：

```python
# 保存 angr 脚本
result = save_generated_script(script_content, "angr", "my_analysis.py")

# 保存 frida 脚本
result = save_generated_script(script_content, "frida", "my_hook.js")
```

#### run_external_script(script_path, script_type, target_binary=None, target_pid=None)

**功能**：运行外部脚本（angr 或 frida）

**参数**：

- `script_path`: 脚本文件路径
- `script_type`: 脚本类型（'angr' 或 'frida'）
- `target_binary`: 目标二进制文件路径（可选）
- `target_pid`: 目标进程 ID（可选，用于 frida 附加到运行中的进程）

**返回**：脚本执行的输出结果

**调用示例**：

```python
# 运行 angr 脚本
result = run_external_script("my_analysis.py", "angr")

# 运行 frida 脚本附加到已运行的进程
result = run_external_script("my_hook.js", "frida", target_pid=12345)
```

#### get_run_command_hint(script_type, script_path)

**功能**：获取运行脚本的命令提示

**参数**：

- `script_type`: 脚本类型（'angr' 或 'frida'）
- `script_path`: 脚本文件路径

**返回**：运行命令字符串

## 典型工作流

### 基础分析流程

1. 加载二进制文件到 IDA Pro
2. 启动 MCP 插件服务器（Ctrl-Alt-M）
3. 使用 get_metadata() 获取基本信息
4. 使用 list_functions() 浏览所有函数
5. 使用 get_function() 深入分析特定函数
6. 使用 decompile_function() 获取伪代码
7. 使用 detect_obfuscation() 检测混淆
8. 使用 get_algorithm_signature() 识别算法

### 动态分析流程

1. 确定分析目标函数
2. 使用 generate_frida_script() 生成 Hook 脚本
3. 使用 save_generated_script() 保存脚本
4. 使用 run_external_script() 运行脚本并观察结果
5. 分析输出结果并调整脚本参数

### 批量处理流程

1. 选择需要处理的函数集
2. 使用 batch_rename_functions() 统一命名规范
3. 使用 batch_set_local_variable_types() 设置变量类型
4. 使用 batch_set_function_prototypes() 规范函数原型
5. 使用 batch_add_comments() 添加描述性注释

## 高级用法

### 使用调用图进行分析

1. 使用 get_function_call_graph() 生成调用图
2. 分析关键函数的调用关系
3. 识别程序的核心组件和数据流

### 调试器控制

MCP 插件提供了基本的调试器控制功能，可用于自动化调试过程：

- `dbg_continue_process()`: 继续执行进程
- `dbg_run_to(address)`: 运行到指定地址
- `dbg_set_breakpoint(address)`: 设置断点
- `dbg_remove_breakpoint(address)`: 移除断点

## 注意事项

### 一般注意事项

1. **Python 版本要求**：MCP 插件需要 Python 3.11 或更高版本。确保 IDA Pro 使用的 Python 版本符合要求。
2. **端口占用**：插件默认使用端口 13337。如果此端口已被占用，可能需要修改 `mcp-plugin.py` 中的端口设置。
3. **性能考虑**：某些批量操作和分析功能可能会消耗大量资源，特别是对大型二进制文件。
4. **IDA Pro 兼容性**：确保使用 IDA Pro 7.5 或更高版本，以获得最佳兼容性。

### 安全注意事项

1. **不安全方法标记**：某些功能被标记为 `unsafe`，使用这些功能时请谨慎，避免对重要文件造成不可逆的修改。
2. **远程访问**：默认配置下，插件仅接受本地（127.0.0.1）的请求。如需远程访问，请谨慎修改网络配置。
3. **数据备份**：在进行批量修改前，建议先备份您的 IDB 文件。

### Windows 平台特殊注意事项

1. **管理员权限**：Frida 在 Windows 上运行可能需要管理员权限。
2. **进程模式**：推荐使用进程附加模式（`target_pid` 参数）而非启动新进程。
3. **控制台窗口**：使用 `CREATE_NEW_CONSOLE` 标志创建独立的控制台窗口，避免输出冲突。
4. **函数查找**：Windows 平台上函数查找时会尝试多种策略，包括直接地址、导出函数和模糊搜索。

### Frida 脚本使用注意事项

1. **安装依赖**：确保已安装 frida-tools：`pip install frida-tools`
2. **Windows 原生程序**：使用命令 `frida -p <进程ID> -l <脚本文件> --no-pause` 附加到已运行的程序
3. **Java 程序**：使用命令 `frida -U -f <包名> -l <脚本文件> --no-pause` 启动并附加到 Java 应用
4. **输出保存**：若要保存输出，可重定向到文件：`frida -p <进程ID> -l <脚本文件> --no-pause > output.log`

### 常见问题排查

1. **插件加载失败**：检查 IDA Pro 的插件目录结构是否正确，确保所有文件都已正确放置。
2. **服务器无法启动**：检查端口是否被占用，或是否有足够的权限创建服务器。
3. **JSON-RPC 错误**：确保请求格式正确，特别是参数类型和数量。
4. **反编译失败**：部分函数可能由于优化或混淆无法被 Hex-Rays 正确反编译。

## 版本要求

- IDA Pro 7.5 或更高版本
- Python 3.11 或更高版本
- angr 和 frida-tools 库

## 许可证

本项目采用 MIT 许可证。
