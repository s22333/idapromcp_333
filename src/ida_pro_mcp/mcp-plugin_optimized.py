"""
IDA Pro MCP 插件优化版本
包含重构后的脚本生成功能，使用模块化设计提高代码可维护性
"""

# 导入必要的模块
import os
import sys
import json
import traceback
from typing import Dict, List, Any, Optional, Annotated
from dataclasses import dataclass
import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_nalt
import ida_dbg
import ida_enum
import ida_segment
import ida_struct
import ida_typeinf
import ida_frame
import ida_kernwin
import ida_name
import ida_hexrays
import ida_lines
import ida_ida

# 导入已创建的script_utils模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import script_utils
    print("成功导入script_utils模块")
except ImportError as e:
    print(f"无法导入script_utils模块: {str(e)}")
    script_utils = None

# 配置日志记录
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义错误类
class IDAError(Exception):
    """IDA操作相关的自定义异常类"""
    pass

# 函数注释装饰器
def idaread(func):
    """IDA读取操作的装饰器"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_info = traceback.format_exc()
            logger.error(f"函数 {func.__name__} 执行出错: {str(e)}")
            logger.error(error_info)
            raise IDAError(f"IDA操作失败: {str(e)}")
    return wrapper

# RPC装饰器（模拟）
def jsonrpc(func):
    """JSON-RPC装饰器（模拟）"""
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

@jsonrpc
@idaread
def generate_frida_script(
    target: Annotated[str, "目标函数名或地址"],
    script_type: Annotated[str, "脚本类型: 'hook', 'memory_dump', 'string_hook'"],
    options: Annotated[dict, "可选配置参数"] = None
) -> str:
    """
    生成frida动态分析脚本。
    参数：
        target: 目标函数名或地址
        script_type: 脚本类型
        options: 可选配置
    返回：
        生成的JavaScript脚本代码
    """
    try:
        # 使用script_utils模块中的辅助函数（如果可用）
        if script_utils:
            # 检查target是否为地址
            is_address = script_utils._is_address_string(target)
            # 生成目标表达式
            target_expr = script_utils._get_target_expression(target, is_address)
            # 获取应用环境前缀和后缀
            app_type = options.get('app_type', 'native') if options else 'native'
            script_prefix, script_suffix = script_utils._get_app_environment(app_type)
            
            # 根据脚本类型生成相应的脚本内容
            if script_type == 'hook':
                script_content = script_utils._generate_hook_script(target, is_address, target_expr, options)
            elif script_type == 'memory_dump':
                script_content = script_utils._generate_memory_dump_script(target_expr, options)
            elif script_type == 'string_hook':
                script_content = script_utils._generate_string_hook_script(target, is_address, target_expr)
            else:
                raise IDAError(f"不支持的脚本类型: {script_type}")
            
            # 组合脚本并添加使用说明
            script = script_prefix + script_content + script_suffix + script_utils._get_usage_notes(script_type)
            return script
        else:
            # 回退到内置实现（当script_utils模块不可用时）
            if options is None:
                options = {}
                
            # 检查target是否为地址
            is_address = False
            try:
                if target.startswith('0x'):
                    int(target, 16)
                    is_address = True
            except ValueError:
                pass
            
            # 生成脚本模板
            if is_address:
                target_expr = f"ptr('{target}')"
            else:
                target_expr = f"'{target}'"
            
            # 应用类型，默认native（原生二进制）
            app_type = options.get('app_type', 'native')
            
            # 根据应用类型生成不同的前缀和后缀
            if app_type == 'java':
                script_prefix = "Java.perform(function() {\n"
                script_suffix = "\n});"
            else:
                script_prefix = ""  # 原生二进制不需要Java环境
                script_suffix = ""
            
            if script_type == 'hook':
                script_content = script_utils._generate_hook_script(target, is_address, target_expr, options)
            elif script_type == 'memory_dump':
                script_content = script_utils._generate_memory_dump_script(target_expr, options)
            elif script_type == 'string_hook':
                script_content = script_utils._generate_string_hook_script(target, is_address, target_expr)
            else:
                raise IDAError(f"不支持的脚本类型: {script_type}")
            
            script = script_prefix + script_content + script_suffix
            return script
    except Exception as e:
        logger.error(f"生成frida脚本时出错: {str(e)}")
        raise IDAError(f"生成frida脚本失败: {str(e)}")

# 提供一个简单的使用示例
if __name__ == "__main__":
    print("这是IDA Pro MCP插件的优化版本")
    print("使用方法：")
    print("1. 将此文件重命名为mcp-plugin.py替换原文件")
    print("2. 确保script_utils.py在同一目录下")
    print("3. 在IDA Pro中重新加载插件")
