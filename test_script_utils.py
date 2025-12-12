#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试脚本，用于验证script_utils模块和generate_frida_script函数的功能
"""

import sys
import os

# 添加项目根目录到Python路径，以便能够导入script_utils模块
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

try:
    # 尝试导入script_utils模块
    from ida_pro_mcp import script_utils
    print("✓ 成功导入script_utils模块")
except ImportError as e:
    print(f"✗ 无法导入script_utils模块: {e}")
    sys.exit(1)

# 定义测试函数
def test_is_address_string():
    """测试_is_address_string函数"""
    print("\n测试 _is_address_string 函数:")
    
    # 测试有效地址
    test_cases = [
        ("0x1234", True),
        ("0xABCDEF", True),
        ("1234", False),
        ("main", False),
        ("0XGHIJ", False),  # 无效的十六进制字符
    ]
    
    passed = True
    for input_str, expected in test_cases:
        try:
            result = script_utils._is_address_string(input_str)
            status = "✓" if result == expected else "✗"
            print(f"  {status} _is_address_string('{input_str}') = {result} (期望: {expected})")
            if result != expected:
                passed = False
        except Exception as e:
            print(f"  ✗ _is_address_string('{input_str}') 抛出异常: {e}")
            passed = False
    
    return passed

def test_get_target_expression():
    """测试_get_target_expression函数"""
    print("\n测试 _get_target_expression 函数:")
    
    test_cases = [
        ("0x1234", True, "ptr('0x1234')"),
        ("main", False, "'main'"),
        ("sub_401000", False, "'sub_401000'"),
    ]
    
    passed = True
    for target, is_address, expected in test_cases:
        try:
            result = script_utils._get_target_expression(target, is_address)
            status = "✓" if result == expected else "✗"
            print(f"  {status} _get_target_expression('{target}', {is_address}) = '{result}' (期望: '{expected}')")
            if result != expected:
                passed = False
        except Exception as e:
            print(f"  ✗ _get_target_expression('{target}', {is_address}) 抛出异常: {e}")
            passed = False
    
    return passed

def test_get_app_environment():
    """测试_get_app_environment函数"""
    print("\n测试 _get_app_environment 函数:")
    
    test_cases = [
        ("native", ("", "")),
        ("java", ("Java.perform(function() {\n", "\n});")),
    ]
    
    passed = True
    for app_type, expected in test_cases:
        try:
            result = script_utils._get_app_environment(app_type)
            status = "✓" if result == expected else "✗"
            print(f"  {status} _get_app_environment('{app_type}') 返回正确的前缀和后缀")
            if result != expected:
                passed = False
        except Exception as e:
            print(f"  ✗ _get_app_environment('{app_type}') 抛出异常: {e}")
            passed = False
    
    return passed

def test_generate_scripts():
    """测试脚本生成函数"""
    print("\n测试脚本生成函数:")
    
    passed = True
    
    # 测试hook脚本生成
    try:
        hook_script = script_utils._generate_hook_script("main", False, {"app_type": "native", "log_args": True, "log_return": True})
        print("  ✓ _generate_hook_script 成功生成脚本")
        # 验证生成的脚本包含必要的元素
        if "Interceptor.attach" in hook_script and "onEnter" in hook_script and "onLeave" in hook_script:
            print("    ✓ 生成的Hook脚本包含必要元素")
        else:
            print("    ✗ 生成的Hook脚本缺少必要元素")
            passed = False
    except Exception as e:
        print(f"  ✗ _generate_hook_script 抛出异常: {e}")
        passed = False
    
    # 测试memory_dump脚本生成
    try:
        memory_script = script_utils._generate_memory_dump_script("0x12345678", {"size": 1024, "interval": 100})
        print("  ✓ _generate_memory_dump_script 成功生成脚本")
        if "Memory.protect" in memory_script or "Memory.accessMonitor" in memory_script:
            print("    ✓ 生成的内存监控脚本包含必要元素")
        else:
            print("    ✗ 生成的内存监控脚本缺少必要元素")
            passed = False
    except Exception as e:
        print(f"  ✗ _generate_memory_dump_script 抛出异常: {e}")
        passed = False
    
    # 测试string_hook脚本生成
    try:
        string_script = script_utils._generate_string_hook_script("main", False, {"string_functions": True})
        print("  ✓ _generate_string_hook_script 成功生成脚本")
        if "Interceptor.attach" in string_script and "Memory.readUtf8String" in string_script:
            print("    ✓ 生成的字符串监控脚本包含必要元素")
        else:
            print("    ✗ 生成的字符串监控脚本缺少必要元素")
            passed = False
    except Exception as e:
        print(f"  ✗ _generate_string_hook_script 抛出异常: {e}")
        passed = False
    
    return passed

def test_get_usage_notes():
    """测试_get_usage_notes函数"""
    print("\n测试 _get_usage_notes 函数:")
    
    try:
        notes = script_utils._get_usage_notes()
        if isinstance(notes, str) and len(notes) > 0:
            print("  ✓ _get_usage_notes 成功返回使用说明")
            print(f"    ✓ 使用说明长度: {len(notes)} 字符")
            return True
        else:
            print("  ✗ _get_usage_notes 返回无效内容")
            return False
    except Exception as e:
        print(f"  ✗ _get_usage_notes 抛出异常: {e}")
        return False

def test_config_json():
    """测试配置文件是否包含script_utils配置"""
    print("\n测试配置文件:")
    
    config_path = os.path.join(os.path.dirname(__file__), "src", "ida_pro_mcp", "mcp_config.json")
    if os.path.exists(config_path):
        try:
            import json
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            if "script_utils_path" in config:
                print(f"  ✓ 配置文件包含script_utils_path: {config['script_utils_path']}")
                return True
            else:
                print("  ✗ 配置文件缺少script_utils_path")
                return False
        except Exception as e:
            print(f"  ✗ 读取配置文件时出错: {e}")
            return False
    else:
        print(f"  ✗ 找不到配置文件: {config_path}")
        return False

def test_install_script():
    """测试安装脚本是否支持script_utils"""
    print("\n测试安装脚本:")
    
    install_path = os.path.join(os.path.dirname(__file__), "install.py")
    if os.path.exists(install_path):
        try:
            with open(install_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if "setup_script_library" in content and "script_utils" in content:
                print("  ✓ 安装脚本包含script_utils支持")
                return True
            else:
                print("  ✗ 安装脚本缺少script_utils支持")
                return False
        except Exception as e:
            print(f"  ✗ 读取安装脚本时出错: {e}")
            return False
    else:
        print(f"  ✗ 找不到安装脚本: {install_path}")
        return False

def test_mcp_plugin():
    """测试mcp-plugin.py是否使用script_utils模块"""
    print("\n测试mcp-plugin.py:")
    
    plugin_path = os.path.join(os.path.dirname(__file__), "src", "ida_pro_mcp", "mcp-plugin.py")
    if os.path.exists(plugin_path):
        try:
            with open(plugin_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if "import script_utils" in content and "generate_frida_script" in content:
                print("  ✓ mcp-plugin.py 包含script_utils导入和generate_frida_script函数")
                return True
            else:
                print("  ✗ mcp-plugin.py 缺少script_utils导入或generate_frida_script函数")
                return False
        except Exception as e:
            print(f"  ✗ 读取mcp-plugin.py时出错: {e}")
            return False
    else:
        print(f"  ✗ 找不到mcp-plugin.py: {plugin_path}")
        return False

# 运行所有测试
def run_all_tests():
    """运行所有测试并返回总体结果"""
    print("开始测试 script_utils 模块功能...\n")
    
    # 定义测试函数列表
    tests = [
        test_is_address_string,
        test_get_target_expression,
        test_get_app_environment,
        test_generate_scripts,
        test_get_usage_notes,
        test_config_json,
        test_install_script,
        test_mcp_plugin
    ]
    
    # 运行所有测试
    results = [test() for test in tests]
    
    # 计算通过率
    passed_count = sum(results)
    total_count = len(results)
    
    # 显示总体结果
    print(f"\n=== 测试结果汇总 ===")
    print(f"通过测试: {passed_count}/{total_count}")
    
    if passed_count == total_count:
        print("\n🎉 所有测试通过！script_utils模块功能验证完成。")
        return True
    else:
        print(f"\n❌ 有 {total_count - passed_count} 个测试失败，请检查相关代码。")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
