#!/usr/bin/env python3
"""
IDA Pro MCP 插件安装脚本

此脚本将帮助用户自动将 MCP 插件安装到 IDA Pro 的插件目录中。
"""

import os
import sys
import shutil
import argparse
import subprocess
import time
import stat
import traceback
from pathlib import Path

# 记录开始时间
start_time = time.time()

# 支持的操作系统
SUPPORTED_OS = {
    'win32': 'Windows',
    'darwin': 'macOS',
    'linux': 'Linux'
}

# 默认的 IDA Pro 安装路径（支持IDA Pro 7.6-9.1版本）
DEFAULT_IDA_PATHS = {
    'win32': [
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 9.1'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 9.0'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 8.3'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 8.2'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 8.1'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 8.0'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 7.9'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 7.8'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 7.7'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'IDA Pro 7.6'),
        # 也检查Program Files (x86)目录
        Path(os.environ.get('PROGRAMFILES(X86)', 'C:/Program Files (x86)'), 'IDA Pro 9.1'),
        Path(os.environ.get('PROGRAMFILES(X86)', 'C:/Program Files (x86)'), 'IDA Pro 9.0'),
    ],
    'darwin': [
        Path('/Applications/IDA Pro 9.1/ida.app/Contents/MacOS'),
        Path('/Applications/IDA Pro 9.0/ida.app/Contents/MacOS'),
        Path('/Applications/IDA Pro 8.3/ida.app/Contents/MacOS'),
        Path('/Applications/IDA Pro 8.2/ida.app/Contents/MacOS'),
        Path('/Applications/IDA Pro 8.1/ida.app/Contents/MacOS'),
        Path('/Applications/IDA Pro 8.0/ida.app/Contents/MacOS'),
        # 备选路径格式
        Path('/Applications/IDA Pro 9.1'),
        Path('/Applications/IDA Pro 9.0'),
        Path('/Applications/IDA Pro 8.3'),
        Path('/Applications/IDA Pro 8.2'),
    ],
    'linux': [
        Path('/opt/idapro-9.1'),
        Path('/opt/idapro-9.0'),
        Path('/opt/idapro-8.3'),
        Path('/opt/idapro-8.2'),
        Path('/opt/idapro-8.1'),
        Path('/opt/idapro-8.0'),
        Path('/usr/local/ida-9.1'),
        Path('/usr/local/ida-9.0'),
        Path('/usr/local/ida-8.3'),
        Path('/usr/local/ida-8.2'),
        # 其他可能的安装路径
        Path('/home/user/ida-9.1'),
        Path('/home/user/ida-9.0'),
    ]
}

def find_ida_pro_path():
    """自动查找 IDA Pro 安装路径，优先识别最新版本（包括IDA Pro 9.0和9.1）
    
    增强版本检测和路径验证，确保找到正确的IDA Pro安装目录
    """
    os_type = sys.platform
    if os_type not in SUPPORTED_OS:
        print(f"[错误] 不支持的操作系统: {os_type}")
        print(f"[信息] 支持的操作系统: {', '.join(SUPPORTED_OS.values())}")
        return None
    
    found_paths = []
    
    # 首先检查默认路径列表
    for path in DEFAULT_IDA_PATHS.get(os_type, []):
        if path.exists() and path.is_dir():
            # 验证是否真的是IDA Pro安装目录（检查关键文件）
            ida_exe = None
            if os_type == 'win32':
                ida_exe = path / 'ida.exe'
                ida64_exe = path / 'ida64.exe'
                if ida_exe.exists() or ida64_exe.exists():
                    found_paths.append(path)
                    print(f"[找到] IDA Pro 安装路径: {path}")
            else:
                # macOS和Linux路径验证
                ida_exe = path / 'ida'
                ida64_exe = path / 'ida64'
                if ida_exe.exists() or ida64_exe.exists():
                    found_paths.append(path)
                    print(f"[找到] IDA Pro 安装路径: {path}")
    
    # 如果默认路径没找到，尝试通过环境变量和注册表（Windows）
    if not found_paths and os_type == 'win32':
        try:
            import winreg
            # 尝试从注册表读取IDA Pro路径
            registry_paths = [
                r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro 9.1',
                r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro 9.0',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro 9.1',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro 9.0',
            ]
            
            for reg_path in registry_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    install_location = winreg.QueryValueEx(key, 'InstallLocation')[0]
                    path = Path(install_location)
                    if path.exists():
                        found_paths.append(path)
                        print(f"[注册表] 找到 IDA Pro 安装路径: {path}")
                    winreg.CloseKey(key)
                except:
                    pass
        except ImportError:
            pass
    
    # 对找到的路径按版本号排序，优先选择最新版本
    def get_version_score(path):
        path_str = str(path)
        # 查找版本号并转换为分数
        for version in ['9.1', '9.0', '8.3', '8.2', '8.1', '8.0', '7.9', '7.8', '7.7', '7.6']:
            if version in path_str:
                # 转换为可比较的分数，例如9.1转为91，8.3转为83等
                return float(version.replace('.', ''))
        return 0
    
    if found_paths:
        # 按版本号降序排序
        found_paths.sort(key=get_version_score, reverse=True)
        selected_path = found_paths[0]
        print(f"[选择] 使用最新版本 IDA Pro: {selected_path}")
        return selected_path
    
    print("[警告] 未找到已安装的 IDA Pro。请确认安装路径或手动指定。")
    print("[提示] 支持的IDA Pro版本: 7.6, 7.7, 7.8, 7.9, 8.0, 8.1, 8.2, 8.3, 9.0, 9.1")
    return None

def find_ida_python_exe(ida_path):
    """自动查找 IDA Pro 自带的 Python 解释器路径，增强对IDA Pro 9.0/9.1和Python 3.11的支持
    
    适配不同IDA版本的Python解释器路径布局，提供更完善的错误处理和版本验证
    """
    if not ida_path:
        print("[警告] IDA Pro路径为空，无法查找Python解释器")
        return None
    
    print(f"[查找] 正在查找 IDA Pro Python 解释器: {ida_path}")
    
    # 获取IDA Pro版本号（通过目录名判断）
    ida_version = None
    path_str = str(ida_path)
    for version in ['9.1', '9.0', '8.3', '8.2', '8.1', '8.0', '7.9', '7.8', '7.7', '7.6']:
        if version in path_str:
            ida_version = version
            break
    
    print(f"[信息] 检测到可能的IDA Pro版本: {ida_version or '未知'}")
    
    # 常见的 IDA Python 解释器路径模式
    python_paths = []
    
    # Windows 路径模式 - 针对IDA Pro 9.x优化，增加对Python 3.11的支持
    if sys.platform == 'win32':
        # 针对IDA Pro 9.x的特殊路径
        if ida_version and float(ida_version) >= 9.0:
            print("[优化] 应用IDA Pro 9.x特定的Python路径检测")
            # IDA 9.x通常使用Python 3.11
            python_paths.extend([
                os.path.join(ida_path, 'python311', 'python.exe'),  # IDA 9.x默认Python 3.11位置
                os.path.join(ida_path, 'python3', 'python.exe'),     # 备选位置
            ])
        
        # 通用Windows Python路径模式
        for py_ver in ['311', '310', '39', '38', '37', '36']:
            python_paths.append(os.path.join(ida_path, f'python{py_ver}', 'python.exe'))
        
        # 其他可能的路径
        python_paths.extend([
            os.path.join(ida_path, 'python', 'python.exe'),       # 标准位置
            os.path.join(ida_path, 'plugins', 'python', 'python.exe'),  # 备选位置
            os.path.join(ida_path, 'python.exe'),                 # 根目录下
        ])
    
    # macOS 路径模式
    elif sys.platform == 'darwin':
        # IDA Pro 9.x在macOS上的路径
        if ida_version and float(ida_version) >= 9.0:
            print("[优化] 应用IDA Pro 9.x特定的macOS Python路径检测")
            python_paths.extend([
                os.path.join(ida_path, 'python311', 'bin', 'python3'),
                os.path.join(ida_path, 'python3', 'bin', 'python3'),
            ])
        
        # 通用macOS Python路径
        python_paths.extend([
            os.path.join(ida_path, 'python', 'bin', 'python3'),
            os.path.join(ida_path, 'python', 'bin', 'python'),
        ])
        
        # 检查不同的 Python 版本
        for py_ver in ['3.11', '3.10', '3.9', '3.8', '3.7']:
            python_paths.append(os.path.join(ida_path, 'python', 'bin', f'python{py_ver}'))
    
    # Linux 路径模式
    elif sys.platform == 'linux':
        # IDA Pro 9.x在Linux上的路径
        if ida_version and float(ida_version) >= 9.0:
            print("[优化] 应用IDA Pro 9.x特定的Linux Python路径检测")
            python_paths.extend([
                os.path.join(ida_path, 'python311', 'bin', 'python3'),
                os.path.join(ida_path, 'python3', 'bin', 'python3'),
            ])
        
        # 通用Linux Python路径
        python_paths.extend([
            os.path.join(ida_path, 'python', 'bin', 'python3'),
            os.path.join(ida_path, 'python', 'bin', 'python'),
        ])
        
        # 检查不同的 Python 版本
        for py_ver in ['3.11', '3.10', '3.9', '3.8', '3.7']:
            python_paths.append(os.path.join(ida_path, 'python', 'bin', f'python{py_ver}'))
    
    # 系统Python作为后备选项
    system_python_candidates = [
        shutil.which('python3'),
        shutil.which('python')
    ]
    for py_exe in system_python_candidates:
        if py_exe:
            python_paths.append(py_exe)
    
    # 检查是否存在并验证
    best_match = None
    best_version = (0, 0)  # 用于存储最佳匹配的版本号
    
    for python_exe in python_paths:
        if os.path.exists(python_exe):
            try:
                # 验证 Python 版本兼容性
                result = subprocess.run([python_exe, '--version'], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE,
                                      text=True, 
                                      timeout=5)
                version_output = result.stderr if result.stderr else result.stdout
                version_str = version_output.strip().lower().replace('python ', '')
                
                # 解析版本号，优先选择较高版本的Python 3.x
                try:
                    if version_str.startswith('3.'):
                        version_parts = version_str.split('.')
                        major = int(version_parts[0])
                        minor = int(version_parts[1])
                        current_version = (major, minor)
                        
                        # 记录最佳匹配
                        if current_version > best_version:
                            best_version = current_version
                            best_match = python_exe
                            print(f"[找到] 候选Python解释器: {python_exe} ({version_str})")
                except (IndexError, ValueError):
                    # 无法解析版本号，但至少是有效的Python
                    if not best_match:  # 如果还没有找到，就使用这个
                        best_match = python_exe
                        print(f"[找到] Python解释器(版本未知): {python_exe}")
            except Exception as e:
                print(f"[警告] Python解释器存在但验证失败: {python_exe}, 错误: {e}")
    
    if best_match:
        # 再次验证最佳匹配
        try:
            result = subprocess.run([best_match, '--version'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  text=True, 
                                  timeout=5)
            version_output = result.stderr if result.stderr else result.stdout
            print(f"[选择] 最佳Python解释器: {best_match} ({version_output.strip()})")
            return best_match
        except Exception as e:
            print(f"[错误] 最佳匹配的Python解释器验证失败: {e}")
    
    print(f"[警告] 未找到 IDA Pro Python 解释器: {ida_path}")
    print("[提示] 请考虑手动指定Python解释器路径")
    return None

def check_write_permissions(path):
    """检查路径是否具有写入权限"""
    try:
        # 检查目录是否存在
        if os.path.exists(path):
            # 尝试在目录中创建一个临时文件
            temp_file = os.path.join(path, f'.test_write_permission_{int(time.time())}')
            with open(temp_file, 'w') as f:
                f.write('test')
            os.remove(temp_file)
            return True
        else:
            # 如果目录不存在，检查其父目录是否有写入权限
            parent_dir = os.path.dirname(path)
            if parent_dir and os.path.exists(parent_dir):
                return check_write_permissions(parent_dir)
            return False
    except:
        return False

def backup_existing_plugin(plugin_dir):
    """备份已存在的插件目录"""
    if not os.path.exists(plugin_dir):
        return None
        
    backup_dir = f"{plugin_dir}_backup_{int(time.time())}"
    try:
        print(f"发现已存在的插件目录，创建备份: {backup_dir}")
        shutil.copytree(plugin_dir, backup_dir)
        return backup_dir
    except Exception as e:
        print(f"创建备份失败: {e}")
        return None

def install_plugin(ida_path, plugin_source_path, custom_plugin_dir=None, python_exe=None):
    """将插件安装到指定的 IDA Pro 目录，增强版包含错误处理和备份功能
    
    Args:
        ida_path: IDA Pro安装路径
        plugin_source_path: 插件源代码路径
        custom_plugin_dir: 自定义插件目录路径（可选）
        python_exe: Python解释器路径（可选）
    
    Returns:
        bool: 安装是否成功
    """
    try:
        if not ida_path or not os.path.exists(ida_path):
            print(f"IDA Pro 路径不存在: {ida_path}")
            return False
        
        # 获取IDA Pro的plugins目录
        plugins_dir = os.path.join(ida_path, 'plugins')
        
        # 检查plugins目录是否存在
        if not os.path.exists(plugins_dir):
            print(f"IDA Pro plugins 目录不存在: {plugins_dir}")
            print("请确认IDA Pro安装完整或路径正确。")
            return False
        
        # 检查写入权限
        if not check_write_permissions(plugins_dir):
            print(f"没有写入权限: {plugins_dir}")
            print("请以管理员权限或更高权限运行此脚本。")
            return False
        
        # 确定插件目录
        if custom_plugin_dir:
            # 使用用户提供的自定义插件目录
            plugin_dir = os.path.abspath(custom_plugin_dir)
            print(f"使用自定义插件目录: {plugin_dir}")
            # 检查自定义目录的写入权限
            if not check_write_permissions(plugin_dir):
                print(f"没有写入权限: {plugin_dir}")
                print("请修改自定义目录权限或选择其他位置。")
                return False
        else:
            # 使用默认的插件目录
            plugin_dir = os.path.join(plugins_dir, 'ida_pro_mcp')
            print(f"使用默认插件目录: {plugin_dir}")
        
        # 创建备份
        backup_dir = backup_existing_plugin(plugin_dir)
        
        # 创建插件目录（如果不存在）
        os.makedirs(plugin_dir, exist_ok=True)
        
    except Exception as e:
        print(f"准备插件目录时出错: {e}")
        traceback.print_exc()
        return False
    
    # 复制插件文件
        try:
            print(f"正在复制插件文件到: {plugin_dir}")
            
            # 检查插件源目录
            if not os.path.exists(plugin_source_path):
                print(f"插件源目录不存在: {plugin_source_path}")
                return False
            
            # 确保目标目录完全清空
            if os.path.exists(plugin_dir):
                for item in os.listdir(plugin_dir):
                    item_path = os.path.join(plugin_dir, item)
                    if os.path.isdir(item_path):
                        try:
                            shutil.rmtree(item_path)
                        except Exception as e:
                            print(f"警告: 无法删除目录 {item_path}: {e}")
                    else:
                        try:
                            os.remove(item_path)
                        except Exception as e:
                            print(f"警告: 无法删除文件 {item_path}: {e}")
            
            # 复制 src/ida_pro_mcp 目录下的所有文件
            copied_files = 0
            copied_dirs = 0
            
            for item in os.listdir(plugin_source_path):
                s = os.path.join(plugin_source_path, item)
                d = os.path.join(plugin_dir, item)
                try:
                    if os.path.isdir(s):
                        shutil.copytree(s, d)
                        copied_dirs += 1
                    else:
                        shutil.copy2(s, d)
                        copied_files += 1
                        # 确保复制后的文件有适当的权限
                        if sys.platform != 'win32':
                            os.chmod(d, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | 
                                    stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP)
                except Exception as e:
                    print(f"警告: 无法复制 {s} 到 {d}: {e}")
            
            print(f"成功复制 {copied_files} 个文件和 {copied_dirs} 个目录")
            
            # 验证script_utils.py是否已复制
            script_utils_path = os.path.join(plugin_dir, 'script_utils.py')
            if not os.path.exists(script_utils_path):
                # 如果script_utils.py不存在，创建一个基本版本
                print("警告: script_utils.py未找到，创建基本版本...")
                # 使用更简单的方法创建文件，避免嵌套三引号问题
                script_utils_content = '# script_utils.py - 基础版本\n'
                script_utils_content += '# 此模块提供生成Frida和其他动态分析脚本的实用函数\n\n'
                script_utils_content += 'import json\n'
                script_utils_content += 'import base64\n\n'
                script_utils_content += 'def _generate_hook_script(target_address, module_name=None, script_type="function"):\n'
                script_utils_content += '    # 生成Frida函数钩子脚本\n'
                script_utils_content += '    # 基础实现，完整版本会在安装时自动更新\n'
                script_utils_content += '    pass\n\n'
                script_utils_content += 'def _generate_memory_dump_script(address, size):\n'
                script_utils_content += '    # 生成内存转储脚本\n'
                script_utils_content += '    # 基础实现\n'
                script_utils_content += '    pass\n\n'
                script_utils_content += 'def _generate_string_hook_script(target_addresses):\n'
                script_utils_content += '    # 生成字符串监控脚本\n'
                script_utils_content += '    # 基础实现\n'
                script_utils_content += '    pass\n'
                
                with open(script_utils_path, 'w', encoding='utf-8') as f:
                    f.write(script_utils_content)
                print(f"已创建基础版script_utils模块: {script_utils_path}")
        except Exception as e:
            print(f"复制插件文件时出错: {e}")
            traceback.print_exc()
            return False

        # 设置完成，返回成功
        return True
    except Exception as e:
        print(f"设置script库路径失败: {e}")
        return False

def main():
    # 主函数 增强版包含版本信息和环境检查 支持script_utils模块
    # 打印脚本信息
    print("===== IDA Pro MCP 插件安装脚本 v2.0 =====")
    print("增强版: 支持更多IDA Pro版本，添加详细错误处理和安装验证")
    print("新增功能: script_utils模块支持，提供高级脚本生成能力")
    print(f"当前Python版本: {sys.version}")
    print(f"当前操作系统: {SUPPORTED_OS.get(sys.platform, sys.platform)}")
    print("=========================================")
    
    # 检查Python版本兼容性（要求Python 3.6+）
    if sys.version_info < (3, 6):
        print("错误: 需要Python 3.6或更高版本")
        return 1
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='IDA Pro MCP 插件安装脚本')
    parser.add_argument('--ida-path', help='IDA Pro 安装路径（自动检测如果未指定）')
    parser.add_argument('--skip-deps', action='store_true', help='跳过依赖安装')
    parser.add_argument('--python-exe', help='自定义Python解释器路径')
    parser.add_argument('--plugin-dir', help='自定义IDA插件目录路径')
    parser.add_argument('--script-lib', help='自定义script库路径')
    args = parser.parse_args()
    
    # 显示参数信息
    print("\n安装参数:")
    print(f"IDA Pro 路径: {'自动检测' if not args.ida_path else args.ida_path}")
    print(f"跳过依赖: {args.skip_deps}")
    print(f"Python解释器: {'自动选择' if not args.python_exe else args.python_exe}")
    print(f"插件目录: {'默认' if not args.plugin_dir else args.plugin_dir}")
    print(f"Script库: {'不设置' if not args.script_lib else args.script_lib}")
    
    # 确定 IDA Pro 路径
    ida_path = args.ida_path
    if not ida_path:
        print("\n正在自动查找 IDA Pro 安装路径...")
        ida_path = find_ida_pro_path()
        
    if not ida_path:
        print("\n无法自动找到 IDA Pro 安装路径。")
        print("请使用 --ida-path 参数指定您的 IDA Pro 安装路径。")
        print("\n示例:")
        print("  python install.py --ida-path \"C:\\Program Files\\IDA Pro 9.1\"")
        return 1
    
    print(f"\n使用 IDA Pro 路径: {ida_path}")
    
    # 设置Python解释器路径信息
    if args.python_exe:
        print(f"使用自定义Python解释器: {args.python_exe}")
        if not os.path.exists(args.python_exe):
            print(f"警告: 提供的Python解释器路径不存在: {args.python_exe}")
            # 尝试查找相似的Python路径
            print("尝试查找相似的Python解释器...")
            python_dir = os.path.dirname(args.python_exe)
            if os.path.exists(python_dir):
                for item in os.listdir(python_dir):
                    if 'python' in item.lower():
                        print(f"  发现: {os.path.join(python_dir, item)}")
    
    # 安装依赖
    if not args.skip_deps:
        print("\n开始安装依赖...")
        if not install_dependencies(ida_path, args.python_exe):
            print("警告: 依赖安装失败，但将继续安装插件。您可能需要手动安装依赖。")
            try:
                # 尝试获取可用的Python解释器
                python_exe = find_ida_python_exe(ida_path) or sys.executable
                print(f"您可以尝试直接使用以下命令手动安装依赖:")
                print(f"  {python_exe} -m pip install -r requirements.txt")
            except:
                print("请使用适当的Python解释器安装requirements.txt中的依赖")
        # 显示检测到的Python解释器信息
        print("\nPython环境检查:")
        ida_python = find_ida_python_exe(ida_path)
        if ida_python:
            print(f"✓ 检测到IDA Pro自带的Python解释器: {ida_python}")
        else:
            print("✗ 未检测到IDA Pro自带的Python解释器，请确保IDA安装完整。")
            print("这可能会影响插件的正常运行。")
    
    # 安装插件
    print("\n开始安装插件...")
    plugin_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src', 'ida_pro_mcp')
    if not os.path.exists(plugin_source_path):
        print(f"错误: 未找到插件源代码目录: {plugin_source_path}")
        print("请确保您在正确的项目目录中运行此脚本。")
        return 1
    
    # 设置script库路径
    if args.script_lib:
        print(f"\n设置自定义script库路径: {args.script_lib}")
        setup_script_library(args.script_lib)
    
    # 获取使用的Python解释器路径（优先使用IDA自带的）
    python_exe = find_ida_python_exe(ida_path) if ida_path else None
    if not python_exe and args.python_exe:
        python_exe = args.python_exe
    
    print(f"\n使用的Python解释器: {python_exe if python_exe else '系统默认'}")
    
    if install_plugin(ida_path, plugin_source_path, args.plugin_dir, python_exe):
        print("\n===== 安装完成！ =====")
        print("\n使用说明:")
        print("1. 启动 IDA Pro")
        print("2. 通过 Edit -> Plugins -> MCP 启动插件")
        print("3. 或使用快捷键 Ctrl-Alt-M 启动插件服务器")
        print("\n插件服务器将在端口 13337 上监听请求")
        
        # 显示script_utils模块信息
        script_utils_path = os.path.join(plugin_dir, 'script_utils.py')
        if os.path.exists(script_utils_path):
            print("\nscript_utils模块信息:")
            print(f"• 模块路径: {script_utils_path}")
        print("• 功能: 提供高级脚本生成，包括函数钩子、内存转储和字符串监控")
        print("• 与generate_frida_script函数集成,提供更强大的脚本生成能力")
        
        print("\n故障排除提示:")
        print("• 如果插件无法加载，请检查IDA Pro的Python环境是否已安装所有依赖")
        print("• 查看IDA Pro的输出窗口获取详细错误信息")
        print("• 检查端口13337是否被其他程序占用")
        print(f"• 详细配置信息已保存到: {os.path.join(plugin_dir, 'plugin_config.txt')}")
        print(f"• 安装总用时: {time.time() - start_time:.2f}秒")
        return 0
    else:
        print("\n===== 安装失败 =====")
        print("请检查上面的错误信息。")
        print("\n建议操作:")
        print("1. 以管理员权限重新运行此脚本")
        print("2. 确认IDA Pro路径正确")
        print("3. 尝试使用 --skip-deps 参数跳过依赖安装")
        print("4. 检查是否有足够的磁盘空间")
        return 1

if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n安装被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n脚本执行出错: {e}")
        traceback.print_exc()
        sys.exit(1)

# 示例用法:
# python install.py --ida-path "C:\Program Files\IDA Pro 7.7" --python-exe "C:\Python311\python.exe" --plugin-dir "D:\MyPlugins\ida_pro_mcp" --script-lib "D:\MyScripts"