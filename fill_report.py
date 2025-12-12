#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
填写开题报告表格
"""

from docx import Document

def fill_report(file_path):
    """填写开题报告表格"""
    doc = Document(file_path)
    table = doc.tables[0]  # 获取第一个表格
    
    # 填写题目
    table.cell(0, 1).text = "IDA Pro MCP 插件开发与实现"
    
    # 填写选题意义及现状简介
    significance_text = ("选题意义：\n" 
                        "1. 自动化分析流程：通过JSON-RPC协议提供API，实现二进制分析的自动化\n" 
                        "2. 增强的函数和变量分析：提供丰富的函数和变量分析功能\n" 
                        "3. 批量处理功能：支持批量重命名、添加注释、设置变量类型等\n" 
                        "4. 动态分析辅助工具：生成Angr和Frida脚本，辅助动态分析\n" 
                        "5. 混淆代码检测：识别控制流平坦化、字符串加密等混淆技术\n" 
                        "6. 常见算法识别：自动识别加密算法、哈希函数等\n" 
                        "7. 标准MCP协议兼容：支持标准MCP协议，便于与其他工具集成\n\n" 
                        "现状简介：\n" 
                        "目前二进制分析工具如IDA Pro主要依赖人工操作，效率较低。MCP插件通过提供自动化API，" 
                        "结合混淆检测、算法识别等功能，提高二进制分析效率。该插件基于mrexodia/ida-pro-mcp项目" 
                        "二次开发，新增了script_utils模块，优化了Frida脚本生成，增强了错误处理和日志记录。")
    table.cell(7, 0).text = significance_text
    
    # 填写毕业设计的主要内容
    main_content = ("1. 批量处理功能：\n" 
                   "   - 批量重命名函数\n" 
                   "   - 批量添加注释\n" 
                   "   - 批量设置变量类型\n" 
                   "   - 批量设置函数原型\n\n" 
                   "2. 混淆检测功能：\n" 
                   "   - 控制流平坦化检测\n" 
                   "   - 字符串加密检测\n" 
                   "   - 反调试检测\n" 
                   "   - 死代码检测\n\n" 
                   "3. 算法识别功能：\n" 
                   "   - 自动识别常见加密算法（AES、DES、RC4等）\n" 
                   "   - 自动识别哈希函数（MD5、SHA1、SHA256等）\n" 
                   "   - 自动识别编码方式（Base64、Base32等）\n\n" 
                   "4. 动态分析辅助功能：\n" 
                   "   - 生成Angr符号执行脚本\n" 
                   "   - 生成Frida动态分析脚本（函数Hook、内存监控、字符串监控）\n" 
                   "   - 脚本保存和运行\n" 
                   "   - Windows平台兼容性优化\n\n" 
                   "5. 调用图分析：\n" 
                   "   - 生成函数调用关系图\n" 
                   "   - 支持可视化展示\n\n" 
                   "6. 标准MCP协议支持：\n" 
                   "   - 支持/jsonrpc和/mcp两种访问路径\n" 
                   "   - 实现标准check_connection和get_methods接口\n" 
                   "   - MCP协议版本1.6.0\n" 
                   "   - 自描述API功能")
    table.cell(8, 0).text = main_content
    
    # 填写拟解决的问题及思路、方法
    solution_text = ("拟解决的问题：\n" 
                    "1. 提高二进制分析效率，减少人工操作\n" 
                    "2. 增强混淆代码检测能力，识别复杂混淆技术\n" 
                    "3. 自动化常见算法识别，辅助逆向分析\n" 
                    "4. 提供强大的动态分析辅助工具\n" 
                    "5. 支持标准MCP协议，便于工具集成\n\n" 
                    "思路与方法：\n" 
                    "1. 基于IDA Pro插件架构，通过JSON-RPC协议提供API\n" 
                    "2. 利用静态分析技术实现混淆检测和算法识别\n" 
                    "3. 集成Angr和Frida等动态分析工具，提供脚本生成功能\n" 
                    "4. 设计script_utils模块，优化脚本生成流程\n" 
                    "5. 实现完整的错误处理和日志记录机制\n" 
                    "6. 支持多平台，特别是Windows平台优化")
    table.cell(9, 0).text = solution_text
    
    # 填写研究进度安排
    schedule_text = ("1. 需求分析和设计：2024年11月-2024年12月\n" 
                    "   - 分析项目需求和功能点\n" 
                    "   - 设计插件架构和API\n" 
                    "   - 制定开发计划\n\n" 
                    "2. 核心功能开发：2025年1月-2025年3月\n" 
                    "   - 实现批量处理功能\n" 
                    "   - 开发混淆检测模块\n" 
                    "   - 实现算法识别功能\n" 
                    "   - 开发动态分析辅助工具\n\n" 
                    "3. 测试和优化：2025年4月-2025年5月\n" 
                    "   - 功能测试和bug修复\n" 
                    "   - 性能优化\n" 
                    "   - 文档完善\n\n" 
                    "4. 文档撰写和答辩准备：2025年5月-2025年6月\n" 
                    "   - 撰写毕业论文\n" 
                    "   - 准备答辩材料\n" 
                    "   - 进行答辩")
    table.cell(10, 0).text = schedule_text
    
    # 保存文档
    doc.save(file_path)
    print(f"开题报告已填写完成，保存至：{file_path}")

if __name__ == "__main__":
    file_path = "d:\code\idapromcp_333-main\王晨俊毕业论文（设计）开题报告 .docx"
    fill_report(file_path)
