#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
造序AI跑图小工具 - 配置文件加载器
用于加载 config.env 文件中的环境变量
"""

import os
from pathlib import Path


def load_config():
    """加载配置文件中的环境变量"""
    config_file = Path(__file__).parent / "config.env"
    
    if not config_file.exists():
        print(f"配置文件不存在: {config_file}")
        return
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # 跳过空行和注释行
                if not line or line.startswith('#'):
                    continue
                
                # 解析键值对
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # 移除值两端的引号
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    # 设置环境变量
                    os.environ[key] = value
                    print(f"已设置环境变量: {key}={value}")
                else:
                    print(f"警告: 第{line_num}行格式错误: {line}")
                    
    except Exception as e:
        print(f"加载配置文件失败: {e}")


def get_config_value(key, default=None):
    """获取配置值"""
    return os.environ.get(key, default)


def is_debug_mode():
    """检查是否为调试模式"""
    return os.environ.get("DEBUG", "0") == "1"


def get_comfyui_url():
    """获取ComfyUI地址"""
    return os.environ.get("COMFYUI_URL", "http://nps.izeta.com.cn:5005")


def get_default_project_dir():
    """获取默认项目目录"""
    return os.environ.get("DEFAULT_PROJECT_DIR", "D:\\zx\\cursor\\jingqiu\\tu\\")


def get_default_sleep_time():
    """获取默认休眠时间"""
    try:
        return int(os.environ.get("DEFAULT_SLEEP_TIME", "30"))
    except ValueError:
        return 30


def get_request_timeout():
    """获取请求超时时间"""
    try:
        return int(os.environ.get("REQUEST_TIMEOUT", "60"))
    except ValueError:
        return 60


def get_workflow_timeout():
    """获取工作流超时时间"""
    try:
        return int(os.environ.get("WORKFLOW_TIMEOUT", "900"))
    except ValueError:
        return 900


if __name__ == "__main__":
    # 测试配置加载
    print("=== 配置加载测试 ===")
    load_config()
    print(f"DEBUG模式: {is_debug_mode()}")
    print(f"ComfyUI地址: {get_comfyui_url()}")
    print(f"默认项目目录: {get_default_project_dir()}")
    print(f"默认休眠时间: {get_default_sleep_time()}秒")
    print(f"请求超时: {get_request_timeout()}秒")
    print(f"工作流超时: {get_workflow_timeout()}秒")
