#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TOKEN功能测试脚本
"""

import uuid
import hashlib
import hmac
import base64
from datetime import datetime, timedelta


def get_mac_address():
    """获取本机MAC地址"""
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))


def generate_token(mac_address=None, valid_days=30):
    """基于MAC地址生成带时间限制的TOKEN"""
    if mac_address is None:
        mac_address = get_mac_address()
    
    # 计算过期时间戳
    expire_timestamp = int((datetime.now() + timedelta(days=valid_days)).timestamp())
    
    # 构建TOKEN数据：MAC地址 + 过期时间戳
    # 将MAC地址中的冒号替换为其他分隔符，避免与主分隔符冲突
    mac_clean = mac_address.replace(":", "-")
    token_data = f"{mac_clean}:{expire_timestamp}"
    
    # 使用固定密钥生成HMAC签名
    secret_key = "p-run-secret-key-2024"
    signature = hmac.new(
        secret_key.encode('utf-8'),
        token_data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # 组合数据：token_data + signature
    full_token = f"{token_data}:{signature}"
    
    # Base64编码便于传输
    encoded_token = base64.b64encode(full_token.encode('utf-8')).decode('utf-8')
    
    return encoded_token


def get_token_info(token):
    """获取TOKEN信息（用于调试）"""
    try:
        decoded_token = base64.b64decode(token.encode('utf-8')).decode('utf-8')
        parts = decoded_token.split(':')
        if len(parts) != 3:
            return {"error": "TOKEN格式错误"}
        
        mac_clean, expire_timestamp_str, signature = parts
        
        # 恢复MAC地址格式（将-替换回:）
        mac_address = mac_clean.replace("-", ":")
        expire_time = datetime.fromtimestamp(int(expire_timestamp_str))
        
        return {
            "mac_address": mac_address,
            "expire_time": expire_time.strftime('%Y-%m-%d %H:%M:%S'),
            "is_expired": datetime.now().timestamp() > int(expire_timestamp_str),
            "signature": signature[:16] + "..."  # 只显示前16位
        }
    except Exception as e:
        return {"error": str(e)}


def verify_token(input_token):
    """验证输入的TOKEN是否正确且未过期"""
    try:
        # Base64解码
        decoded_token = base64.b64decode(input_token.encode('utf-8')).decode('utf-8')
        
        # 分离数据部分和签名
        parts = decoded_token.split(':')
        if len(parts) != 3:
            return False, "TOKEN格式错误"
        
        mac_clean, expire_timestamp_str, signature = parts
        
        # 恢复MAC地址格式（将-替换回:）
        mac_address = mac_clean.replace("-", ":")
        
        # 验证MAC地址是否匹配
        current_mac = get_mac_address()
        if mac_address != current_mac:
            return False, "TOKEN不匹配当前设备"
        
        # 验证签名
        token_data = f"{mac_clean}:{expire_timestamp_str}"
        secret_key = "p-run-secret-key-2024"
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            token_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return False, "TOKEN签名验证失败"
        
        # 验证时间是否过期
        expire_timestamp = int(expire_timestamp_str)
        current_timestamp = int(datetime.now().timestamp())
        
        if current_timestamp > expire_timestamp:
            expire_time = datetime.fromtimestamp(expire_timestamp)
            return False, f"TOKEN已过期（过期时间: {expire_time.strftime('%Y-%m-%d %H:%M:%S')}）"
        
        return True, "验证成功"
        
    except Exception as e:
        return False, f"TOKEN解析失败: {str(e)}"


if __name__ == "__main__":
    print("=== TOKEN功能测试 ===")
    
    # 获取MAC地址
    mac = get_mac_address()
    print(f"本机MAC地址: {mac}")
    
    # 生成TOKEN
    token = generate_token(valid_days=7)
    print(f"生成的TOKEN: {token}")
    
    # 解析TOKEN信息
    token_info = get_token_info(token)
    print(f"TOKEN信息: {token_info}")
    
    # 验证TOKEN
    is_valid, error_msg = verify_token(token)
    print(f"验证结果: {is_valid}, {error_msg}")
    
    # 测试旧TOKEN（应该失败）
    old_token = "OUM6QUQ6RTU6NEE6NUI6MjA6MTc1ODQ0NTg2MDo5OWM5OWJhMTkxMzdhMDE3MjE3NmEzYzc1MTM0Yjg0MDUzMzM3OGQ4NGU0YTBlMzE0MDE4ZTVkZmYzNjdkNzE4"
    print(f"\n测试旧TOKEN: {old_token}")
    old_info = get_token_info(old_token)
    print(f"旧TOKEN信息: {old_info}")
