import json
import os
import queue
import shutil
import threading
import time
import tkinter as tk
from tkinter import ttk
import uuid
import hashlib
import hmac
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, scrolledtext

import requests

# 加载配置文件
try:
    from load_config import load_config, is_debug_mode
    load_config()
    print("配置文件加载完成")
except ImportError:
    print("配置文件加载器不存在，使用默认设置")
    def is_debug_mode():
        return os.getenv("DEBUG") == "1"

# 调试模式标记
DEBUG_MODE = is_debug_mode()


def get_mac_address():
    """获取本机MAC地址"""
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))


def generate_token(mac_address=None, valid_days=30):
    """基于MAC地址生成带时间限制的TOKEN
    
    Args:
        mac_address: MAC地址，如果为None则使用本机MAC
        valid_days: TOKEN有效天数，默认30天
    
    Returns:
        生成的TOKEN字符串
    """
    if mac_address is None:
        mac_address = get_mac_address()
    
    # 计算过期时间戳
    expire_timestamp = int((datetime.now() + timedelta(days=valid_days)).timestamp())
    
    # 构建TOKEN数据：MAC地址 + 过期时间戳
    # 将MAC地址中的冒号替换为其他分隔符，避免与主分隔符冲突
    mac_clean = mac_address.replace(":", "-")
    token_data = f"{mac_clean}:{expire_timestamp}"
    
    # 使用固定密钥生成HMAC签名
    secret_key = "p-run-secret-key-2025"
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


def verify_token(input_token):
    """验证输入的TOKEN是否正确且未过期
    
    Args:
        input_token: 用户输入的TOKEN
    
    Returns:
        tuple: (是否有效, 错误信息)
    """
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
        secret_key = "p-run-secret-key-2025"
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


def get_token_info(token):
    """获取TOKEN信息（用于调试）
    
    Args:
        token: TOKEN字符串
    
    Returns:
        dict: TOKEN信息
    """
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


def save_token_to_file(token):
    """保存TOKEN到本地文件
    
    Args:
        token: 要保存的TOKEN字符串
    """
    try:
        token_file = "saved_token.txt"
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(token)
        print(f"TOKEN已保存到 {token_file}")
    except Exception as e:
        print(f"保存TOKEN失败: {e}")


def load_token_from_file():
    """从本地文件读取TOKEN
    
    Returns:
        str or None: 读取到的TOKEN，如果文件不存在或读取失败则返回None
    """
    try:
        token_file = "saved_token.txt"
        if not os.path.exists(token_file):
            return None
            
        with open(token_file, "r", encoding="utf-8") as f:
            token = f.read().strip()
            
        # 验证TOKEN是否有效且未过期
        if token:
            is_valid, error_msg = verify_token(token)
            if is_valid:
                print(f"从文件读取到有效TOKEN")
                return token
            else:
                print(f"文件中的TOKEN已失效: {error_msg}")
                # 删除失效的TOKEN文件
                try:
                    os.remove(token_file)
                    print("已删除失效的TOKEN文件")
                except Exception:
                    pass
                return None
        return None
    except Exception as e:
        print(f"读取TOKEN文件失败: {e}")
        return None


@dataclass
class TaskItem:
    project_name: str
    episode_name: str
    role_name: str
    image_path: str
    lora_name: str
    role_prompt: str


class ComfyClient:
    def __init__(self, base_url: str, logger):
        if base_url.endswith("/"):
            base_url = base_url[:-1]
        self.base_url = base_url
        self.logger = logger
        # 统一请求头（包含 User-Agent）
        self.default_headers = {
            "User-Agent": "p-run/1.0 (+ComfyUI client)"
        }

    def _fix_paths_in_payload(self, obj):
        """递归处理payload中的所有路径字段，将双斜杠转换为单反斜杠"""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if isinstance(value, str) and self._is_path_field(key, value):
                    # 处理路径字段：将双斜杠转换为单反斜杠
                    # 先处理双正斜杠，再处理双反斜杠
                    fixed_value = value.replace("//", "\\").replace("/", "\\").replace("\\\\", "\\")
                    result[key] = fixed_value
                else:
                    result[key] = self._fix_paths_in_payload(value)
            return result
        elif isinstance(obj, list):
            return [self._fix_paths_in_payload(item) for item in obj]
        else:
            return obj

    def _is_path_field(self, key, value):
        """判断字段是否可能包含路径"""
        # 常见的路径字段名
        path_keys = {
            'ckpt_name', 'lora_name', 'image', 'filename', 'path', 'file_path',
            'input_path', 'output_path', 'model_path', 'vae_path', 'control_net_name'
        }
        
        # 检查字段名是否包含路径相关关键词
        if any(path_key in key.lower() for path_key in path_keys):
            return True
            
        # 检查值是否看起来像路径（包含斜杠和文件扩展名）
        if isinstance(value, str) and ("/" in value or "\\" in value):
            # 检查是否包含文件扩展名
            common_extensions = {'.safetensors', '.ckpt', '.pth', '.bin', '.png', '.jpg', '.jpeg', '.webp'}
            if any(value.lower().endswith(ext) for ext in common_extensions):
                return True
                
        return False

    def submit_workflow(self, workflow_json_text: str) -> str:
        try:
            payload = json.loads(workflow_json_text)
        except Exception as exc:
            raise ValueError(f"工作流JSON解析失败: {exc}")
        # 兼容两种输入：
        # 1) 直接是ComfyUI图（各节点字典）=> 需要包裹到{"prompt": graph}
        # 2) 已经是{"prompt": graph, ...} => 直接提交
        if not isinstance(payload, dict):
            raise ValueError("工作流JSON格式错误：顶层需为对象")
        if "prompt" not in payload:
            payload = {"prompt": payload}
        
        # 处理所有路径字段，将双斜杠转换为单斜杠
        payload = self._fix_paths_in_payload(payload)
        # 增加client_id，便于服务端区分
        payload.setdefault("client_id", f"p-run-{int(time.time()*1000)}")

        url = f"{self.base_url}/prompt"
        # 优先使用raw body以兼容部分反向代理/实现差异；失败回退到requests的json参数
        try:
            headers = {"Content-Type": "application/json"}
            headers.update(self.default_headers)
            # 从配置文件获取请求超时时间
            try:
                from load_config import get_request_timeout
                timeout = get_request_timeout()
            except ImportError:
                timeout = 60
                
            resp = requests.post(url, data=json.dumps(payload, ensure_ascii=False), headers=headers, timeout=timeout)
            if resp.status_code in (400, 415) or (not resp.ok):
                # 某些实现只接受json参数或返回奇异错误，进行一次回退重试
                self.logger(f"提交raw失败(HTTP {resp.status_code})，尝试回退json方式...")
                resp = requests.post(url, json=payload, headers=self.default_headers, timeout=timeout)
        except Exception as exc:
            raise RuntimeError(f"连接ComfyUI失败: {exc}")
        if not resp.ok:
            # 返回更详细的错误内容，帮助定位
            text = None
            try:
                text = resp.text
            except Exception:
                text = "<无响应文本>"
            raise RuntimeError(f"提交工作流失败 HTTP {resp.status_code}: {text}")
        try:
            data = resp.json()
        except Exception as exc:
            raise RuntimeError(f"解析ComfyUI响应失败: {exc}; 原始文本: {resp.text[:500]}")
        prompt_id = data.get("prompt_id") or data.get("promptId")
        if not prompt_id:
            raise RuntimeError(f"提交工作流失败，未返回prompt_id: {data}")
        return prompt_id

    def wait_until_done(self, prompt_id: str, poll_interval_sec: float = 1.0, timeout_sec: int = 1800) -> dict:
        url = f"{self.base_url}/history/{prompt_id}"
        deadline = time.time() + timeout_sec
        last_err = None
        next_log_ts = time.time()  # 心跳日志节流
        while time.time() < deadline:
            try:
                resp = requests.get(url, headers=self.default_headers, timeout=15)
                if resp.status_code == 404:
                    # 可能尚未入队，稍等
                    time.sleep(poll_interval_sec)
                    continue
                resp.raise_for_status()
                data = resp.json()
                # 兼容历史接口：有些实现把结果包在 {prompt_id: {...}} 里
                if isinstance(data, dict) and prompt_id in data and isinstance(data[prompt_id], dict):
                    data = data[prompt_id]

                # ComfyUI返回的结构通常含有"status"或包含输出
                status = None
                if isinstance(data, dict):
                    # 可能的形式一：status 为字符串
                    status = data.get("status") or data.get("state")

                    # 可能的形式二：status 为对象，包含 completed/status_str
                    status_obj = data.get("status") if isinstance(data.get("status"), dict) else None
                    if status_obj:
                        if status_obj.get("completed") is True:
                            self.logger(f"运行完成: prompt {prompt_id} status=success")
                            return data
                        status_str = status_obj.get("status_str")
                        if isinstance(status_str, str) and status_str.lower() in {"completed", "success", "done"}:
                            self.logger(f"运行完成: prompt {prompt_id} status={status_str}")
                            return data

                    # 如果包含outputs则认为完成
                    outputs = data.get("outputs") or data.get("output")
                    if outputs:
                        self.logger(f"运行完成: prompt {prompt_id} outputs_ready=true")
                        return data

                    # 周期性心跳日志，避免用户误以为卡死
                    now = time.time()
                    if now >= next_log_ts:
                        status_for_log = None
                        if status_obj and isinstance(status_obj.get("status_str"), str):
                            status_for_log = status_obj.get("status_str")
                        elif isinstance(status, str):
                            status_for_log = status
                        self.logger(f"运行中: prompt {prompt_id} status={status_for_log or 'pending'}")
                        next_log_ts = now + 5

                    # 检测错误状态
                    if (isinstance(status, str) and status.lower() in {"error", "failed"}) or data.get("error") or data.get("node_errors"):
                        raise RuntimeError(f"ComfyUI执行错误: {str(data)[:500]}")

                if isinstance(status, str) and status.lower() in {"completed", "success", "done"}:
                    self.logger(f"运行完成: prompt {prompt_id} status={status}")
                    return data
            except Exception as exc:
                last_err = exc
            time.sleep(poll_interval_sec)
        raise TimeoutError(f"等待工作流完成超时: {last_err}")


class TokenDialog:
    """TOKEN输入对话框"""
    def __init__(self, parent):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("身份验证")
        self.dialog.geometry("500x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self._build_dialog()
        
    def _build_dialog(self):
        frame = tk.Frame(self.dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        title_label = tk.Label(frame, text="造序AI跑图小工具", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # 说明文字
        info_text = (
            "本程序需要身份验证才能使用。\n"
            "请联系管理员-微信号\"jack-bu\"-获取TOKEN。"
        )
        info_label = tk.Label(frame, text=info_text, justify=tk.LEFT, font=("Arial", 10))
        info_label.pack(pady=(0, 10))
        
        # MAC地址显示和复制按钮
        mac_frame = tk.Frame(frame)
        mac_frame.pack(pady=(0, 20))
        
        mac_label = tk.Label(mac_frame, text=f"本机MAC地址: {get_mac_address()}", 
                           font=("Arial", 10), fg="blue")
        mac_label.pack(side=tk.LEFT)
        
        copy_mac_btn = tk.Button(mac_frame, text="复制", command=self._copy_mac_address, 
                               width=6, font=("Arial", 9))
        copy_mac_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # TOKEN输入框
        tk.Label(frame, text="请输入TOKEN:", font=("Arial", 10)).pack(anchor="w")
        self.token_entry = tk.Entry(frame, width=50, font=("Consolas", 10), show="*")
        self.token_entry.pack(pady=(5, 20), fill=tk.X)
        self.token_entry.focus()
        
        # 按钮框架
        button_frame = tk.Frame(frame)
        button_frame.pack(fill=tk.X)
        
        # 生成TOKEN按钮（仅用于调试）
        if DEBUG_MODE:
            gen_btn = tk.Button(button_frame, text="生成TOKEN", command=self._show_token_generator)
            gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 确定和取消按钮
        ok_btn = tk.Button(button_frame, text="确定", command=self._ok_clicked, width=10)
        ok_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        cancel_btn = tk.Button(button_frame, text="取消", command=self._cancel_clicked, width=10)
        cancel_btn.pack(side=tk.RIGHT)
        
        # 绑定回车键
        self.token_entry.bind('<Return>', lambda e: self._ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self._cancel_clicked())
        
    def _show_token_generator(self):
        """显示TOKEN生成器对话框"""
        TokenGeneratorDialog(self.dialog)
        
    def _generate_token(self, valid_days=30):
        """生成TOKEN（仅调试模式）"""
        # 使用本机MAC地址生成TOKEN
        token = generate_token(valid_days=valid_days)
        self.token_entry.delete(0, tk.END)
        self.token_entry.insert(0, token)
        
        # 显示TOKEN信息
        token_info = get_token_info(token)
        info_text = f"已生成TOKEN:\n{token}\n\n"
        if 'error' not in token_info:
            info_text += f"过期时间: {token_info.get('expire_time', '未知')}\n"
            info_text += f"MAC地址: {token_info.get('mac_address', '未知')}"
        else:
            info_text += f"TOKEN解析错误: {token_info['error']}"
        messagebox.showinfo("TOKEN", info_text)
        
    def _ok_clicked(self):
        token = self.token_entry.get().strip()
        if not token:
            messagebox.showerror("错误", "请输入TOKEN")
            return
            
        is_valid, error_msg = verify_token(token)
        if is_valid:
            # 保存TOKEN到文件
            save_token_to_file(token)
            self.result = token
            self.dialog.destroy()
        else:
            messagebox.showerror("TOKEN验证失败", error_msg)
            self.token_entry.delete(0, tk.END)
            self.token_entry.focus()
            
    def _copy_mac_address(self):
        """复制MAC地址到剪贴板"""
        mac_address = get_mac_address()
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(mac_address)
        messagebox.showinfo("成功", f"MAC地址已复制到剪贴板:\n{mac_address}")
        
    def _cancel_clicked(self):
        self.result = None
        self.dialog.destroy()


class TokenGeneratorDialog:
    """TOKEN生成器对话框"""
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("TOKEN生成器")
        self.dialog.geometry("600x400")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self._build_dialog()
        
    def _build_dialog(self):
        frame = tk.Frame(self.dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        title_label = tk.Label(frame, text="TOKEN生成器", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # MAC地址显示
        mac_frame = tk.Frame(frame)
        mac_frame.pack(fill=tk.X, pady=(0, 15))
        tk.Label(mac_frame, text="本机MAC地址:", font=("Arial", 10)).pack(anchor="w")
        mac_entry = tk.Entry(mac_frame, font=("Consolas", 10), state="readonly")
        mac_entry.pack(fill=tk.X, pady=(5, 0))
        mac_entry.config(state="normal")
        mac_entry.insert(0, get_mac_address())
        mac_entry.config(state="readonly")
        
        # 有效期设置
        valid_frame = tk.Frame(frame)
        valid_frame.pack(fill=tk.X, pady=(0, 15))
        tk.Label(valid_frame, text="TOKEN有效期:", font=("Arial", 10)).pack(anchor="w")
        
        valid_input_frame = tk.Frame(valid_frame)
        valid_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.valid_days_var = tk.StringVar(value="30")
        valid_entry = tk.Entry(valid_input_frame, textvariable=self.valid_days_var, width=10, font=("Arial", 10))
        valid_entry.pack(side=tk.LEFT)
        tk.Label(valid_input_frame, text="天", font=("Arial", 10)).pack(side=tk.LEFT, padx=(5, 0))
        
        # 预设按钮
        preset_frame = tk.Frame(valid_frame)
        preset_frame.pack(fill=tk.X, pady=(5, 0))
        tk.Button(preset_frame, text="1分钟", command=lambda: self.valid_days_var.set("0.000694")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="7天", command=lambda: self.valid_days_var.set("7")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="30天", command=lambda: self.valid_days_var.set("30")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="90天", command=lambda: self.valid_days_var.set("90")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="365天", command=lambda: self.valid_days_var.set("365")).pack(side=tk.LEFT)
        
        # 生成的TOKEN显示
        token_frame = tk.Frame(frame)
        token_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        tk.Label(token_frame, text="生成的TOKEN:", font=("Arial", 10)).pack(anchor="w")
        
        # 创建滚动文本框
        text_frame = tk.Frame(token_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.token_text = scrolledtext.ScrolledText(text_frame, height=8, font=("Consolas", 9), wrap=tk.WORD)
        self.token_text.pack(fill=tk.BOTH, expand=True)
        
        # 按钮框架
        button_frame = tk.Frame(frame)
        button_frame.pack(fill=tk.X)
        
        # 生成TOKEN按钮
        gen_btn = tk.Button(button_frame, text="生成TOKEN", command=self._generate_token, width=12)
        gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 复制TOKEN按钮
        copy_btn = tk.Button(button_frame, text="复制TOKEN", command=self._copy_token, width=12)
        copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 关闭按钮
        close_btn = tk.Button(button_frame, text="关闭", command=self.dialog.destroy, width=12)
        close_btn.pack(side=tk.RIGHT)
        
    def _generate_token(self):
        """生成TOKEN"""
        try:
            valid_days = float(self.valid_days_var.get())
            if valid_days <= 0:
                messagebox.showerror("错误", "有效期必须大于0天")
                return
        except ValueError:
            messagebox.showerror("错误", "请输入有效的天数")
            return
            
        # 生成TOKEN
        token = generate_token(valid_days=valid_days)
        token_info = get_token_info(token)
        
        # 显示TOKEN信息
        info_text = f"TOKEN: {token}\n\n"
        info_text += f"MAC地址: {token_info['mac_address']}\n"
        info_text += f"过期时间: {token_info['expire_time']}\n"
        info_text += f"有效期: {valid_days}天\n"
        info_text += f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.token_text.delete(1.0, tk.END)
        self.token_text.insert(1.0, info_text)
        
    def _copy_token(self):
        """复制TOKEN到剪贴板"""
        content = self.token_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("提示", "请先生成TOKEN")
            return
            
        # 提取TOKEN（第一行）
        lines = content.split('\n')
        if lines and lines[0].startswith('TOKEN: '):
            token = lines[0][7:]  # 去掉"TOKEN: "前缀
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(token)
            messagebox.showinfo("成功", "TOKEN已复制到剪贴板")
        else:
            messagebox.showerror("错误", "无法提取TOKEN")


class TokenManagerDialog:
    """TOKEN管理器对话框（DEBUG模式专用）"""
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("TOKEN管理器 - 调试模式")
        self.dialog.geometry("700x500")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self._build_dialog()
        
    def _build_dialog(self):
        # 创建主框架
        main_frame = tk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        title_label = tk.Label(main_frame, text="TOKEN管理器", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # 创建选项卡框架
        notebook = tk.ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # 生成TOKEN选项卡
        self._create_generate_tab(notebook)
        
        # 验证TOKEN选项卡
        self._create_verify_tab(notebook)
        
        # 关闭按钮
        close_btn = tk.Button(main_frame, text="关闭", command=self.dialog.destroy, width=12)
        close_btn.pack(pady=(10, 0))
        
    def _create_generate_tab(self, notebook):
        """创建生成TOKEN选项卡"""
        generate_frame = tk.Frame(notebook)
        notebook.add(generate_frame, text="生成TOKEN")
        
        # MAC地址输入
        mac_frame = tk.Frame(generate_frame)
        mac_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(mac_frame, text="目标MAC地址:", font=("Arial", 10, "bold")).pack(anchor="w")
        
        mac_input_frame = tk.Frame(mac_frame)
        mac_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.mac_entry = tk.Entry(mac_input_frame, font=("Consolas", 10))
        self.mac_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.mac_entry.insert(0, get_mac_address())
        
        # 获取本机MAC按钮
        get_mac_btn = tk.Button(mac_input_frame, text="本机MAC", command=self._get_current_mac, width=8)
        get_mac_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # 有效期设置
        valid_frame = tk.Frame(generate_frame)
        valid_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(valid_frame, text="TOKEN有效期:", font=("Arial", 10, "bold")).pack(anchor="w")
        
        valid_input_frame = tk.Frame(valid_frame)
        valid_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.valid_days_var = tk.StringVar(value="30")
        valid_entry = tk.Entry(valid_input_frame, textvariable=self.valid_days_var, width=10, font=("Arial", 10))
        valid_entry.pack(side=tk.LEFT)
        tk.Label(valid_input_frame, text="天", font=("Arial", 10)).pack(side=tk.LEFT, padx=(5, 0))
        
        # 预设按钮
        preset_frame = tk.Frame(valid_frame)
        preset_frame.pack(fill=tk.X, pady=(5, 0))
        tk.Button(preset_frame, text="1分钟", command=lambda: self.valid_days_var.set("0.000694")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="7天", command=lambda: self.valid_days_var.set("7")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="30天", command=lambda: self.valid_days_var.set("30")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="90天", command=lambda: self.valid_days_var.set("90")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="365天", command=lambda: self.valid_days_var.set("365")).pack(side=tk.LEFT)
        
        # 生成的TOKEN显示
        token_frame = tk.Frame(generate_frame)
        token_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(token_frame, text="生成的TOKEN:", font=("Arial", 10, "bold")).pack(anchor="w")
        
        # 创建滚动文本框
        text_frame = tk.Frame(token_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.token_text = scrolledtext.ScrolledText(text_frame, height=8, font=("Consolas", 9), wrap=tk.WORD)
        self.token_text.pack(fill=tk.BOTH, expand=True)
        
        # 按钮框架 - 独立于滚动文本框
        button_frame = tk.Frame(generate_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(10, 10))
        
        # 生成TOKEN按钮
        gen_btn = tk.Button(button_frame, text="生成TOKEN", command=self._generate_token, width=12)
        gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 复制TOKEN按钮
        copy_btn = tk.Button(button_frame, text="复制TOKEN", command=self._copy_token, width=12)
        copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
    def _create_verify_tab(self, notebook):
        """创建验证TOKEN选项卡"""
        verify_frame = tk.Frame(notebook)
        notebook.add(verify_frame, text="验证TOKEN")
        
        # TOKEN输入
        input_frame = tk.Frame(verify_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(input_frame, text="输入TOKEN进行验证:", font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.verify_entry = tk.Entry(input_frame, font=("Consolas", 10), show="*")
        self.verify_entry.pack(fill=tk.X, pady=(5, 0))
        
        # 验证按钮
        verify_btn = tk.Button(input_frame, text="验证TOKEN", command=self._verify_token, width=12)
        verify_btn.pack(pady=(10, 0))
        
        # 验证结果显示
        result_frame = tk.Frame(verify_frame)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(result_frame, text="验证结果:", font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, font=("Consolas", 9), wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
    def _generate_token(self):
        """生成TOKEN"""
        try:
            valid_days = float(self.valid_days_var.get())
            if valid_days <= 0:
                messagebox.showerror("错误", "有效期必须大于0天")
                return
        except ValueError:
            messagebox.showerror("错误", "请输入有效的天数")
            return
            
        # 获取目标MAC地址
        target_mac = self.mac_entry.get().strip()
        if not target_mac:
            messagebox.showerror("错误", "请输入目标MAC地址")
            return
            
        # 验证MAC地址格式
        if not self._validate_mac_address(target_mac):
            messagebox.showerror("错误", "MAC地址格式不正确，应为 XX:XX:XX:XX:XX:XX 格式")
            return
            
        # 生成TOKEN
        token = generate_token(mac_address=target_mac, valid_days=valid_days)
        token_info = get_token_info(token)
        
        # 显示TOKEN信息
        info_text = f"TOKEN: {token}\n\n"
        if 'error' not in token_info:
            info_text += f"目标MAC地址: {token_info.get('mac_address', '未知')}\n"
            info_text += f"过期时间: {token_info.get('expire_time', '未知')}\n"
            info_text += f"有效期: {valid_days}天\n"
            info_text += f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            info_text += f"是否过期: {'是' if token_info.get('is_expired', True) else '否'}"
        else:
            info_text += f"TOKEN解析错误: {token_info['error']}\n"
            info_text += f"目标MAC地址: {target_mac}\n"
            info_text += f"有效期: {valid_days}天\n"
            info_text += f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.token_text.delete(1.0, tk.END)
        self.token_text.insert(1.0, info_text)
        
    def _copy_token(self):
        """复制TOKEN到剪贴板"""
        content = self.token_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("提示", "请先生成TOKEN")
            return
            
        # 提取TOKEN（第一行）
        lines = content.split('\n')
        if lines and lines[0].startswith('TOKEN: '):
            token = lines[0][7:]  # 去掉"TOKEN: "前缀
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(token)
            messagebox.showinfo("成功", "TOKEN已复制到剪贴板")
        else:
            messagebox.showerror("错误", "无法提取TOKEN")
    
    def _verify_token(self):
        """验证TOKEN"""
        token = self.verify_entry.get().strip()
        if not token:
            messagebox.showerror("错误", "请输入TOKEN")
            return
            
        # 验证TOKEN
        is_valid, error_msg = verify_token(token)
        token_info = get_token_info(token)
        
        # 显示验证结果
        result_text = f"验证时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        result_text += f"验证结果: {'通过' if is_valid else '失败'}\n"
        result_text += f"错误信息: {error_msg}\n\n"
        
        if 'error' not in token_info:
            result_text += f"TOKEN信息:\n"
            result_text += f"  MAC地址: {token_info.get('mac_address', '未知')}\n"
            result_text += f"  过期时间: {token_info.get('expire_time', '未知')}\n"
            result_text += f"  是否过期: {'是' if token_info.get('is_expired', True) else '否'}\n"
            result_text += f"  签名: {token_info.get('signature', '未知')}\n"
        else:
            result_text += f"TOKEN解析错误: {token_info['error']}\n"
        
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(1.0, result_text)
        self.result_text.config(state=tk.DISABLED)
        
    def _get_current_mac(self):
        """获取本机MAC地址"""
        current_mac = get_mac_address()
        self.mac_entry.delete(0, tk.END)
        self.mac_entry.insert(0, current_mac)
        
    def _validate_mac_address(self, mac):
        """验证MAC地址格式"""
        import re
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("造序AI跑图小工具")
        self.is_running = False
        self.worker_thread = None
        self.log_queue = queue.Queue()
        # 集群/并发相关
        self.task_queue: queue.Queue | None = None
        self.worker_threads: list[threading.Thread] = []
        self.stop_event = threading.Event()
        self.enqueued_paths: set[str] = set()
        self.current_token = None  # 存储当前使用的TOKEN
        self.token_check_timer = None  # TOKEN检查定时器
        self.last_model_name = None  # 记录上次使用的大模型名称
        self.model_switch_count = 0  # 模型切换次数统计
        self.model_switch_times = []  # 记录每次模型切换的时间

        # DEBUG模式下跳过TOKEN验证，直接进入主界面
        if DEBUG_MODE:
            print("DEBUG模式：跳过TOKEN验证，直接进入主界面")
            self._build_ui()
            self._drain_logs_periodically()
        else:
            # 先尝试从文件读取已保存的TOKEN
            saved_token = load_token_from_file()
            if saved_token:
                print("使用已保存的TOKEN，跳过验证对话框")
                self.current_token = saved_token
                self._build_ui()
                self._drain_logs_periodically()
                self._start_token_check_timer()  # 启动TOKEN定时检查
            else:
                # 显示TOKEN验证对话框
                token_dialog = TokenDialog(root)
                root.wait_window(token_dialog.dialog)
                
                if token_dialog.result is None:
                    # 用户取消或关闭对话框，退出程序
                    print("用户取消TOKEN输入，程序退出")
                    root.destroy()
                    return
                else:
                    self.current_token = token_dialog.result
                    self._build_ui()
                    self._drain_logs_periodically()
                    self._start_token_check_timer()  # 启动TOKEN定时检查

        # 加载上次的界面设置
        try:
            self._load_ui_settings()
        except Exception:
            pass
        # 关闭前自动保存设置
        try:
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        except Exception:
            pass

    def _build_ui(self):
        frm = tk.Frame(self.root)
        frm.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 目录地址
        tk.Label(frm, text="目录地址(项目根):").grid(row=0, column=0, sticky="w")
        self.entry_dir = tk.Entry(frm, width=60)
        self.entry_dir.grid(row=0, column=1, sticky="we", padx=6)
        # 从配置文件获取默认目录
        try:
            from load_config import get_default_project_dir
            default_dir = get_default_project_dir()
        except ImportError:
            default_dir = "Z:\\挂机跑图"
        self.entry_dir.insert(0, default_dir)
        btn_browse = tk.Button(frm, text="选择", command=self._choose_dir)
        btn_browse.grid(row=0, column=2, padx=4)

        # ComfyUI地址（表格/多行：每行一个）
        tk.Label(frm, text="ComfyUI地址列表(每行一个):").grid(row=1, column=0, sticky="nw")
        # 从配置文件获取默认ComfyUI地址
        try:
            from load_config import get_comfyui_url
            default_url = get_comfyui_url()
        except ImportError:
            default_url = "http://192.168.2.104:8188"
        self.text_nodes = scrolledtext.ScrolledText(frm, width=60, height=4)
        self.text_nodes.grid(row=1, column=1, columnspan=3, sticky="we", padx=6)
        self.text_nodes.insert("1.0", default_url)

        # 无图休眠时间(秒)
        tk.Label(frm, text="无图休眠时间(秒):").grid(row=2, column=0, sticky="w")
        self.entry_sleep = tk.Entry(frm, width=20)
        # 从配置文件获取默认休眠时间
        try:
            from load_config import get_default_sleep_time
            default_sleep = str(get_default_sleep_time())
        except ImportError:
            default_sleep = "30"
        self.entry_sleep.insert(0, default_sleep)
        self.entry_sleep.grid(row=2, column=1, sticky="w", padx=6)

        # 每台机器任务间隔(秒)
        tk.Label(frm, text="每台机器任务间隔(秒):").grid(row=2, column=2, sticky="w")
        self.entry_node_interval = tk.Entry(frm, width=6)
        self.entry_node_interval.insert(0, "3")
        self.entry_node_interval.grid(row=2, column=3, sticky="w")

        # 末端目录(可选)
        tk.Label(frm, text="末端目录(可选):").grid(row=3, column=0, sticky="w")
        self.entry_end_dir = tk.Entry(frm, width=60)
        self.entry_end_dir.grid(row=3, column=1, sticky="we", padx=6)
        tk.Label(frm, text="为空则使用: 项目名称/集数/角色/图片.JPG", 
                font=("Arial", 8), fg="gray").grid(row=4, column=1, sticky="w", padx=6)
        tk.Label(frm, text="有值则使用: 项目名称/集数/角色/末端目录/图片.JPG", 
                font=("Arial", 8), fg="gray").grid(row=5, column=1, sticky="w", padx=6)

        # 工作流信息
        tk.Label(frm, text="工作流JSON(支持占位符):").grid(row=6, column=0, sticky="nw")
        self.text_workflow = scrolledtext.ScrolledText(frm, width=80, height=16)
        self.text_workflow.grid(row=6, column=1, columnspan=2, sticky="nsew", pady=6)

        # 执行按钮
        self.btn_run = tk.Button(frm, text="执行", command=self._on_click_run)
        self.btn_run.grid(row=7, column=1, sticky="w")
        
        # TOKEN相关按钮
        token_btn_frame = tk.Frame(frm)
        token_btn_frame.grid(row=7, column=2, sticky="w", padx=(10, 0))
        
        # 重新验证TOKEN按钮
        btn_reverify = tk.Button(token_btn_frame, text="重新验证TOKEN", command=self._reverify_token, width=15)
        btn_reverify.pack(side=tk.LEFT, padx=(0, 5))
        
        # DEBUG模式下显示TOKEN管理按钮
        if DEBUG_MODE:
            btn_token = tk.Button(token_btn_frame, text="TOKEN管理", command=self._show_token_manager, width=12)
            btn_token.pack(side=tk.LEFT)

        # 日志
        tk.Label(frm, text="执行日志:").grid(row=8, column=0, sticky="nw")
        self.text_log = scrolledtext.ScrolledText(frm, width=80, height=16, state=tk.DISABLED)
        self.text_log.grid(row=8, column=1, columnspan=2, sticky="nsew")

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(6, weight=1)
        frm.rowconfigure(8, weight=1)

        # 提示占位符
        placeholder_tip = (
            "可用占位符:\n"
            "  {{LORA_NAME}} -> 项目名称/角色名称\n"
            "  {{ROLE_PROMPT}} -> 角色提示词内容\n"
            "  {{INPUT_IMAGE_PATH}} -> 待处理图片绝对路径\n"
            "  {{OUTPUT_DIR}} -> 输出目录(含日期子目录)\n"
            "    无末端目录: 项目名称/集数/角色/日期/\n"
            "    有末端目录: 项目名称/集数/角色/末端目录/日期/\n"
            "  {{MODEL_NAME}} -> 项目目录/大模型/<名称>.txt 的 <名称>\n"
            "  {{MODEL_PROMPT}} -> 上述 .txt 文件中的内容\n"
            "  {{NEGATIVE_PROMPT}} -> 项目目录/大模型/负面提示词.txt 的内容\n"
            "\n"
            "图片扫描路径:\n"
            "  无末端目录: 项目名称/集数/角色名称/图片.JPG\n"
            "  有末端目录: 项目名称/集数/角色名称/末端目录/图片.JPG\n"
        )
        self._log(placeholder_tip)

    # =============== UI 设置的保存与加载 ===============
    def _get_settings_path(self) -> str:
        return os.path.join(os.getcwd(), "ui_settings.json")

    def _save_ui_settings(self):
        try:
            settings = {
                "project_dir": self.entry_dir.get().strip(),
                "nodes": self.text_nodes.get("1.0", tk.END).strip(),
                "sleep_sec": self.entry_sleep.get().strip(),
                "node_interval": self.entry_node_interval.get().strip(),
                "end_dir": self.entry_end_dir.get().strip(),
                "workflow": self.text_workflow.get("1.0", tk.END).strip(),
            }
            with open(self._get_settings_path(), "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
            if DEBUG_MODE:
                print("UI设置已保存")
        except Exception as exc:
            if DEBUG_MODE:
                print(f"保存UI设置失败: {exc}")

    def _load_ui_settings(self):
        try:
            path = self._get_settings_path()
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                settings = json.load(f)
            # 恢复各字段
            if isinstance(settings, dict):
                val = settings.get("project_dir")
                if isinstance(val, str) and val:
                    self.entry_dir.delete(0, tk.END)
                    self.entry_dir.insert(0, val)
                val = settings.get("nodes")
                if isinstance(val, str) and val:
                    self.text_nodes.delete("1.0", tk.END)
                    self.text_nodes.insert("1.0", val)
                val = settings.get("sleep_sec")
                if isinstance(val, str) and val:
                    self.entry_sleep.delete(0, tk.END)
                    self.entry_sleep.insert(0, val)
                val = settings.get("node_interval")
                if isinstance(val, str) and val:
                    self.entry_node_interval.delete(0, tk.END)
                    self.entry_node_interval.insert(0, val)
                val = settings.get("end_dir")
                if isinstance(val, str):
                    self.entry_end_dir.delete(0, tk.END)
                    self.entry_end_dir.insert(0, val)
                val = settings.get("workflow")
                if isinstance(val, str) and val:
                    self.text_workflow.delete("1.0", tk.END)
                    self.text_workflow.insert("1.0", val)
            if DEBUG_MODE:
                print("UI设置已加载")
        except Exception as exc:
            if DEBUG_MODE:
                print(f"加载UI设置失败: {exc}")

    def _on_close(self):
        try:
            self._save_ui_settings()
        except Exception:
            pass
        try:
            self.is_running = False
            self.stop_event.set()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def _choose_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, d)
    
    def _show_token_manager(self):
        """显示TOKEN管理器（仅DEBUG模式）"""
        if DEBUG_MODE:
            TokenManagerDialog(self.root)
        else:
            messagebox.showwarning("提示", "TOKEN管理功能仅在调试模式下可用")
    
    def _reverify_token(self):
        """重新验证TOKEN"""
        # 显示TOKEN验证对话框
        token_dialog = TokenDialog(self.root)
        self.root.wait_window(token_dialog.dialog)
        
        if token_dialog.result is not None:
            # 验证成功，TOKEN已自动保存
            self.current_token = token_dialog.result
            self._log("TOKEN重新验证成功")
            messagebox.showinfo("成功", "TOKEN重新验证成功！")
            return True
        else:
            # 用户取消验证，退出程序
            self._log("TOKEN重新验证被取消，程序将退出")
            self.root.destroy()
            return False
    
    def _start_token_check_timer(self):
        """启动TOKEN定时检查"""
        if DEBUG_MODE:
            return  # DEBUG模式下不检查TOKEN
            
        # 每30秒检查一次TOKEN是否过期
        self._check_token_validity()
        self.token_check_timer = self.root.after(30000, self._start_token_check_timer)
    
    def _check_token_validity(self):
        """检查TOKEN是否仍然有效"""
        if not self.current_token:
            return
            
        is_valid, error_msg = verify_token(self.current_token)
        if not is_valid:
            self._log(f"TOKEN已失效: {error_msg}")
            self._handle_token_expired()
    
    def _handle_token_expired(self):
        """处理TOKEN过期"""
        # 停止定时检查
        if self.token_check_timer:
            self.root.after_cancel(self.token_check_timer)
            self.token_check_timer = None
        
        # 显示TOKEN过期提示并要求重新验证
        result = messagebox.askyesno(
            "TOKEN已过期", 
            "您的TOKEN已过期，需要重新验证才能继续使用。\n\n是否现在重新验证TOKEN？",
            icon="warning"
        )
        
        if result:
            # 用户选择重新验证
            if self._reverify_token():
                # 重新验证成功，重新启动定时检查
                self._start_token_check_timer()
            # 如果重新验证失败（用户取消），程序已经在_reverify_token中退出了
        else:
            # 用户选择不重新验证，退出程序
            self._log("用户选择不重新验证TOKEN，程序将退出")
            self.root.destroy()
    
    def __del__(self):
        """析构函数，清理定时器"""
        if hasattr(self, 'token_check_timer') and self.token_check_timer:
            self.root.after_cancel(self.token_check_timer)

    def _on_click_run(self):
        if not self.is_running:
            base_dir = self.entry_dir.get().strip()
            if not base_dir:
                messagebox.showwarning("提示", "请先选择/输入目录地址(项目根)")
                return
            if not os.path.isdir(base_dir):
                messagebox.showerror("错误", "目录不存在")
                return
            try:
                int(self.entry_sleep.get().strip())
            except Exception:
                messagebox.showerror("错误", "无图休眠时间必须为整数秒")
                return

            # 解析多台ComfyUI地址（多行，每行一个）
            nodes = self._parse_nodes(self.text_nodes.get("1.0", tk.END))
            if not nodes:
                messagebox.showerror("错误", "请至少配置一个有效的ComfyUI地址")
                return
            try:
                node_interval = float(self.entry_node_interval.get().strip() or "3")
                if node_interval < 0:
                    raise ValueError()
            except Exception:
                messagebox.showerror("错误", "每台机器任务间隔必须为非负数字(秒)")
                return

            self.is_running = True
            self.btn_run.config(text="停止")
            self.stop_event.clear()
            self.task_queue = queue.Queue()
            self.enqueued_paths.clear()
            # 启动扫描线程
            self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
            self.worker_thread.start()
            # 为每个节点启动一个工作线程
            self.worker_threads = []
            for node_url in nodes:
                t = threading.Thread(target=self._node_worker, args=(node_url, node_interval), daemon=True)
                t.start()
                self.worker_threads.append(t)
            self._log(f"开始执行循环... 已启动 {len(nodes)} 个节点工作线程，间隔 {node_interval}s")
        else:
            self.is_running = False
            self.btn_run.config(text="执行")
            self._log("请求停止，完成当前任务后退出...")
            self.stop_event.set()
            # 等待工作线程结束
            try:
                if self.worker_thread:
                    self.worker_thread.join(timeout=1.0)
            except Exception:
                pass
            for t in self.worker_threads:
                try:
                    t.join(timeout=1.0)
                except Exception:
                    pass

    def _drain_logs_periodically(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.root.after(200, self._drain_logs_periodically)

    def _append_log(self, text: str):
        self.text_log.config(state=tk.NORMAL)
        self.text_log.insert(tk.END, text + "\n")
        self.text_log.see(tk.END)
        self.text_log.config(state=tk.DISABLED)

    def _log(self, text: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{ts}] {text}")

    # =============== 主循环与任务处理 ===============
    def _run_loop(self):
        base_dir = self.entry_dir.get().strip()
        sleep_sec = int(self.entry_sleep.get().strip())

        while self.is_running and not self.stop_event.is_set():
            tasks = self._scan_directory_for_tasks(base_dir)
            new_count = 0
            for task in tasks:
                if self.stop_event.is_set():
                    break
                # 去重：避免重复入队相同图片
                if task.image_path in self.enqueued_paths:
                    continue
                try:
                    self.task_queue.put_nowait(task)
                    self.enqueued_paths.add(task.image_path)
                    new_count += 1
                except Exception:
                    pass

            if new_count > 0:
                self._log(f"扫描到 {new_count} 个新任务，已入队，等待节点处理...")
            else:
                self._log(f"未发现新的待处理图片，休眠 {sleep_sec} 秒...")

            for _ in range(sleep_sec):
                if not self.is_running or self.stop_event.is_set():
                    break
                time.sleep(1)

        self._log("已停止(扫描线程)。")

    def _node_worker(self, node_url: str, node_interval_sec: float):
        client = ComfyClient(node_url, self._log)
        while self.is_running and not self.stop_event.is_set():
            try:
                task: TaskItem = self.task_queue.get(timeout=1.0)
            except Exception:
                continue
            # 任务可能已被其他原因处理/移动，处理函数内部有存在性校验
            try:
                self._process_single_task(task, client)
            except Exception as exc:
                self._log(f"节点 {node_url} 处理失败: {task.image_path} -> {exc}")
            finally:
                # 从去重集合移除，允许后续重新扫描时再次入队（如果仍存在）
                try:
                    if task.image_path in self.enqueued_paths:
                        self.enqueued_paths.remove(task.image_path)
                except Exception:
                    pass
                try:
                    self.task_queue.task_done()
                except Exception:
                    pass
            # 每台机器的任务间隔
            if node_interval_sec > 0:
                for _ in range(int(max(1, node_interval_sec))):
                    if not self.is_running or self.stop_event.is_set():
                        break
                    time.sleep(1)

    def _parse_nodes(self, raw: str) -> list[str]:
        nodes: list[str] = []
        for part in raw.split(','):
            url = part.strip()
            if not url:
                continue
            # 规范化：去除末尾斜杠
            if url.endswith('/'):
                url = url[:-1]
            nodes.append(url)
        return nodes

    def _scan_directory_for_tasks(self, base_dir: str) -> list:
        tasks: list[TaskItem] = []
        # 获取末端目录设置
        end_dir = self.entry_end_dir.get().strip()
        
        # 需要匹配: 项目名称/集数/角色名称/图片.JPG 或 项目名称/集数/角色名称/末端目录/图片.JPG
        # 假设base_dir下是多个项目名称目录
        for project_name in os.listdir(base_dir):
            project_dir = os.path.join(base_dir, project_name)
            if not os.path.isdir(project_dir):
                continue

            # 角色提示词根: 项目名称/角色提示词
            role_prompt_root = os.path.join(project_dir, "角色提示词")

            for episode_name in os.listdir(project_dir):
                episode_dir = os.path.join(project_dir, episode_name)
                if not os.path.isdir(episode_dir) or episode_name == "角色提示词":
                    continue

                for role_name in os.listdir(episode_dir):
                    role_dir = os.path.join(episode_dir, role_name)
                    if not os.path.isdir(role_dir):
                        continue

                    # 根据是否有末端目录确定图片搜索路径
                    if end_dir:
                        # 有末端目录：在 角色名称/末端目录/ 下查找图片
                        image_search_dir = os.path.join(role_dir, end_dir)
                        if not os.path.isdir(image_search_dir):
                            continue
                    else:
                        # 无末端目录：直接在 角色名称/ 下查找图片
                        image_search_dir = role_dir

                    # 查找常见图片扩展名
                    for fname in os.listdir(image_search_dir):
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            continue
                        image_path = os.path.normpath(os.path.join(image_search_dir, fname))

                        # 目标完成目录
                        if end_dir:
                            # 有末端目录：完成目录在 角色名称/末端目录/完成/
                            done_dir = os.path.join(image_search_dir, "完成")
                        else:
                            # 无末端目录：完成目录在 角色名称/完成/
                            done_dir = os.path.join(role_dir, "完成")
                            
                        if os.path.isdir(done_dir) and os.path.exists(os.path.join(done_dir, fname)):
                            # 已完成
                            continue

                        # 组成LORA名称: 项目名称/角色名称
                        lora_name = f"{project_name}/{role_name}"

                        # 读取角色提示词: 项目名称/角色提示词/角色名称.txt
                        role_prompt_path = os.path.join(role_prompt_root, f"{role_name}.txt")
                        role_prompt = ""
                        if os.path.isfile(role_prompt_path):
                            try:
                                with open(role_prompt_path, "r", encoding="utf-8") as f:
                                    role_prompt = f.read().strip()
                            except Exception:
                                role_prompt = ""
                        else:
                            # 未找到提示词，跳过并告警
                            self._log(f"未找到角色提示词: {role_prompt_path}")
                            continue

                        tasks.append(
                            TaskItem(
                                project_name=project_name,
                                episode_name=episode_name,
                                role_name=role_name,
                                image_path=image_path,
                                lora_name=lora_name,
                                role_prompt=role_prompt,
                            )
                        )
        # 稳定排序，按路径
        tasks.sort(key=lambda t: t.image_path)
        return tasks

    def _prepare_workflow_text(self, task: TaskItem) -> str:
        raw = self.text_workflow.get("1.0", tk.END).strip()
        if not raw:
            raise ValueError("请在界面粘贴工作流JSON")
        # 简单占位符替换
        abs_image_path = os.path.abspath(task.image_path)
        # 规范化路径，确保使用正确的路径分隔符
        abs_image_path = os.path.normpath(abs_image_path)
        
        # 获取末端目录设置
        end_dir = self.entry_end_dir.get().strip()
        
        # 解析路径结构
        if end_dir:
            # 有末端目录：项目/集数/角色/末端目录/图片
            end_dir_path = os.path.dirname(abs_image_path)  # 末端目录路径
            role_dir = os.path.dirname(end_dir_path)        # 角色目录
        else:
            # 无末端目录：项目/集数/角色/图片
            role_dir = os.path.dirname(abs_image_path)      # 角色目录
            
        # 构建输出目录路径
        if end_dir:
            # 有末端目录：项目名称/集数/角色/末端目录/日期/
            output_dir = os.path.join(role_dir, end_dir)
        else:
            # 无末端目录：项目名称/集数/角色/日期/
            output_dir = role_dir
            
        # 为输出目录追加按天日期子目录
        date_str = datetime.now().strftime("%Y-%m-%d")
        output_dir_with_date = os.path.join(output_dir, date_str)
        
        # 解析项目目录 -> 寻找 大模型/*.txt
        episode_dir = os.path.dirname(role_dir)             # 集数目录
        project_dir = os.path.dirname(episode_dir)          # 项目目录
        model_dir = os.path.join(project_dir, "大模型")
        model_name = ""
        model_prompt = ""
        negative_prompt = ""
        try:
            if os.path.isdir(model_dir):
                # 获取大模型名称：查找除负面提示词.txt外的其他txt文件
                all_files = os.listdir(model_dir)
                txt_files = [f for f in all_files if f.lower().endswith('.txt')]
                model_txt_files = [f for f in txt_files if f != '负面提示词.txt']
                
                if model_txt_files:
                    # 取第一个非负面提示词txt文件作为模型名称和基础提示词
                    model_txt_files.sort()
                    chosen = model_txt_files[0]
                    model_name = os.path.splitext(chosen)[0]
                    
                    # 检测模型切换
                    if self.last_model_name is not None and self.last_model_name != model_name:
                        self.model_switch_count += 1
                        switch_time = time.time()
                        self.model_switch_times.append(switch_time)
                        self._log(f"🔄 检测到模型切换: {self.last_model_name} -> {model_name} (第{self.model_switch_count}次切换)")
                        self._log("💡 提示: 即使通过API调用，模型切换仍会影响GPU缓存和性能")
                        self._log("📊 建议: 按项目分组处理，避免频繁切换模型")
                    
                    self.last_model_name = model_name
                    
                    # 读取模型基础提示词
                    model_file = os.path.join(model_dir, chosen)
                    with open(model_file, 'r', encoding='utf-8') as f:
                        model_prompt = f.read().strip()
                else:
                    self._log(f"未在大模型目录找到模型txt文件: {model_dir}")
                
                # 读取负面提示词
                negative_file = os.path.join(model_dir, "负面提示词.txt")
                if os.path.isfile(negative_file):
                    with open(negative_file, 'r', encoding='utf-8') as f:
                        negative_prompt = f.read().strip()
                else:
                    self._log(f"未找到负面提示词文件: {negative_file}")
            else:
                self._log(f"大模型目录不存在: {model_dir}")
        except Exception as exc:
            self._log(f"读取大模型信息失败: {exc}")

        # JSON-safe 转义函数（最少化转义）
        def _json_escape(s: str) -> str:
            return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')

        # JSON 字符串中的反斜杠需要转义为 \\
        escaped_image_path = abs_image_path.replace("\\", "\\\\")
        escaped_output_dir = output_dir_with_date.replace("\\", "\\\\")
        escaped_model_name = _json_escape(model_name)
        escaped_model_prompt = _json_escape(model_prompt)
        escaped_negative_prompt = _json_escape(negative_prompt)
        replaced = (
            raw.replace("{{LORA_NAME}}", task.lora_name)
            .replace("{{ROLE_PROMPT}}", task.role_prompt)
            .replace("{{INPUT_IMAGE_PATH}}", escaped_image_path)
            .replace("{{OUTPUT_DIR}}", escaped_output_dir)
            .replace("{{MODEL_NAME}}", escaped_model_name)
            .replace("{{MODEL_PROMPT}}", escaped_model_prompt)
            .replace("{{NEGATIVE_PROMPT}}", escaped_negative_prompt)
        )
        # 验证JSON
        json.loads(replaced)
        return replaced
    

    def _process_single_task(self, task: TaskItem, client: ComfyClient):
        # 规范化路径，确保使用正确的路径分隔符
        task.image_path = os.path.normpath(task.image_path)
        self._log(f"开始处理: {task.image_path}")
        start = time.time()
        
        # 记录处理开始时间，用于性能分析
        process_start_time = time.time()
        
        # 检查源文件是否存在
        if not os.path.exists(task.image_path):
            self._log(f"警告: 源文件不存在，跳过处理: {task.image_path}")
            return
            
        try:
            workflow_text = self._prepare_workflow_text(task)
            prompt_id = client.submit_workflow(workflow_text)
            self._log(f"提交成功，prompt_id={prompt_id}")
            # 从配置文件获取工作流超时时间
            try:
                from load_config import get_workflow_timeout
                workflow_timeout = get_workflow_timeout()
            except ImportError:
                workflow_timeout = 900
            _ = client.wait_until_done(prompt_id, timeout_sec=workflow_timeout)
        except Exception as exc:
            # 失败：移动到失败目录并记录，避免后续死循环重复处理
            role_dir = os.path.dirname(task.image_path)
            fail_dir = os.path.join(role_dir, "失败")
            os.makedirs(fail_dir, exist_ok=True)
            base_name = os.path.basename(task.image_path)
            dest_fail = os.path.join(fail_dir, base_name)
            if os.path.exists(dest_fail):
                name, ext = os.path.splitext(base_name)
                dest_fail = os.path.join(fail_dir, f"{name}_{int(time.time())}{ext}")
            
            # 再次检查源文件是否存在
            if os.path.exists(task.image_path):
                try:
                    shutil.move(task.image_path, dest_fail)
                except Exception:
                    try:
                        shutil.copy2(task.image_path, dest_fail)
                        os.remove(task.image_path)
                    except Exception:
                        pass
                ts_fail = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._log(f"失败: {task.image_path} -> {dest_fail} 错误: {exc}")
                self._append_run_log_file(task.image_path + " [FAILED]", time.time() - start, ts_fail)
            else:
                self._log(f"失败: 源文件已不存在，无法移动: {task.image_path} 错误: {exc}")
                self._append_run_log_file(task.image_path + " [FAILED - FILE NOT FOUND]", time.time() - start, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return

        cost = time.time() - start

        # 性能分析和建议
        if cost > 60:  # 如果处理时间超过60秒
            self._log(f"⚠️ 性能警告: 处理时间较长 ({cost:.1f}s)")
            if self.model_switch_count > 0:
                self._log(f"💡 优化建议: 已检测到{self.model_switch_count}次模型切换，建议:")
                self._log("   1. 按项目分组处理，避免频繁切换模型")
                self._log("   2. 相同模型的图片批量处理")
                self._log("   3. 考虑增加ComfyUI的内存和显存")
                
        # 分析模型切换对性能的影响
        if self.model_switch_count > 0 and len(self.model_switch_times) > 0:
            # 计算最近一次模型切换后的处理时间
            recent_switch_time = self.model_switch_times[-1]
            time_since_switch = time.time() - recent_switch_time
            if time_since_switch < 300:  # 5分钟内
                self._log(f"🔍 性能分析: 距离上次模型切换 {time_since_switch:.1f}秒，当前处理时间 {cost:.1f}秒")
                if cost > 45:  # 如果处理时间超过45秒
                    self._log("⚠️ 确认: 模型切换确实影响了GPU缓存，导致性能下降")

        # 成功：移动到完成目录
        role_dir = os.path.dirname(task.image_path)
        done_dir = os.path.join(role_dir, "完成")
        os.makedirs(done_dir, exist_ok=True)
        dest = os.path.join(done_dir, os.path.basename(task.image_path))
        
        # 检查源文件是否存在
        if os.path.exists(task.image_path):
            try:
                shutil.move(task.image_path, dest)
            except Exception:
                # 可能跨盘，改为copy+remove
                shutil.copy2(task.image_path, dest)
                os.remove(task.image_path)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._log(f"完成: {task.image_path} -> {dest} 用时 {cost:.1f}s @ {ts}")
            # 追加运行日志到文件
            self._append_run_log_file(task.image_path, cost, ts)
        else:
            self._log(f"警告: 源文件已不存在，无法移动到完成目录: {task.image_path}")
            self._append_run_log_file(task.image_path + " [COMPLETED - FILE NOT FOUND]", cost, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def _append_run_log_file(self, image_path: str, cost_sec: float, ts: str):
        try:
            with open("run.log", "a", encoding="utf-8") as f:
                f.write(f"{ts}\t{image_path}\t{cost_sec:.1f}s\n")
        except Exception:
            pass


def main():
    root = tk.Tk()
    app = App(root)
    
    # 检查窗口是否仍然存在（用户可能取消了TOKEN输入）
    try:
        root.minsize(900, 700)
        root.mainloop()
    except tk.TclError:
        # 窗口已被销毁，程序正常退出
        pass


if __name__ == "__main__":
    main()


