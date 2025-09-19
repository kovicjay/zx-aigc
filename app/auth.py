"""
鉴权模块

职责:
- TOKEN 生成/验证/持久化
- 身份验证对话框与调试生成器

说明:
- 与硬件绑定(get_mac_address)，保持与 main 的 UI 解耦
"""

import os
import uuid
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, scrolledtext


def get_mac_address():
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))


def generate_token(mac_address=None, valid_days=30):
    if mac_address is None:
        mac_address = get_mac_address()
    expire_timestamp = int((datetime.now() + timedelta(days=valid_days)).timestamp())
    mac_clean = mac_address.replace(":", "-")
    token_data = f"{mac_clean}:{expire_timestamp}"
    secret_key = "p-run-secret-key-2025"
    signature = hmac.new(secret_key.encode('utf-8'), token_data.encode('utf-8'), hashlib.sha256).hexdigest()
    full_token = f"{token_data}:{signature}"
    encoded_token = base64.b64encode(full_token.encode('utf-8')).decode('utf-8')
    return encoded_token


def verify_token(input_token):
    try:
        decoded_token = base64.b64decode(input_token.encode('utf-8')).decode('utf-8')
        parts = decoded_token.split(':')
        if len(parts) != 3:
            return False, "TOKEN格式错误"
        mac_clean, expire_timestamp_str, signature = parts
        mac_address = mac_clean.replace("-", ":")
        current_mac = get_mac_address()
        if mac_address != current_mac:
            return False, "TOKEN不匹配当前设备"
        token_data = f"{mac_clean}:{expire_timestamp_str}"
        secret_key = "p-run-secret-key-2025"
        expected_signature = hmac.new(secret_key.encode('utf-8'), token_data.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return False, "TOKEN签名验证失败"
        expire_timestamp = int(expire_timestamp_str)
        current_timestamp = int(datetime.now().timestamp())
        if current_timestamp > expire_timestamp:
            expire_time = datetime.fromtimestamp(expire_timestamp)
            return False, f"TOKEN已过期（过期时间: {expire_time.strftime('%Y-%m-%d %H:%M:%S')}）"
        return True, "验证成功"
    except Exception as e:
        return False, f"TOKEN解析失败: {str(e)}"


def get_token_info(token):
    try:
        decoded_token = base64.b64decode(token.encode('utf-8')).decode('utf-8')
        parts = decoded_token.split(':')
        if len(parts) != 3:
            return {"error": "TOKEN格式错误"}
        mac_clean, expire_timestamp_str, signature = parts
        mac_address = mac_clean.replace("-", ":")
        expire_time = datetime.fromtimestamp(int(expire_timestamp_str))
        return {
            "mac_address": mac_address,
            "expire_time": expire_time.strftime('%Y-%m-%d %H:%M:%S'),
            "is_expired": datetime.now().timestamp() > int(expire_timestamp_str),
            "signature": signature[:16] + "..."
        }
    except Exception as e:
        return {"error": str(e)}


def save_token_to_file(token):
    try:
        token_file = "saved_token.txt"
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(token)
        print(f"TOKEN已保存到 {token_file}")
    except Exception as e:
        print(f"保存TOKEN失败: {e}")


def load_token_from_file():
    try:
        token_file = "saved_token.txt"
        if not os.path.exists(token_file):
            return None
        with open(token_file, "r", encoding="utf-8") as f:
            token = f.read().strip()
        if token:
            is_valid, error_msg = verify_token(token)
            if is_valid:
                print(f"从文件读取到有效TOKEN")
                return token
            else:
                print(f"文件中的TOKEN已失效: {error_msg}")
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


class TokenDialog:
    def __init__(self, parent, debug_mode=False):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("身份验证")
        self.dialog.geometry("500x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        self._build_dialog(debug_mode)

    def _build_dialog(self, debug_mode: bool):
        frame = tk.Frame(self.dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        title_label = tk.Label(frame, text="造序AI跑图小工具", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        info_text = (
            "本程序需要身份验证才能使用。\n"
            "请联系管理员-微信号\"jack-bu\"-获取TOKEN。"
        )
        info_label = tk.Label(frame, text=info_text, justify=tk.LEFT, font=("Arial", 10))
        info_label.pack(pady=(0, 10))
        mac_frame = tk.Frame(frame)
        mac_frame.pack(pady=(0, 20))
        mac_label = tk.Label(mac_frame, text=f"本机MAC地址: {get_mac_address()}", font=("Arial", 10), fg="blue")
        mac_label.pack(side=tk.LEFT)
        copy_mac_btn = tk.Button(mac_frame, text="复制", command=self._copy_mac_address, width=6, font=("Arial", 9))
        copy_mac_btn.pack(side=tk.LEFT, padx=(10, 0))
        tk.Label(frame, text="请输入TOKEN:", font=("Arial", 10)).pack(anchor="w")
        self.token_entry = tk.Entry(frame, width=50, font=("Consolas", 10), show="*")
        self.token_entry.pack(pady=(5, 20), fill=tk.X)
        self.token_entry.focus()
        button_frame = tk.Frame(frame)
        button_frame.pack(fill=tk.X)
        if debug_mode:
            gen_btn = tk.Button(button_frame, text="生成TOKEN", command=self._show_token_generator)
            gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        ok_btn = tk.Button(button_frame, text="确定", command=self._ok_clicked, width=10)
        ok_btn.pack(side=tk.RIGHT, padx=(10, 0))
        cancel_btn = tk.Button(button_frame, text="取消", command=self._cancel_clicked, width=10)
        cancel_btn.pack(side=tk.RIGHT)
        self.token_entry.bind('<Return>', lambda e: self._ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self._cancel_clicked())

    def _show_token_generator(self):
        TokenGeneratorDialog(self.dialog)

    def _generate_token(self, valid_days=30):
        token = generate_token(valid_days=valid_days)
        self.token_entry.delete(0, tk.END)
        self.token_entry.insert(0, token)
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
            save_token_to_file(token)
            self.result = token
            self.dialog.destroy()
        else:
            messagebox.showerror("TOKEN验证失败", error_msg)
            self.token_entry.delete(0, tk.END)
            self.token_entry.focus()

    def _cancel_clicked(self):
        self.result = None
        self.dialog.destroy()

    def _copy_mac_address(self):
        mac_address = get_mac_address()
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(mac_address)
        messagebox.showinfo("成功", f"MAC地址已复制到剪贴板:\n{mac_address}")


class TokenGeneratorDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("TOKEN生成器")
        self.dialog.geometry("600x400")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        self._build_dialog()

    def _build_dialog(self):
        frame = tk.Frame(self.dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        title_label = tk.Label(frame, text="TOKEN生成器", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        mac_frame = tk.Frame(frame)
        mac_frame.pack(fill=tk.X, pady=(0, 15))
        tk.Label(mac_frame, text="本机MAC地址:", font=("Arial", 10)).pack(anchor="w")
        mac_entry = tk.Entry(mac_frame, font=("Consolas", 10), state="readonly")
        mac_entry.pack(fill=tk.X, pady=(5, 0))
        mac_entry.config(state="normal")
        mac_entry.insert(0, get_mac_address())
        mac_entry.config(state="readonly")
        valid_frame = tk.Frame(frame)
        valid_frame.pack(fill=tk.X, pady=(0, 15))
        tk.Label(valid_frame, text="TOKEN有效期:", font=("Arial", 10)).pack(anchor="w")
        valid_input_frame = tk.Frame(valid_frame)
        valid_input_frame.pack(fill=tk.X, pady=(5, 0))
        self.valid_days_var = tk.StringVar(value="30")
        valid_entry = tk.Entry(valid_input_frame, textvariable=self.valid_days_var, width=10, font=("Arial", 10))
        valid_entry.pack(side=tk.LEFT)
        tk.Label(valid_input_frame, text="天", font=("Arial", 10)).pack(side=tk.LEFT, padx=(5, 0))
        preset_frame = tk.Frame(valid_frame)
        preset_frame.pack(fill=tk.X, pady=(5, 0))
        tk.Button(preset_frame, text="1分钟", command=lambda: self.valid_days_var.set("0.000694")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="7天", command=lambda: self.valid_days_var.set("7")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="30天", command=lambda: self.valid_days_var.set("30")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="90天", command=lambda: self.valid_days_var.set("90")).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(preset_frame, text="365天", command=lambda: self.valid_days_var.set("365")).pack(side=tk.LEFT)
        token_frame = tk.Frame(frame)
        token_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        tk.Label(token_frame, text="生成的TOKEN:", font=("Arial", 10)).pack(anchor="w")
        text_frame = tk.Frame(token_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.token_text = scrolledtext.ScrolledText(text_frame, height=8, font=("Consolas", 9), wrap=tk.WORD)
        self.token_text.pack(fill=tk.BOTH, expand=True)
        button_frame = tk.Frame(frame)
        button_frame.pack(fill=tk.X)
        gen_btn = tk.Button(button_frame, text="生成TOKEN", command=self._generate_token, width=12)
        gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        copy_btn = tk.Button(button_frame, text="复制TOKEN", command=self._copy_token, width=12)
        copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        close_btn = tk.Button(button_frame, text="关闭", command=self.dialog.destroy, width=12)
        close_btn.pack(side=tk.RIGHT)

    def _generate_token(self):
        try:
            valid_days = float(self.valid_days_var.get())
            if valid_days <= 0:
                messagebox.showerror("错误", "有效期必须大于0天")
                return
        except ValueError:
            messagebox.showerror("错误", "请输入有效的天数")
            return
        token = generate_token(valid_days=valid_days)
        token_info = get_token_info(token)
        info_text = f"TOKEN: {token}\n\n"
        info_text += f"MAC地址: {token_info['mac_address']}\n"
        info_text += f"过期时间: {token_info['expire_time']}\n"
        info_text += f"有效期: {valid_days}天\n"
        info_text += f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.token_text.delete(1.0, tk.END)
        self.token_text.insert(1.0, info_text)

    def _copy_token(self):
        content = self.token_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("提示", "请先生成TOKEN")
            return
        lines = content.split('\n')
        if lines and lines[0].startswith('TOKEN: '):
            token = lines[0][7:]
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(token)
            messagebox.showinfo("成功", "TOKEN已复制到剪贴板")
        else:
            messagebox.showerror("错误", "无法提取TOKEN")


