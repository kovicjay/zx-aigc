"""
ComfyUI 客户端

职责:
- 负责与 ComfyUI HTTP 接口交互
- 提供提交 workflow 与等待完成的能力

注意:
- 仅做API调用与简单payload路径修正，不包含业务逻辑
"""

import json
import time
import requests


class ComfyClient:
    def __init__(self, base_url: str, logger):
        if base_url.endswith("/"):
            base_url = base_url[:-1]
        self.base_url = base_url
        self.logger = logger
        self.default_headers = {
            "User-Agent": "p-run/1.0 (+ComfyUI client)"
        }

    def _fix_paths_in_payload(self, obj):
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if isinstance(value, str) and self._is_path_field(key, value):
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
        path_keys = {
            'ckpt_name', 'lora_name', 'image', 'filename', 'path', 'file_path',
            'input_path', 'output_path', 'model_path', 'vae_path', 'control_net_name'
        }
        if any(path_key in key.lower() for path_key in path_keys):
            return True
        if isinstance(value, str) and ("/" in value or "\\" in value):
            common_extensions = {'.safetensors', '.ckpt', '.pt', '.pth', '.bin', '.png', '.jpg', '.jpeg', '.webp'}
            if any(value.lower().endswith(ext) for ext in common_extensions):
                return True
        return False

    def submit_workflow(self, workflow_json_text: str) -> str:
        try:
            payload = json.loads(workflow_json_text)
        except Exception as exc:
            raise ValueError(f"工作流JSON解析失败: {exc}")
        if not isinstance(payload, dict):
            raise ValueError("工作流JSON格式错误：顶层需为对象")
        if "prompt" not in payload:
            payload = {"prompt": payload}
        payload = self._fix_paths_in_payload(payload)
        payload.setdefault("client_id", f"p-run-{int(time.time()*1000)}")

        url = f"{self.base_url}/prompt"
        try:
            headers = {"Content-Type": "application/json"}
            headers.update(self.default_headers)
            try:
                from load_config import get_request_timeout
                timeout = get_request_timeout()
            except Exception:
                timeout = 60
            resp = requests.post(url, data=json.dumps(payload, ensure_ascii=False), headers=headers, timeout=timeout)
            if resp.status_code in (400, 415) or (not resp.ok):
                self.logger(f"提交raw失败(HTTP {resp.status_code})，尝试回退json方式...")
                resp = requests.post(url, json=payload, headers=self.default_headers, timeout=timeout)
        except Exception as exc:
            raise RuntimeError(f"连接ComfyUI失败: {exc}")
        if not resp.ok:
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
        next_log_ts = time.time()
        while time.time() < deadline:
            try:
                import requests
                resp = requests.get(url, headers=self.default_headers, timeout=15)
                if resp.status_code == 404:
                    time.sleep(poll_interval_sec)
                    continue
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, dict) and prompt_id in data and isinstance(data[prompt_id], dict):
                    data = data[prompt_id]
                status = None
                if isinstance(data, dict):
                    status = data.get("status") or data.get("state")
                    status_obj = data.get("status") if isinstance(data.get("status"), dict) else None
                    if status_obj:
                        if status_obj.get("completed") is True:
                            self.logger(f"运行完成: prompt {prompt_id} status=success")
                            return data
                        status_str = status_obj.get("status_str")
                        if isinstance(status_str, str) and status_str.lower() in {"completed", "success", "done"}:
                            self.logger(f"运行完成: prompt {prompt_id} status={status_str}")
                            return data
                    outputs = data.get("outputs") or data.get("output")
                    if outputs:
                        self.logger(f"运行完成: prompt {prompt_id} outputs_ready=true")
                        return data
                    now = time.time()
                    if now >= next_log_ts:
                        status_for_log = None
                        if status_obj and isinstance(status_obj.get("status_str"), str):
                            status_for_log = status_obj.get("status_str")
                        elif isinstance(status, str):
                            status_for_log = status
                        self.logger(f"运行中: prompt {prompt_id} status={status_for_log or 'pending'}")
                        next_log_ts = now + 5
                    if (isinstance(status, str) and status.lower() in {"error", "failed"}) or data.get("error") or data.get("node_errors"):
                        raise RuntimeError(f"ComfyUI执行错误: {str(data)[:500]}")
                if isinstance(status, str) and status.lower() in {"completed", "success", "done"}:
                    self.logger(f"运行完成: prompt {prompt_id} status={status}")
                    return data
            except Exception as exc:
                last_err = exc
            time.sleep(poll_interval_sec)
        raise TimeoutError(f"等待工作流完成超时: {last_err}")


