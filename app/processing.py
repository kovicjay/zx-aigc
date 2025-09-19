"""
处理服务(ProcessingService)

职责:
- 封装单任务的完整处理流程(准备workflow/提交/等待/落盘)

注入:
- prepare_workflow_text: 由UI/业务层提供占位符替换
- log_func, append_run_log_file: 复用主程序日志
"""

import os
import shutil
import time
from datetime import datetime
from typing import Callable

from app.client import ComfyClient
from app.models import TaskItem


class ProcessingService:
    def __init__(
        self,
        prepare_workflow_text: Callable[[TaskItem], str],
        log_func: Callable[[str], None],
        append_run_log_file: Callable[[str, float, str], None],
    ) -> None:
        self.prepare_workflow_text = prepare_workflow_text
        self.log = log_func
        self.append_run_log_file = append_run_log_file

    def process(self, task: TaskItem, client: ComfyClient):
        task.image_path = os.path.normpath(task.image_path)
        self.log(f"开始处理: {task.image_path}")
        start = time.time()

        if not os.path.exists(task.image_path):
            self.log(f"警告: 源文件不存在，跳过处理: {task.image_path}")
            return

        try:
            workflow_text = self.prepare_workflow_text(task)
            prompt_id = client.submit_workflow(workflow_text)
            self.log(f"提交成功，prompt_id={prompt_id}")
            try:
                from load_config import get_workflow_timeout
                workflow_timeout = get_workflow_timeout()
            except Exception:
                workflow_timeout = 900
            _ = client.wait_until_done(prompt_id, timeout_sec=workflow_timeout)
        except Exception as exc:
            role_dir = os.path.dirname(task.image_path)
            fail_dir = os.path.join(role_dir, "失败")
            os.makedirs(fail_dir, exist_ok=True)
            base_name = os.path.basename(task.image_path)
            dest_fail = os.path.join(fail_dir, base_name)
            if os.path.exists(dest_fail):
                name, ext = os.path.splitext(base_name)
                dest_fail = os.path.join(fail_dir, f"{name}_{int(time.time())}{ext}")
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
                self.log(f"失败: {task.image_path} -> {dest_fail} 错误: {exc}")
                self.append_run_log_file(task.image_path + " [FAILED]", time.time() - start, ts_fail)
            else:
                self.log(f"失败: 源文件已不存在，无法移动: {task.image_path} 错误: {exc}")
                self.append_run_log_file(
                    task.image_path + " [FAILED - FILE NOT FOUND]",
                    time.time() - start,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
            return

        cost = time.time() - start

        role_dir = os.path.dirname(task.image_path)
        done_dir = os.path.join(role_dir, "完成")
        os.makedirs(done_dir, exist_ok=True)
        dest = os.path.join(done_dir, os.path.basename(task.image_path))

        if os.path.exists(task.image_path):
            try:
                shutil.move(task.image_path, dest)
            except Exception:
                shutil.copy2(task.image_path, dest)
                os.remove(task.image_path)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log(f"完成: {task.image_path} -> {dest} 用时 {cost:.1f}s @ {ts}")
            self.append_run_log_file(task.image_path, cost, ts)
        else:
            self.log(f"警告: 源文件已不存在，无法移动到完成目录: {task.image_path}")
            self.append_run_log_file(
                task.image_path + " [COMPLETED - FILE NOT FOUND]",
                cost,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )


