"""
并发调度器(ClusterRunner)

职责:
- 维护共享任务队列
- 为每个节点创建工作线程，按间隔执行
- 提供入队、启动、停止的统一接口

约定:
- 通过 set_process_func 注入真正的单任务处理函数
"""

import os
import time
import threading
import queue
from datetime import datetime
from typing import Callable, Iterable

from app.client import ComfyClient
from app.models import TaskItem


class ClusterRunner:
    def __init__(self, logger: Callable[[str], None]):
        self.logger = logger
        self.task_queue: queue.Queue[TaskItem] | None = None
        self.enqueued_paths: set[str] = set()
        self.worker_threads: list[threading.Thread] = []
        self.stop_event = threading.Event()
        # 钩子
        self.process_func: Callable[[TaskItem, ComfyClient], None] | None = None

    def start(self, node_urls: list[str], node_interval_sec: float):
        self.stop_event.clear()
        self.task_queue = queue.Queue()
        self.enqueued_paths.clear()
        self.worker_threads = []
        for node_url in node_urls:
            t = threading.Thread(target=self._node_worker, args=(node_url, node_interval_sec), daemon=True)
            t.start()
            self.worker_threads.append(t)
        self.logger(f"已启动 {len(node_urls)} 个节点工作线程，间隔 {node_interval_sec}s")

    def stop(self):
        self.stop_event.set()
        for t in self.worker_threads:
            try:
                t.join(timeout=1.0)
            except Exception:
                pass
        self.worker_threads.clear()

    def enqueue_tasks(self, tasks: Iterable[TaskItem]) -> int:
        new_count = 0
        for task in tasks:
            if self.stop_event.is_set():
                break
            if task.image_path in self.enqueued_paths:
                continue
            try:
                self.task_queue.put_nowait(task)
                self.enqueued_paths.add(task.image_path)
                new_count += 1
            except Exception:
                pass
        return new_count

    def _node_worker(self, node_url: str, node_interval_sec: float):
        client = ComfyClient(node_url, self.logger)
        while not self.stop_event.is_set():
            try:
                task: TaskItem = self.task_queue.get(timeout=1.0)
            except Exception:
                continue
            try:
                if self.process_func is None:
                    raise RuntimeError("未设置处理函数 process_func")
                self.process_func(task, client)
            except Exception as exc:
                self.logger(f"节点 {node_url} 处理失败: {task.image_path} -> {exc}")
            finally:
                try:
                    if task.image_path in self.enqueued_paths:
                        self.enqueued_paths.remove(task.image_path)
                except Exception:
                    pass
                try:
                    self.task_queue.task_done()
                except Exception:
                    pass
            if node_interval_sec > 0:
                for _ in range(int(max(1, node_interval_sec))):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)

    def set_process_func(self, func: Callable[[TaskItem, ComfyClient], None]):
        self.process_func = func


