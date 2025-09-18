from dataclasses import dataclass


@dataclass
class TaskItem:
    project_name: str
    episode_name: str
    role_name: str
    image_path: str
    lora_name: str
    role_prompt: str


