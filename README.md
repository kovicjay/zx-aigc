## ComfyUI 跑图小工具

### 功能
- 扫描目录结构：`项目名称/集数/角色名称/图片.jpg`
- 自动读取角色提示词：`项目名称/角色提示词/角色名称.txt`
- 将占位符注入工作流JSON并调用 ComfyUI `/prompt` 接口
- 任务完成后将原始图片移动到同路径下的`完成/`目录
- 所有执行日志输出到界面，同时追加到`run.log`
- 无图时按配置的秒数休眠后自动再次扫描

### 占位符
- `{{LORA_NAME}}`：`项目名称/角色名称`
- `{{ROLE_PROMPT}}`：角色提示词文件内容
- `{{INPUT_IMAGE_PATH}}`：待处理图片的绝对路径
- `{{OUTPUT_DIR}}`：图片所在目录下的`YYYY-MM-DD`子目录
- `{{MODEL_NAME}}`：`项目目录/大模型/<名称>.txt` 的 `<名称>`
- `{{MODEL_PROMPT}}`：上述 `.txt` 文件内容

### 环境
1. 安装依赖
```bash
pip install -r requirements.txt
```
2. 启动 ComfyUI（默认 `http://127.0.0.1:8188`，可在界面修改）

### 运行
```bash
python main.py
```

### 使用步骤
1. 选择或输入项目根目录
2. 粘贴/编辑工作流JSON（包含上述占位符）
3. 设置无图休眠秒数
4. 点击“执行”开始；再次点击可停止

### 目录规范示例
```
项目A/
  角色提示词/
    小明.txt
    小红.txt
  第1集/
    小明/
      001.jpg
      002.jpg
    小红/
      a.jpg
```

### 日志
- 界面日志自动滚动
- 追加文件：`run.log`（格式：时间\t图片路径\t耗时s）

### 注意
- 
### 一键打包（Windows）

支持两种方式：

1) PowerShell
```powershell
./build.ps1
```

2) CMD (.bat)
```bat
build.bat
```

脚本会：
- 创建虚拟环境 `.venv`
- 安装 `requirements.txt`
- 安装 `pyinstaller`
- 生成可执行程序到 `dist/p-run`

将 `dist/p-run` 文件夹拷贝到其它电脑，直接运行 `p-run.exe` 即可。
- 角色提示词缺失会跳过该角色并记录告警
- 若跨盘移动失败，会采用拷贝后删除的回退策略

