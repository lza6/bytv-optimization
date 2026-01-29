# 📺 DecoTV Manager V5 - 现代化多实例部署与运维系统

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg) ![Python](https://img.shields.io/badge/Python-3.8%2B-yellow) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-green) ![Docker](https://img.shields.io/badge/Container-Docker-blue)

> **"技术的本质是让人自由，而不是设限。他行，你也行。"** 🚀
> 
> *Technology should empower, not restrict. If they can do it, so can you.*

---

## 📖 目录 (Table of Contents)

1. [项目哲学与价值观](#-项目哲学与价值观-philosophy)
2. [这是什么？](#-这是什么-introduction)
3. [懒人极速上手](#-懒人极速上手-quick-start)
4. [核心功能与优势](#-核心功能与优势-features)
5. [技术原理深度解析 (硬核篇)](#-技术原理深度解析-technical-deep-dive)
6. [文件结构与 AI 蓝图](#-文件结构与-ai-蓝图-structure)
7. [未来展望与扩展](#-未来展望与扩展-roadmap)
8. [许可证](#-许可证-license)

---

## 💡 项目哲学与价值观 (Philosophy)

在这个项目里，我们不仅仅是在写代码，更是在传递一种信念：

*   **打破黑盒 (Open Box)**: 拒绝 "盲盒式" 运行。每一个功能、每一个按钮背后的逻辑都是透明的。我们希望你在使用工具的同时，也能理解工具。
*   **掌控力 (Control)**: 无论是 VPS 还是家用服务器，数据的所有权和控制权应完全归属于你。
*   **极客精神 (Geek Spirit)**: 鼓励折腾，鼓励动手。看到复杂的代码不要怕，拆解它，理解它，重构它。
*   **快乐编程 (Joy)**: 编程不应是枯燥的。当你看到那个精美的 GUI 界面弹出的那一刻，那种多巴胺的释放，才是我们追求的极致体验。😎

---

## 🧐 这是什么？ (Introduction)

**DecoTV Manager** 是一个专为 DecoTV（Docker 版）打造的 **企业级运维管理系统**。

它不仅仅是一个启动脚本，而是一个拥有 **现代化图形界面 (GUI)**、**工业级加密存储**、**实时资源监控** 和 **自动化运维能力** 的综合管理平台。

### 🎯 适用场景
*   **云服务器 (VPS)**: 批量管理多台服务器上的媒体服务。
*   **家庭实验室 (HomeLab)**: 极客们的本地部署首选。
*   **团队协作**: 需要安全分发配置但不泄露明文密码的场景。

### ⚖️ 优缺点分析
| 优点 (Pros) ✅ | 缺点 (Cons) ❌ |
| :--- | :--- |
| **颜值即正义**: PyQt6 打造的现代化深色模式 UI，赏心悦目。 | **环境依赖**: 需要安装 Python 和相关库（适合有一定基础的用户）。 |
| **数据安全**: AES-256 加密存储所有敏感信息，丢了配置文件也不怕。 | **GUI 限制**: 需要图形界面环境（Windows/Mac 或 Linux 桌面版）。 |
| **全能监控**: CPU、内存、网络 IO、Docker 状态一目了然。 | |
| **多开神器**: 同时管理 N 个实例，一键批量启停。 | |

---

## ⚡ 懒人极速上手 (Lazy Start)

### 🟢 Windows 用户 (最简单)
1.  **环境准备**: 安装 [Python 3.8+](https://www.python.org/downloads/) 和 [Docker Desktop](https://www.docker.com/products/docker-desktop)。
2.  **下载项目**: 点击右上角 `Code` -> `Download ZIP` 解压。
3.  **安装依赖**: 双击文件夹内的 `必须先看.txt` (或者在终端运行 `pip install -r requirements.txt`)。
4.  **一键启动**: 双击 `启动DecoTV管理工具.bat`。

🎉 **Boom!** 你的可视化管理后台已启动。

### 🐧 Linux / MacOS 用户
```bash
# 1. 克隆仓库
git clone https://github.com/lza6/bytv-optimization.git
cd bytv-optimization

# 2. 安装依赖
pip3 install -r requirements.txt

# 3. 运行
python3 decotv_gui.py
```

---

## ✨ 核心功能与优势 (Features)

*   🎨 **现代化 UI 设计**: 支持 **深色模式 (Dark Mode)**，磨砂质感，丝滑动画。
*   🔐 **工业级安全**: 内置 **AES-256-CBC** 加密算法。你的密码在本地也是加密存储的！
*   📊 **Dashboard 仪表盘**: 自绘图表组件，实时显示 CPU/内存 曲线，不仅好用，更是好看。
*   🐳 **Docker 深度集成**: 自动检测 Docker 守护进程，像原生应用一样管理容器。
*   ⚡ **异步高性能**: 耗时操作全部 **多线程 (QThread)** 处理，界面永不卡顿。
*   🩹 **自动备份与恢复**: 定时增量备份配置，手残党的后悔药。

---

## 🔬 技术原理深度解析 (Technical Deep Dive)

> 🤓 **给开发者的硬核指南** - 这里是通过代码看本质的地方。

本项目完全基于 **Python 3** + **PyQt6** 开发，核心文件 `decotv_gui.py` 包含以下关键技术点：

### 1. 架构设计 (Architecture)
采用 **MVC (Model-View-Controller)** 的变种模式：
*   **View (UI)**: `QMainWindow`, `QWidget` 等 PyQt 组件负责展示。
*   **Logic (Controller)**: `DecoTVManager` 类统筹业务逻辑。
*   **Worker**: `WorkerThread`, `LogMonitorThread` 负责后台耗时任务。

### 2. 关键组件解析

#### 🔒 加密模块 (`EncryptionUtil`)
*   **技术点**: 使用 `cryptography` 库。
*   **算法**: `PBKDF2HMAC` (基于 HMAC-SHA256) 进行密钥派生 + `Fernet` (AES-CBC) 对称加密。
*   **实现**: 系统启动时要求输入“主密码”，该密码不存储，仅在内存中用于解密配置文件。
*   **代码位置**: 搜索 `class EncryptionUtil`。

#### 📈 资源监控 (`ResourceMonitor`)
*   **技术点**: `psutil` 库 + Docker CLI。
*   **魔法**: 使用了装饰器模式 `@performance_monitor` 和 `@async_cache`。
    *   `@async_cache(ttl=60)`: 给耗时的数据获取加上缓存，避免频繁调用 Docker API 导致 CPU 飙升。
*   **代码位置**: 搜索 `class ResourceMonitor`。

#### 🧵 多线程模型 (Threading)
*   **问题**: 直接在 GUI 线程运行 `subprocess.run` 会导致界面“假死”。
*   **解决**: 
    *   `WorkerThread(QThread)`: 处理 Docker pull/start/stop 等命令。
    *   `LogMonitorThread(QThread)`: 使用 `subprocess.Popen` 读取 `stdout` 流，实时吐出日志到 UI。

#### 📊 自绘组件 (Custom Widgets)
*   **亮点**: `ModernChartWidget` 类。
*   **原理**: 重写 `paintEvent` 方法，使用 `QPainter` 手绘坐标轴、网格线和数据折线，实现比原生控件更美观的图表。

### 3. 代码亮点 (Code Highlights)
```python
# 装饰器示例：为耗时函数增加缓存
def async_cache(ttl=60):
    def decorator(func):
        cache = {}
        @wraps(func)
        def wrapper(*args, **kwargs):
            # ... 缓存逻辑 ...
            return result
        return wrapper
    return decorator
```

---

## 📂 文件结构与 AI 蓝图 (Structure)

如果你是 AI 爬虫或者想要通过 AI 二次开发，请参考此结构：

```text
bytv-optimization/
├── decotv_gui.py          # [核心] 主程序源代码 (1000+行)
├── requirements.txt       # Python 依赖清单
├── 启动DecoTV管理工具.bat  # Windows 一键启动脚本
├── README.md              # 说明文档 (本文)
└── (自动生成)
    ├── config/            # 配置文件存储目录
    └── backups/           # 备份文件目录
```

### 🤖 AI 复刻/升级路径
如果你想让 AI 帮你升级这个项目，可以尝试以下 Prompt 思路：
1.  **UI 升级**: "读取 `decotv_gui.py` 中的 `ThemeManager` 类，帮我增加一套 'Cyberpunk 2077' 配色方案。"
2.  **功能扩展**: "基于 `WorkerThread` 类，通过 `ssh` 库实现远程服务器管理功能。"
3.  **Web化**: "分析 `ResourceMonitor` 的逻辑，用 Flask 重写一个 API 接口。"

---

## 🔮 未来展望与扩展 (Roadmap)

我们深知项目目前还不完美，以下是我们的 **星辰大海**：

*   [ ] **Web 界面版**: 摆脱 PyQt 依赖，实现浏览器远程管理 (React + FastAPI)。
*   [ ] **插件系统**: 允许开发者编写 Python 脚本插件动态加载。
*   [ ] **集群模式**: 一个主控端管理 N 台 VPS 上的节点。
*   [ ] **一键 HTTPS**: 集成 Caddy/Nginx 反代配置向导。

---

## 🤝 贡献与反馈

不管你是大神还是小白，如果你发现了 Bug，或者有更 cool 的想法，欢迎 **Issue** 或 **Pull Request**！另外，如果这个项目帮到了你，请不要吝啬你的 **Star** ⭐，这对我真的很重要！

让我们一起，用代码改变世界，哪怕只有一点点。🌍

---

## 📜 许可证 (License)

本项目采用 **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)** 开源协议。

这意味着你可以：
*   ✅ **商业使用**
*   ✅ **修改代码**
*   ✅ **分发副本**

前提是：**你需要保留原作者的版权声明和许可证声明**。

---

*Made with ❤️ by [LZA6](https://github.com/lza6)*
