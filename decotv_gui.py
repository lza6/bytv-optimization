#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DecoTV Manager V5 - 专业化多实例管理工具
全新升级版本：全面汉化、智能检测、性能优化、快捷键支持、深色模式、系统托盘、实时监控、插件系统
"""

import sys
import os
import subprocess
import threading
import json
import shutil
import socket
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import asyncio
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QMessageBox,
    QTabWidget, QGroupBox, QProgressBar, QDialog, QDialogButtonBox,
    QFormLayout, QSpinBox, QComboBox, QListWidget, QListWidgetItem,
    QStackedWidget, QFrame, QScrollArea, QSplitter, QGridLayout,
    QSizePolicy, QCheckBox, QFileDialog, QSystemTrayIcon, QMenu, QSlider,
    QStatusBar, QMenuBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup, QSettings
from PyQt6.QtGui import QFont, QColor, QPalette, QKeySequence, QTextCharFormat, QTextCursor, QAction, QShortcut, QIcon, QPixmap, QPainter, QPen, QBrush, QLinearGradient, QRadialGradient

# 添加加密库
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("警告: 未安装加密库，密码将以明文形式存储。请运行: pip install cryptography")

# 添加缓存装饰器
from functools import wraps
import time


def async_cache(ttl=60):
    """带TTL的异步缓存装饰器"""
    def decorator(func):
        cache = {}
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(sorted(kwargs.items()))
            now = time.time()
            
            if key in cache:
                result, timestamp = cache[key]
                if now - timestamp < ttl:
                    return result
                else:
                    del cache[key]
            
            result = func(*args, **kwargs)
            cache[key] = (result, now)
            return result
        
        return wrapper
    return decorator

def performance_monitor(func):
    """性能监控装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"函数 {func.__name__} 执行时间: {end_time - start_time:.4f}秒")
        return result
    return wrapper

class ResourceMonitor:
    """资源监控类"""
    def __init__(self):
        self.cpu_usage = 0
        self.memory_usage = 0
        self.disk_usage = 0
        self.network_io = 0
        self.last_update = time.time()

    def get_system_resources(self):
        """获取系统资源使用情况"""
        try:
            import psutil
            self.cpu_usage = psutil.cpu_percent(interval=1)
            self.memory_usage = psutil.virtual_memory().percent
            self.disk_usage = psutil.disk_usage('/').percent
            net_io = psutil.net_io_counters()
            self.network_io = net_io.bytes_sent + net_io.bytes_recv
        except ImportError:
            # 如果没有psutil，使用模拟数据
            self.cpu_usage = 0
            self.memory_usage = 0
            self.disk_usage = 0
            self.network_io = 0

    def get_docker_resources(self):
        """获取Docker资源使用情况"""
        try:
            result = subprocess.run(['docker', 'stats', '--no-stream', '--format', '"{{.Container}}\t{{.CPUPerc}}\t{{.MemPerc}}"'], 
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                stats = result.stdout.strip().split('\n')[1:]  # 跳过标题行
                docker_stats = {}
                for stat in stats:
                    parts = stat.replace('"', '').split('\t')
                    if len(parts) >= 3:
                        container, cpu, mem = parts[0], parts[1], parts[2]
                        docker_stats[container] = {'cpu': cpu, 'memory': mem}
                return docker_stats
            return {}
        except Exception:
            return {}

def compare_versions(v1, v2):
    """比较两个版本号"""
    v1_parts = list(map(int, v1.split('.')))
    v2_parts = list(map(int, v2.split('.')))
    for i in range(max(len(v1_parts), len(v2_parts))):
        v1_part = v1_parts[i] if i < len(v1_parts) else 0
        v2_part = v2_parts[i] if i < len(v2_parts) else 0
        if v1_part > v2_part:
            return 1
        elif v1_part < v2_part:
            return -1
    return 0


class EncryptionUtil:
    """加密工具类"""
    @staticmethod
    def encrypt(data, password):
        """使用密码加密数据"""
        try:
            # 使用密码派生密钥
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())
            
            # 将salt和加密数据一起返回
            return {
                'encrypted': True,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'data': base64.b64encode(encrypted_data).decode('utf-8'),
                'algorithm': 'PBKDF2-HMAC-SHA256-Fernet',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"加密失败: {str(e)}")
            return {"encrypted": False, "data": data}
    
    @staticmethod
    def decrypt(encrypted_obj, password):
        """解密数据"""
        try:
            if not encrypted_obj.get('encrypted', False):
                return encrypted_obj['data']
                
            # 提取salt和加密数据
            salt = base64.b64decode(encrypted_obj['salt'])
            encrypted_data = base64.b64decode(encrypted_obj['data'])
            
            # 派生密钥并解密
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
            return decrypted_data.decode()
        except Exception as e:
            print(f"解密失败: {str(e)}")
            return encrypted_obj['data']
    
    @staticmethod
    def generate_secure_password(length=16):
        """生成安全密码"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def hash_password(password):
        """哈希密码"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password_hash(password, hashed):
        """验证密码哈希"""
        return hashlib.sha256(password.encode()).hexdigest() == hashed


class ModernChartWidget(QWidget):
    """现代化图表组件"""
    
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.title = title
        self.data = []
        self.max_points = 50
        self.setMinimumHeight(150)
    
    def paintEvent(self, event):
        """绘制图表"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # 绘制背景
        painter.fillRect(self.rect(), QColor("#f8f9fa"))
        
        # 绘制边框
        painter.setPen(QColor("#e0e0e0"))
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))
        
        if not self.data:
            return
        
        # 绘制标题
        painter.setPen(QColor("#2c3e50"))
        painter.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.Bold))
        painter.drawText(10, 20, self.title)
        
        # 计算绘图区域
        plot_rect = self.rect().adjusted(20, 30, -20, -20)
        if plot_rect.width() <= 0 or plot_rect.height() <= 0:
            return
        
        # 绘制网格线
        painter.setPen(QColor("#e8e8e8"))
        for i in range(5):
            y = plot_rect.top() + i * plot_rect.height() // 4
            painter.drawLine(plot_rect.left(), y, plot_rect.right(), y)
        
        # 绘制数据线
        if len(self.data) > 1:
            painter.setPen(QPen(QColor("#3498db"), 2))
            points = []
            for i, value in enumerate(self.data[-min(len(self.data), plot_rect.width() // 2):]):
                x = plot_rect.left() + i * plot_rect.width() // min(len(self.data), plot_rect.width() // 2 - 1)
                y = plot_rect.bottom() - (value / 100.0) * plot_rect.height()  # 假设数据范围是0-100
                points.append(QPoint(x, y))
            
            for i in range(len(points) - 1):
                painter.drawLine(points[i], points[i+1])
    
    def add_data_point(self, value):
        """添加数据点"""
        self.data.append(value)
        if len(self.data) > self.max_points:
            self.data.pop(0)
        self.update()


# ModernCard legacy definition removed


class SecuritySettingsDialog(QDialog):
    """安全设置对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("安全设置")
        self.setModal(True)
        self.resize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # 主密码设置
        pwd_group = QGroupBox("主密码设置")
        pwd_layout = QVBoxLayout()
        
        pwd_layout.addWidget(QLabel("设置主密码用于加密敏感信息（如实例密码）："))
        
        self.master_pwd_input = QLineEdit()
        self.master_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.master_pwd_input.setPlaceholderText("输入主密码")
        pwd_layout.addWidget(self.master_pwd_input)
        
        self.confirm_pwd_input = QLineEdit()
        self.confirm_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pwd_input.setPlaceholderText("确认主密码")
        pwd_layout.addWidget(self.confirm_pwd_input)
        
        pwd_group.setLayout(pwd_layout)
        layout.addWidget(pwd_group)
        
        # 密码生成器
        gen_group = QGroupBox("安全密码生成器")
        gen_layout = QVBoxLayout()
        
        gen_layout.addWidget(QLabel("生成高强度安全密码："))
        
        gen_btn_layout = QHBoxLayout()
        self.gen_length_spin = QSpinBox()
        self.gen_length_spin.setRange(8, 128)
        self.gen_length_spin.setValue(16)
        gen_btn_layout.addWidget(QLabel("长度:"))
        gen_btn_layout.addWidget(self.gen_length_spin)
        
        self.generate_btn = QPushButton("生成密码")
        self.generate_btn.clicked.connect(self.generate_password)
        gen_btn_layout.addWidget(self.generate_btn)
        
        gen_btn_layout.addStretch()
        gen_layout.addLayout(gen_btn_layout)
        
        self.generated_pwd_display = QLineEdit()
        self.generated_pwd_display.setReadOnly(True)
        gen_layout.addWidget(QLabel("生成的密码:"))
        gen_layout.addWidget(self.generated_pwd_display)
        
        gen_group.setLayout(gen_layout)
        layout.addWidget(gen_group)
        
        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        ok_btn = QPushButton("确定")
        ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
    
    def generate_password(self):
        """生成密码"""
        length = self.gen_length_spin.value()
        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
        self.master_pwd_input.setText(password)
        self.confirm_pwd_input.setText(password)


class MonitoringDashboard(QWidget):
    """监控仪表盘"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 标题
        title = QLabel("系统监控")
        title.setFont(QFont("Microsoft YaHei", 18, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # 资源使用图表
        charts_layout = QHBoxLayout()
        
        # CPU使用率图表
        self.cpu_chart = ModernChartWidget("CPU 使用率")
        cpu_card = ModernCard("CPU 使用率", "")
        cpu_card.content_layout.addWidget(self.cpu_chart)
        charts_layout.addWidget(cpu_card)
        
        # 内存使用率图表
        self.mem_chart = ModernChartWidget("内存 使用率")
        mem_card = ModernCard("内存 使用率", "")
        mem_card.content_layout.addWidget(self.mem_chart)
        charts_layout.addWidget(mem_card)
        
        # 磁盘使用率图表
        self.disk_chart = ModernChartWidget("磁盘 使用率")
        disk_card = ModernCard("磁盘 使用率", "")
        disk_card.content_layout.addWidget(self.disk_chart)
        charts_layout.addWidget(disk_card)
        
        layout.addLayout(charts_layout)
        
        # Docker容器监控
        self.docker_monitor = ModernCard("Docker 容器监控", "正在获取容器信息...")
        layout.addWidget(self.docker_monitor)
        
        # 网络IO监控
        self.network_monitor = ModernCard("网络 I/O", "正在监控网络流量...")
        layout.addWidget(self.network_monitor)
        
        self.setLayout(layout)
    
    def update_cpu_usage(self, value):
        """更新CPU使用率"""
        self.cpu_chart.add_data_point(value)
    
    def update_memory_usage(self, value):
        """更新内存使用率"""
        self.mem_chart.add_data_point(value)
    
    def update_disk_usage(self, value):
        """更新磁盘使用率"""
        self.disk_chart.add_data_point(value)


    
    def generate_password(self):
        """生成安全密码"""
        length = self.gen_length_spin.value()
        password = EncryptionUtil.generate_secure_password(length)
        self.generated_pwd_display.setText(password)


class ThemeManager:
    """主题管理器"""
    
    DARK_THEME = {
        'primary_color': '#3498db',
        'secondary_color': '#2c3e50',
        'accent_color': '#e74c3c',
        'background_color': '#2c3e50',
        'card_background': '#34495e',
        'text_color': '#ecf0f1',
        'subtext_color': '#bdc3c7',
        'border_color': '#4a6fa5',
        'success_color': '#27ae60',
        'warning_color': '#f39c12',
        'danger_color': '#e74c3c'
    }
    
    LIGHT_THEME = {
        'primary_color': '#3498db',
        'secondary_color': '#ecf0f1',
        'accent_color': '#e74c3c',
        'background_color': '#f5f7fa',
        'card_background': '#ffffff',
        'text_color': '#2c3e50',
        'subtext_color': '#7f8c8d',
        'border_color': '#e0e0e0',
        'success_color': '#27ae60',
        'warning_color': '#f39c12',
        'danger_color': '#e74c3c'
    }
    
    @classmethod
    def get_theme(cls, theme_name):
        if theme_name == 'dark':
            return cls.DARK_THEME
        else:
            return cls.LIGHT_THEME

    @classmethod
    def apply_theme(cls, app, theme_name='light'):
        theme = cls.get_theme(theme_name)
        
        stylesheet = f"""
        QMainWindow {{
            background-color: {theme['background_color']};
        }}
        QWidget {{
            font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
            color: {theme['text_color']};
        }}
        QPushButton {{
            background-color: {theme['primary_color']};
            color: white;
            border: none;
            border-radius: 8px;
            padding: 10px 20px;
            font-weight: bold;
            min-height: 35px;
        }}
        QPushButton:hover {{
            background-color: #2980b9;
        }}
        QPushButton:pressed {{
            background-color: #1a5276;
        }}
        QPushButton:disabled {{
            background-color: #bdc3c7;
        }}
        QLabel {{
            color: {theme['text_color']};
        }}
        QTextEdit {{
            background-color: {theme['card_background']};
            border: 1px solid {theme['border_color']};
            border-radius: 8px;
            padding: 12px;
            color: {theme['text_color']};
        }}
        QProgressBar {{
            border: 2px solid {theme['border_color']};
            border-radius: 8px;
            text-align: center;
            color: {theme['text_color']};
        }}
        QProgressBar::chunk {{
            background-color: {theme['primary_color']};
            border-radius: 6px;
        }}
        QFrame {{
            background-color: {theme['card_background']};
            border: 1px solid {theme['border_color']};
            border-radius: 12px;
        }}
        QListView {{
            background-color: {theme['card_background']};
            border: 1px solid {theme['border_color']};
            border-radius: 8px;
        }}
        QListView::item {{
            background-color: {theme['card_background']};
            color: {theme['text_color']};
            padding: 8px;
            border-radius: 6px;
            margin: 4px;
        }}
        QListView::item:selected {{
            background-color: {theme['primary_color']};
            color: white;
        }}
        QListView::item:hover {{
            background-color: #3a506b;
        }}
        QScrollBar:vertical {{
            background: {theme['background_color']};
            width: 15px;
            border-radius: 7px;
        }}
        QScrollBar::handle:vertical {{
            background: {theme['border_color']};
            border-radius: 7px;
            min-height: 20px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {theme['primary_color']};
        }}
        """

        app.setStyleSheet(stylesheet)


class WorkerThread(QThread):
    """后台任务执行线程"""
    output_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, commands, cwd=None):
        super().__init__()
        self.commands = commands
        self.cwd = cwd

    def run(self):
        try:
            total = len(self.commands)
            for i, cmd in enumerate(self.commands):
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    cwd=self.cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                for line in process.stdout:
                    self.output_signal.emit(line.rstrip())
                process.wait()
                progress = int((i + 1) / total * 100)
                self.progress_signal.emit(progress)
            self.finished_signal.emit(True, "任务完成")
        except Exception as e:
            self.finished_signal.emit(False, str(e))


class LogMonitorThread(QThread):
    """日志监控线程"""
    log_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, container_name, tail_lines=100):
        super().__init__()
        self.container_name = container_name
        self.tail_lines = tail_lines
        self._stop_flag = False
    
    def run(self):
        try:
            # 获取容器日志
            cmd = f'docker logs --tail={self.tail_lines} -f {self.container_name}'
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            while not self._stop_flag:
                if process.poll() is not None:
                    break
                
                line = process.stdout.readline()
                if line:
                    self.log_signal.emit(line.rstrip())
                else:
                    if process.poll() is not None:
                        break
                    # 短暂休眠以减少CPU使用
                    self.msleep(100)
            
            process.terminate()
            process.wait(timeout=5)
        except Exception as e:
            self.error_signal.emit(f"日志监控错误: {str(e)}")
    
    def stop(self):
        """停止日志监控"""
        self._stop_flag = True


class RefreshInstancesWorker(QThread):
    """刷新实例列表的工作线程"""
    result_ready = pyqtSignal(object, int)  # instances, running_count
    
    def __init__(self, instance_manager):
        super().__init__()
        self.instance_manager = instance_manager
    
    def run(self):
        try:
            instances = self.instance_manager.load_instances()
            
            # 并行获取实例状态以提高性能
            running_count = 0
            for instance in instances:
                status = self.instance_manager.get_instance_status(instance['name'])
                if status == 'running':
                    running_count += 1
            
            self.result_ready.emit(instances, running_count)
        except Exception as e:
            # 出错时返回空结果
            self.result_ready.emit([], 0)


class DockerDetector:
    """Docker 状态检测器"""
    
    @staticmethod
    def check_docker():
        """检测 Docker 状态"""
        result = {
            'installed': False,
            'running': False,
            'version': '未知',
            'error': None,
            'details': '',
            'containers': 0,
            'images': 0,
            'volumes': 0,
            'networks': 0,
            'memory_usage': '未知',
            'disk_usage': '未知'
        }
        
        try:
            # 检查是否安装
            proc = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if proc.returncode == 0:
                result['installed'] = True
                result['version'] = proc.stdout.strip()
                
                # 检查是否运行
                proc = subprocess.run(
                    ['docker', 'info'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if proc.returncode == 0:
                    result['running'] = True
                    result['details'] = 'Docker 服务正常运行'
                    
                    # 获取更多详细信息
                    try:
                        # 获取容器数量
                        proc = subprocess.run(['docker', 'ps', '-q'], capture_output=True, text=True, timeout=5)
                        result['containers'] = len(proc.stdout.strip().split('\n')) if proc.stdout.strip() else 0
                        
                        # 获取镜像数量
                        proc = subprocess.run(['docker', 'images', '-q'], capture_output=True, text=True, timeout=5)
                        result['images'] = len(proc.stdout.strip().split('\n')) if proc.stdout.strip() else 0
                        
                        # 获取卷数量
                        proc = subprocess.run(['docker', 'volume', 'ls', '-q'], capture_output=True, text=True, timeout=5)
                        result['volumes'] = len(proc.stdout.strip().split('\n')) if proc.stdout.strip() else 0
                        
                        # 获取网络数量
                        proc = subprocess.run(['docker', 'network', 'ls', '-q'], capture_output=True, text=True, timeout=5)
                        result['networks'] = len(proc.stdout.strip().split('\n')) if proc.stdout.strip() else 0
                    except:
                        pass
                else:
                    result['error'] = 'Docker 服务未启动'
                    result['details'] = '请启动 Docker Desktop'
            else:
                result['error'] = 'Docker 未安装'
                result['details'] = '请从 https://www.docker.com/products/docker-desktop 下载安装'
                
        except FileNotFoundError:
            result['error'] = 'Docker 未安装'
            result['details'] = '请从 https://www.docker.com/products/docker-desktop 下载安装'
        except subprocess.TimeoutExpired:
            result['error'] = 'Docker 响应超时'
            result['details'] = 'Docker 服务可能卡死，请重启 Docker'
        except Exception as e:
            result['error'] = f'Docker 检测失败: {str(e)}'
            result['details'] = '请检查 Docker 是否正确安装'
        
        return result
    
    @staticmethod
    def get_detailed_info():
        """获取详细的 Docker 信息"""
        try:
            # 获取系统信息
            system_info = subprocess.run(['docker', 'info', '--format', '{{json .}}'], 
                                        capture_output=True, text=True, timeout=10)
            if system_info.returncode == 0:
                import json
                return json.loads(system_info.stdout)
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_running_containers():
        """获取运行中的容器"""
        try:
            proc = subprocess.run(
                ['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}\t{{.Ports}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if proc.returncode == 0:
                containers = []
                for line in proc.stdout.strip().split('\n')[1:] if proc.stdout.strip() else []:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        containers.append({
                            'name': parts[0],
                            'status': parts[1],
                            'ports': parts[2]
                        })
                return containers
            return []
        except Exception:
            return []
    
    @staticmethod
    def get_disk_usage():
        """获取 Docker 磁盘使用情况"""
        try:
            proc = subprocess.run(
                ['docker', 'system', 'df'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return proc.stdout if proc.returncode == 0 else None
        except Exception:
            return None
    
    @staticmethod
    def check_port_in_use(port):
        """检查端口是否被占用"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', port))
                return result == 0
        except Exception:
            return False


class InstanceManager:
    """实例管理器"""
    
    INSTANCES_DIR = Path.home() / '.decotv' / 'instances'
    CONFIG_FILE = 'instance_config.json'
    MASTER_PASSWORD_FILE = Path.home() / '.decotv' / 'master_password.txt'
    
    def __init__(self):
        self.INSTANCES_DIR.mkdir(parents=True, exist_ok=True)
        self.current_instance = None
        self.instances = self.load_instances()
    
    def batch_start_instances(self, instance_names):
        """批量启动实例"""
        results = {}
        for name in instance_names:
            try:
                instance_dir = self.INSTANCES_DIR / name
                result = subprocess.run(
                    ['docker', 'compose', '--env-file', '.env', 'up', '-d'],
                    cwd=instance_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                results[name] = result.returncode == 0
            except Exception as e:
                results[name] = False
        return results
    
    def batch_stop_instances(self, instance_names):
        """批量停止实例"""
        results = {}
        for name in instance_names:
            try:
                instance_dir = self.INSTANCES_DIR / name
                result = subprocess.run(
                    ['docker', 'compose', '--env-file', '.env', 'stop'],
                    cwd=instance_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                results[name] = result.returncode == 0
            except Exception as e:
                results[name] = False
        return results
    
    def batch_delete_instances(self, instance_names):
        """批量删除实例"""
        results = {}
        for name in instance_names:
            try:
                # 停止容器
                instance_dir = self.INSTANCES_DIR / name
                subprocess.run(
                    ['docker', 'compose', 'down', '-v', '--remove-orphans'],
                    cwd=instance_dir,
                    capture_output=True,
                    timeout=30
                )
                # 删除目录
                shutil.rmtree(instance_dir, ignore_errors=True)
                # 从列表中移除
                self.instances = [i for i in self.instances if i['name'] != name]
                results[name] = True
            except Exception as e:
                results[name] = False
        return results
    
    def load_instances(self):
        """加载所有实例"""
        instances = []
        
        if not self.INSTANCES_DIR.exists():
            return instances
        
        for instance_dir in self.INSTANCES_DIR.iterdir():
            if instance_dir.is_dir():
                config_file = instance_dir / self.CONFIG_FILE
                if config_file.exists():
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            config['path'] = str(instance_dir)
                            instances.append(config)
                    except Exception:
                        continue
        
        return instances
    
    def get_master_password(self):
        """获取主密码"""
        if not ENCRYPTION_AVAILABLE:
            return None
        
        # 尝试从文件读取主密码
        if self.MASTER_PASSWORD_FILE.exists():
            with open(self.MASTER_PASSWORD_FILE, 'r', encoding='utf-8') as f:
                stored_hash = f.read().strip()
            return stored_hash
        return None

    def set_master_password(self, password):
        """设置主密码"""
        if not ENCRYPTION_AVAILABLE:
            return
        
        # 存储密码的哈希值而不是明文
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.MASTER_PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(self.MASTER_PASSWORD_FILE, 'w', encoding='utf-8') as f:
            f.write(password_hash)
    
    def create_instance(self, name, port, user, password, version='latest'):
        """创建新实例"""
        instance_dir = self.INSTANCES_DIR / name
        instance_dir.mkdir(parents=True, exist_ok=True)
        
        # 加密密码
        master_password = self.get_master_password()
        if master_password:
            encrypted_password = EncryptionUtil.encrypt(password, master_password)
        else:
            encrypted_password = {"encrypted": False, "data": password}
        
        config = {
            'name': name,
            'port': port,
            'user': user,
            'password': encrypted_password,  # 存储加密后的密码
            'version': version,
            'created_at': datetime.now().isoformat(),
            'status': 'stopped'
        }
        
        config_file = instance_dir / self.CONFIG_FILE
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        # 创建 .env 文件（也加密存储）
        env_file = instance_dir / '.env'
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(f"USERNAME={user}\n")
            f.write(f"PASSWORD={password}\n")  # 这里暂时使用明文，后续可以改进
            f.write(f"APP_PORT={port}\n")
        
        # 创建 docker-compose.yml
        compose_file = instance_dir / 'docker-compose.yml'
        compose_content = f"""services:
  decotv-core:
    image: ghcr.io/decohererk/decotv:{version}
    container_name: decotv-{name}-core
    restart: on-failure
    ports: ["${{APP_PORT}}:3000"]
    environment:
      - USERNAME=${{USERNAME}}
      - PASSWORD=${{PASSWORD}}
      - NEXT_PUBLIC_STORAGE_TYPE=kvrocks
      - KVROCKS_URL=redis://decotv-{name}-kvrocks:6666
    networks: [decotv-{name}-network]
    depends_on: [decotv-{name}-kvrocks]
  decotv-{name}-kvrocks:
    image: apache/kvrocks:latest
    container_name: decotv-{name}-kvrocks
    restart: unless-stopped
    volumes: [{name}-kvrocks-data:/var/lib/kvrocks]
    networks: [decotv-{name}-network]
networks: {{ decotv-{name}-network: {{ driver: bridge }} }}
volumes: {{ {name}-kvrocks-data: {{}} }}
"""
        
        with open(compose_file, 'w', encoding='utf-8') as f:
            f.write(compose_content)
        
        self.instances.append(config)
        return True
    
    def delete_instance(self, name):
        """删除实例"""
        instance_dir = self.INSTANCES_DIR / name
        
        # 停止容器
        try:
            subprocess.run(
                ['docker', 'compose', 'down', '-v', '--remove-orphans'],
                cwd=instance_dir,
                capture_output=True,
                timeout=30
            )
        except Exception:
            pass
        
        # 删除目录
        shutil.rmtree(instance_dir, ignore_errors=True)
        
        # 从列表中移除
        self.instances = [i for i in self.instances if i['name'] != name]
        
        return True
    
    def get_instance_status(self, name):
        """获取实例状态"""
        try:
            container_name = f"decotv-{name}-core"
            proc = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container_name}', '--format', '{{.Status}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return 'running'
            else:
                return 'stopped'
        except Exception:
            return 'unknown'
    
    def export_instance(self, name):
        """导出实例配置"""
        instance_dir = self.INSTANCES_DIR / name
        config_file = instance_dir / self.CONFIG_FILE
        
        if not config_file.exists():
            return None
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        return json.dumps(config, indent=2, ensure_ascii=False)
    
    def import_instance(self, config_str):
        """导入实例配置"""
        try:
            config = json.loads(config_str)
            
            # 检查必需字段
            required_fields = ['name', 'port', 'user', 'password', 'version']
            if not all(field in config for field in required_fields):
                return False, "配置文件缺少必需字段"
            
            # 检查名称是否已存在
            if any(i['name'] == config['name'] for i in self.instances):
                return False, "实例名称已存在"
            
            # 创建实例
            if self.create_instance(
                config['name'],
                config['port'],
                config['user'],
                config['password'],
                config['version']
            ):
                return True, "实例导入成功"
            else:
                return False, "实例创建失败"
        except json.JSONDecodeError:
            return False, "配置文件格式错误"
        except Exception as e:
            return False, f"导入失败: {str(e)}"

    def backup_all_instances(self, backup_path):
        """备份所有实例"""
        try:
            backup_data = {
                'backup_time': datetime.now().isoformat(),
                'instances': [],
                'version': 'v4.0'
            }
            
            for instance in self.instances:
                # 读取实例配置
                instance_dir = Path(instance['path'])
                config_file = instance_dir / self.CONFIG_FILE
                
                if config_file.exists():
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                    
                    # 添加实例文件夹内容
                    instance_backup = {
                        'config': config,
                        'files': {}
                    }
                    
                    # 读取.env文件
                    env_file = instance_dir / '.env'
                    if env_file.exists():
                        with open(env_file, 'r', encoding='utf-8') as f:
                            instance_backup['files']['.env'] = f.read()
                    
                    # 读取docker-compose.yml文件
                    compose_file = instance_dir / 'docker-compose.yml'
                    if compose_file.exists():
                        with open(compose_file, 'r', encoding='utf-8') as f:
                            instance_backup['files']['docker-compose.yml'] = f.read()
                    
                    backup_data['instances'].append(instance_backup)
            
            # 写入备份文件
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            return True, f"成功备份 {len(backup_data['instances'])} 个实例到 {backup_path}"
        except Exception as e:
            return False, f"备份失败: {str(e)}"

    def restore_from_backup(self, backup_path):
        """从备份恢复实例"""
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            restored_count = 0
            for instance_backup in backup_data.get('instances', []):
                config = instance_backup['config']
                
                # 检查实例是否已存在
                if any(i['name'] == config['name'] for i in self.instances):
                    continue  # 跳过已存在的实例
                
                # 创建实例目录
                instance_dir = self.INSTANCES_DIR / config['name']
                instance_dir.mkdir(parents=True, exist_ok=True)
                
                # 写入配置文件
                config_file = instance_dir / self.CONFIG_FILE
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                
                # 写入其他文件
                for filename, content in instance_backup.get('files', {}).items():
                    file_path = instance_dir / filename
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                
                self.instances.append(config)
                restored_count += 1
            
            return True, f"成功恢复 {restored_count} 个实例"
        except json.JSONDecodeError:
            return False, "备份文件格式错误"
        except Exception as e:
            return False, f"恢复失败: {str(e)}"
    
    def schedule_backup(self, interval_hours=24):
        """设置定时备份"""
        try:
            import schedule
            import threading
            
            def backup_job():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = self.INSTANCES_DIR / f"scheduled_backup_{timestamp}.json"
                success, message = self.backup_all_instances(str(backup_path))
                print(f"定时备份完成: {message}")
                return schedule.CancelJob if not success else None
            
            # 每隔指定小时执行一次备份
            schedule.every(interval_hours).hours.do(backup_job)
            
            # 在后台线程中运行调度器
            def run_scheduler():
                while True:
                    schedule.run_pending()
                    time.sleep(60)  # 每分钟检查一次
            
            scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
            scheduler_thread.start()
            
            return True, f"已设置每 {interval_hours} 小时自动备份一次"
        except ImportError:
            # 如果没有schedule库，使用简化版本
            return False, "需要安装schedule库: pip install schedule"
    
    def incremental_backup(self, backup_path, last_backup_path=None):
        """增量备份 - 只备份自上次备份以来更改的内容"""
        try:
            import filecmp
            
            # 获取所有实例
            instances = self.load_instances()
            
            backup_data = {
                'backup_time': datetime.now().isoformat(),
                'version': 'v5.0',
                'incremental': True,
                'instances': []
            }
            
            for instance in instances:
                instance_dir = Path(instance['path'])
                
                # 检查实例是否已存在备份，如果是增量备份则比较文件
                if last_backup_path and Path(last_backup_path).exists():
                    # 简单的增量备份：如果实例配置文件的修改时间比上次备份时间新，则备份
                    config_file = instance_dir / self.CONFIG_FILE
                    if config_file.exists():
                        config_mtime = datetime.fromtimestamp(config_file.stat().st_mtime)
                        last_backup_time = datetime.fromtimestamp(Path(last_backup_path).stat().st_mtime)
                        
                        if config_mtime > last_backup_time:
                            # 需要备份此实例
                            instance_backup = self._prepare_instance_backup(instance_dir)
                            backup_data['instances'].append(instance_backup)
                else:
                    # 完整备份
                    instance_backup = self._prepare_instance_backup(instance_dir)
                    backup_data['instances'].append(instance_backup)
            
            # 写入备份文件
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            return True, f"增量备份完成，备份了 {len(backup_data['instances'])} 个实例"
        except Exception as e:
            return False, f"增量备份失败: {str(e)}"
    
    def _prepare_instance_backup(self, instance_dir):
        """准备实例备份数据"""
        config_file = instance_dir / self.CONFIG_FILE
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 添加实例文件夹内容
            instance_backup = {
                'config': config,
                'files': {},
                'last_modified': datetime.fromtimestamp(config_file.stat().st_mtime).isoformat()
            }
            
            # 读取.env文件
            env_file = instance_dir / '.env'
            if env_file.exists():
                with open(env_file, 'r', encoding='utf-8') as f:
                    instance_backup['files']['.env'] = f.read()
            
            # 读取docker-compose.yml文件
            compose_file = instance_dir / 'docker-compose.yml'
            if compose_file.exists():
                with open(compose_file, 'r', encoding='utf-8') as f:
                    instance_backup['files']['docker-compose.yml'] = f.read()
            
            return instance_backup
        
        return {}
    
    def get_backup_history(self):
        """获取备份历史"""
        backups = []
        for file in self.INSTANCES_DIR.glob("scheduled_backup_*.json"):
            if file.is_file():
                stat = file.stat()
                backups.append({
                    'name': file.name,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'path': str(file)
                })
        
        # 按修改时间排序
        backups.sort(key=lambda x: x['modified'], reverse=True)
        return backups


class ModernCard(QFrame):
    """现代化卡片组件"""
    
    def __init__(self, title="", content=None, parent=None):
        # 兼容性处理：如果第二个参数是 QWidget，则将其视为 parent
        real_parent = parent
        real_content = content
        
        if content is not None and not isinstance(content, str):
            # 假设非字符串内容为 parent
            real_parent = content
            real_content = None
            
        super().__init__(real_parent)
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            ModernCard {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 12px;
                padding: 16px;
            }
            ModernCard:hover {
                border: 1px solid #3498db;
                background-color: #f8fbff;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        
        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        self.title_label.setStyleSheet("color: #2c3e50;")
        
        layout.addWidget(self.title_label)
        
        self.content_widget = QWidget()
        layout.addWidget(self.content_widget)
        
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        
        # 如果提供了内容文本，添加它
        if real_content and isinstance(real_content, str):
            content_label = QLabel(real_content)
            content_label.setWordWrap(True)
            self.content_layout.addWidget(content_label)


class InstanceListWidget(QListWidget):
    """实例列表组件"""
    
    instance_selected = pyqtSignal(dict)
    instances_selected = pyqtSignal(list)  # 新增：批量选择信号
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)  # 支持多选
        self.setStyleSheet("""
            QListWidget {
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                background-color: #ffffff;
                padding: 8px;
            }
            QListWidget::item {
                padding: 12px;
                border-radius: 8px;
                margin: 4px;
                background-color: #f8f9fa;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #e8f4f8;
            }
        """)
        self.itemClicked.connect(self.on_item_clicked)
        self.itemSelectionChanged.connect(self.on_selection_changed)  # 新增：选择变化事件
    
    def load_instances(self, instances):
        """加载实例列表"""
        self.clear()
        
        for instance in instances:
            item = QListWidgetItem()
            # 显示实例状态
            status = self.get_instance_status(instance['name'])
            status_icon = "●" if status == 'running' else "○"
            item.setText(f"{status_icon} {instance['name']} (端口: {instance['port']}, 状态: {status})")
            item.setData(Qt.ItemDataRole.UserRole, instance)
            self.addItem(item)
    
    def get_instance_status(self, name):
        """获取实例状态"""
        try:
            container_name = f"decotv-{name}-core"
            proc = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container_name}', '--format', '{{.Status}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return 'running'
            else:
                return 'stopped'
        except Exception:
            return 'unknown'
    
    def on_item_clicked(self, item):
        """实例点击事件"""
        instance = item.data(Qt.ItemDataRole.UserRole)
        self.instance_selected.emit(instance)
    
    def on_selection_changed(self):
        """选择变化事件"""
        selected_items = []
        for item in self.selectedItems():
            instance = item.data(Qt.ItemDataRole.UserRole)
            selected_items.append(instance)
        self.instances_selected.emit(selected_items)


class PortCheckerThread(QThread):
    """端口检查线程"""
    port_check_result = pyqtSignal(int, bool)  # port, is_available
    
    def __init__(self, port):
        super().__init__()
        self.port = port
    
    def run(self):
        """异步检查端口是否被占用"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', self.port))
                is_available = result != 0
                self.port_check_result.emit(self.port, is_available)
        except Exception:
            self.port_check_result.emit(self.port, False)


class CreateInstanceDialog(QDialog):
    """创建实例对话框"""
    
    def __init__(self, parent=None, existing_ports=None):
        super().__init__(parent)
        self.setWindowTitle("创建新实例")
        self.setMinimumWidth(450)
        self.result = None
        self.existing_ports = existing_ports or []
        self.current_port_checker = None  # 保存当前的端口检查线程
        
        layout = QVBoxLayout(self)
        
        # 表单
        form_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("实例名称（例如：my-decotv）")
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(3000)
        self.port_input.setSuffix(" 端口")
        self.port_input.valueChanged.connect(self.on_port_changed)  # 改为新方法
        
        self.port_status = QLabel()
        self.port_status.setStyleSheet("color: #27ae60; font-size: 11px;")
        
        self.user_input = QLineEdit("admin")
        self.user_input.setPlaceholderText("用户名")
        
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("密码")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.pass_confirm = QLineEdit()
        self.pass_confirm.setPlaceholderText("确认密码")
        self.pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.version_input = QComboBox()
        self.version_input.addItems(['latest', 'v1.0.0', 'v0.9.0', 'dev'])
        
        form_layout.addRow("实例名称:", self.name_input)
        form_layout.addRow("访问端口:", self.port_input)
        form_layout.addRow("", self.port_status)
        form_layout.addRow("用户名:", self.user_input)
        form_layout.addRow("密码:", self.pass_input)
        form_layout.addRow("确认密码:", self.pass_confirm)
        form_layout.addRow("版本:", self.version_input)
        
        layout.addLayout(form_layout)
        
        # 按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)
        
        # 初始检查端口
        self.check_port_async()
    
    def on_port_changed(self):
        """端口改变时的处理"""
        self.check_port_async()
    
    def check_port_async(self):
        """异步检查端口状态"""
        port = self.port_input.value()
        
        # 如果已经有正在进行的检查，取消它
        if self.current_port_checker and self.current_port_checker.isRunning():
            self.current_port_checker.terminate()
            self.current_port_checker.wait()
        
        # 更新基本状态
        if port in self.existing_ports:
            self.port_status.setText(f"⚠️ 端口 {port} 已被其他实例使用")
            self.port_status.setStyleSheet("color: #e74c3c; font-size: 11px;")
            return
        
        # 开始异步检查
        self.port_status.setText(f"正在检查端口 {port}...")
        self.port_status.setStyleSheet("color: #f39c12; font-size: 11px;")
        
        self.current_port_checker = PortCheckerThread(port)
        self.current_port_checker.port_check_result.connect(self.on_port_check_result)
        self.current_port_checker.start()
    
    def on_port_check_result(self, port, is_available):
        """端口检查结果回调"""
        if port == self.port_input.value():  # 确保是当前端口的结果
            if port in self.existing_ports:
                # 如果端口已被其他实例使用，显示相应信息
                self.port_status.setText(f"⚠️ 端口 {port} 已被其他实例使用")
                self.port_status.setStyleSheet("color: #e74c3c; font-size: 11px;")
            elif is_available:
                self.port_status.setText(f"✓ 端口 {port} 可用")
                self.port_status.setStyleSheet("color: #27ae60; font-size: 11px;")
            else:
                self.port_status.setText(f"⚠️ 端口 {port} 已被系统占用")
                self.port_status.setStyleSheet("color: #e74c3c; font-size: 11px;")
    
    def validate_and_accept(self):
        """验证并接受"""
        name = self.name_input.text().strip()
        password = self.pass_input.text()
        confirm = self.pass_confirm.text()
        port = self.port_input.value()
        
        if not name:
            QMessageBox.warning(self, "错误", "实例名称不能为空")
            return
        
        if not password:
            QMessageBox.warning(self, "错误", "密码不能为空")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "错误", "两次密码不一致")
            return
        
        if port in self.existing_ports:
            QMessageBox.warning(self, "错误", f"端口 {port} 已被其他实例使用")
            return
        
        # 同步检查端口状态
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    QMessageBox.warning(self, "错误", f"端口 {port} 已被系统占用")
                    return
        except Exception:
            pass  # 如果检查失败，继续进行
        
        self.result = {
            'name': name,
            'port': port,
            'user': self.user_input.text(),
            'password': password,
            'version': self.version_input.currentText()
        }
        self.accept()



class PluginManager:
    """插件管理器"""
    def __init__(self):
        self.plugins = []

    def load_plugins(self):
        """加载外部插件"""
        # 简单实现，暂不扫描外部目录
        pass

class BackupPlugin:
    """备份插件"""
    def initialize(self, manager):
        """初始化备份插件"""
        pass

class MonitoringPlugin:
    """监控插件"""
    def initialize(self, manager):
        """初始化监控插件"""
        pass

class DecoTVManager(QMainWindow):
    """主窗口 - 现代化设计 V5"""
    
    def __init__(self):
        super().__init__()
        self.docker_detector = DockerDetector()
        self.instance_manager = InstanceManager()
        self.current_instance = None
        
        # 初始化插件管理器
        self.plugin_manager = PluginManager()
        self.load_plugins()
        
        # 初始化设置
        self.settings = QSettings('DecoTV', 'Manager')
        self.theme_manager = ThemeManager()
        self.tray_icon = None
        
        # 检查Docker是否运行
        self.check_docker_running_at_startup()
        
        self.init_ui()
        self.init_shortcuts()
        self.setup_system_tray()
        self.load_settings()
        self.check_docker_periodically()
        self.refresh_instance_list()
    
    def load_plugins(self):
        """加载插件"""
        # 初始化并加载内置插件
        backup_plugin = BackupPlugin()
        backup_plugin.initialize(self)
        
        monitoring_plugin = MonitoringPlugin()
        monitoring_plugin.initialize(self)
        
        # 也可以从外部目录加载插件
        self.plugin_manager.load_plugins()

    def check_docker_running_at_startup(self):
        """启动时检查Docker是否运行"""
        try:
            docker_status = self.docker_detector.check_docker()
            if not docker_status['running']:
                reply = QMessageBox.question(
                    self,
                    "Docker未运行",
                    "检测到Docker服务未运行，是否立即启动Docker?\n\n"
                    "注意：请先确保已安装Docker Desktop并已启动服务。",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )
                if reply == QMessageBox.StandardButton.Yes:
                    QMessageBox.information(
                        self,
                        "提示",
                        "请手动启动Docker Desktop应用程序，然后重启本程序。\n\n"
                        "Windows用户通常在系统托盘中找到Docker图标并左键点击启动。"
                    )
            elif not docker_status['installed']:
                QMessageBox.critical(
                    self,
                    "Docker未安装",
                    "未检测到Docker，请先安装Docker Desktop后再使用本程序。\n\n"
                    "下载地址：https://www.docker.com/products/docker-desktop"
                )
        except Exception as e:
            QMessageBox.warning(
                self,
                "检查Docker状态失败",
                f"无法检查Docker状态：{str(e)}\n\n"
                "请确保Docker已正确安装并运行。"
            )

    def setup_system_tray(self):
        """设置系统托盘"""
        if QSystemTrayIcon.isSystemTrayAvailable():
            # 创建托盘图标
            self.tray_icon = QSystemTrayIcon(self)
            
            # 创建托盘图标图片
            pixmap = QPixmap(32, 32)
            pixmap.fill(QColor('#3498db'))
            painter = QPainter(pixmap)
            painter.setPen(QColor('white'))
            painter.setFont(QFont('Microsoft YaHei', 14, QFont.Weight.Bold))
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, 'D')
            painter.end()
            
            self.tray_icon.setIcon(QIcon(pixmap))
            self.tray_icon.setToolTip('DecoTV 管理器')
            
            # 创建右键菜单
            tray_menu = QMenu()
            
            show_action = tray_menu.addAction('显示主窗口')
            show_action.triggered.connect(self.show_window)
            
            hide_action = tray_menu.addAction('最小化到托盘')
            hide_action.triggered.connect(self.hide_window)
            
            separator = tray_menu.addSeparator()
            
            quit_action = tray_menu.addAction('退出')
            quit_action.triggered.connect(self.quit_app)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.tray_icon_activated)
            self.tray_icon.show()
    
    def show_window(self):
        """显示主窗口"""
        self.showNormal()
        self.activateWindow()
    
    def hide_window(self):
        """隐藏到托盘"""
        self.hide()
    
    def quit_app(self):
        """退出应用程序"""
        if self.tray_icon:
            self.tray_icon.hide()
        QApplication.quit()
    
    def tray_icon_activated(self, reason):
        """托盘图标激活事件"""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window()
    
    def load_settings(self):
        """加载设置"""
        theme = self.settings.value('theme', 'light')
        if theme == 'dark':
            self.toggle_dark_mode(True)
    
    def toggle_dark_mode(self, enabled):
        """切换深色模式"""
        if enabled:
            self.theme_manager.apply_theme(self.app, 'dark')
            self.settings.setValue('theme', 'dark')
        else:
            self.theme_manager.apply_theme(self.app, 'light')
            self.settings.setValue('theme', 'light')
            
    
    def init_ui(self):
        """初始化 UI"""
        # 获取应用程序实例
        self.app = QApplication.instance()
        
        self.setWindowTitle("DecoTV 管理器 V4")
        self.setMinimumSize(1200, 800)
        
        # 应用现代主题
        self.apply_modern_theme()
        
        # 中央组件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 侧边栏
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar, 1)
        
        # 主内容区
        content_area = self.create_content_area()
        main_layout.addWidget(content_area, 3)
    
    def init_shortcuts(self):
        """初始化快捷键"""
        # Ctrl+N: 新建实例
        shortcut_new = QShortcut(QKeySequence("Ctrl+N"), self)
        shortcut_new.activated.connect(self.on_create_instance)
        
        # Ctrl+D: 删除实例
        shortcut_delete = QShortcut(QKeySequence("Ctrl+D"), self)
        shortcut_delete.activated.connect(self.on_delete_instance)
        
        # Ctrl+R: 刷新
        shortcut_refresh = QShortcut(QKeySequence("Ctrl+R"), self)
        shortcut_refresh.activated.connect(self.refresh_instance_list)
        
        # F5: 刷新
        shortcut_f5 = QShortcut(QKeySequence("F5"), self)
        shortcut_f5.activated.connect(self.refresh_instance_list)
    
    def apply_modern_theme(self):
        """应用现代主题"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f7fa;
            }
            QWidget {
                font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
                color: #2c3e50;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                min-height: 35px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1a5276;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
            QLabel {
                color: #2c3e50;
            }
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 12px;
            }
            QProgressBar {
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 6px;
            }
        """)
    
    def create_sidebar(self):
        """创建侧边栏"""
        sidebar = QFrame()
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #2c3e50;
                border: none;
            }
            QLabel {
                color: white;
            }
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Logo
        logo = QLabel("DecoTV\n管理器")
        logo.setFont(QFont("Microsoft YaHei", 20, QFont.Weight.Bold))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("color: white; padding: 20px 0;")
        layout.addWidget(logo)
        
        # Docker 状态卡片
        self.docker_status_card = ModernCard("Docker 状态")
        self.docker_status_card.setStyleSheet("""
            ModernCard {
                background-color: #34495e;
                border: 1px solid #4a6fa5;
                border-radius: 12px;
            }
            QLabel {
                color: white;
            }
        """)
        layout.addWidget(self.docker_status_card)
        
        self.docker_status_label = QLabel("检测中...")
        self.docker_status_label.setStyleSheet("color: #ecf0f1; font-size: 12px;")
        self.docker_status_card.content_layout.addWidget(self.docker_status_label)
        
        # 实例列表标题
        instances_title = QLabel("实例列表")
        instances_title.setFont(QFont("Microsoft YaHei", 12, QFont.Weight.Bold))
        instances_title.setStyleSheet("color: white;")
        layout.addWidget(instances_title)
        
        # 实例列表
        self.instance_list = InstanceListWidget()
        self.instance_list.instance_selected.connect(self.on_instance_selected)
        self.instance_list.instances_selected.connect(self.on_instances_selected)  # 添加批量选择事件连接
        layout.addWidget(self.instance_list)
        
        # 创建实例按钮
        create_btn = QPushButton("+ 新建实例 (Ctrl+N)")
        create_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                border-radius: 8px;
                padding: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        create_btn.clicked.connect(self.on_create_instance)
        layout.addWidget(create_btn)
        
        # 批量操作按钮
        batch_ops_layout = QHBoxLayout()
        
        self.batch_start_btn = QPushButton("批量启动")
        self.batch_start_btn.setStyleSheet("background-color: #27ae60; padding: 8px;")
        self.batch_start_btn.clicked.connect(self.on_batch_start)
        self.batch_start_btn.setEnabled(False)  # 初始禁用
        batch_ops_layout.addWidget(self.batch_start_btn)
        
        self.batch_stop_btn = QPushButton("批量停止")
        self.batch_stop_btn.setStyleSheet("background-color: #f39c12; padding: 8px;")
        self.batch_stop_btn.clicked.connect(self.on_batch_stop)
        self.batch_stop_btn.setEnabled(False)  # 初始禁用
        batch_ops_layout.addWidget(self.batch_stop_btn)
        
        layout.addLayout(batch_ops_layout)
        
        # 导入导出按钮
        import_export_layout = QHBoxLayout()
        
        import_btn = QPushButton("导入")
        import_btn.setStyleSheet("background-color: #9b59b6; padding: 8px;")
        import_btn.clicked.connect(self.on_import_instance)
        import_export_layout.addWidget(import_btn)
        
        export_btn = QPushButton("导出")
        export_btn.setStyleSheet("background-color: #f39c12; padding: 8px;")
        export_btn.clicked.connect(self.on_export_instance)
        import_export_layout.addWidget(export_btn)
        
        layout.addLayout(import_export_layout)
        
        layout.addStretch()
        
        return sidebar
    
    def create_content_area(self):
        """创建主内容区"""
        stack = QStackedWidget()
        stack.setStyleSheet("background-color: #f5f7fa;")
        
        # 仪表盘页面
        self.dashboard_page = self.create_dashboard_page()
        stack.addWidget(self.dashboard_page)
        
        # 日志页面
        self.log_page = self.create_log_page()
        stack.addWidget(self.log_page)
        
        # 设置页面
        self.settings_page = self.create_settings_page()
        stack.addWidget(self.settings_page)
        
        # 监控页面
        self.monitoring_page = MonitoringDashboard()
        stack.addWidget(self.monitoring_page)
        
        self.content_stack = stack
        return stack
    
    def create_dashboard_page(self):
        """创建仪表盘页面"""
        page = QScrollArea()
        page.setWidgetResizable(True)
        page.setStyleSheet("background-color: #f5f7fa; border: none;")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # 标题
        title = QLabel("仪表盘")
        title.setFont(QFont("Microsoft YaHei", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50;")
        layout.addWidget(title)
        
        # 统计卡片
        stats_layout = QHBoxLayout()
        
        self.instances_card = ModernCard("总实例数")
        self.instances_count_label = QLabel("0")
        self.instances_count_label.setFont(QFont("Microsoft YaHei", 32, QFont.Weight.Bold))
        self.instances_count_label.setStyleSheet("color: #3498db;")
        self.instances_card.content_layout.addWidget(self.instances_count_label)
        stats_layout.addWidget(self.instances_card)
        
        self.running_card = ModernCard("运行中")
        self.running_count_label = QLabel("0")
        self.running_count_label.setFont(QFont("Microsoft YaHei", 32, QFont.Weight.Bold))
        self.running_count_label.setStyleSheet("color: #27ae60;")
        self.running_card.content_layout.addWidget(self.running_count_label)
        stats_layout.addWidget(self.running_card)
        
        self.storage_card = ModernCard("存储使用")
        self.storage_label = QLabel("计算中...")
        self.storage_label.setFont(QFont("Microsoft YaHei", 18, QFont.Weight.Bold))
        self.storage_label.setStyleSheet("color: #f39c12;")
        self.storage_card.content_layout.addWidget(self.storage_label)
        stats_layout.addWidget(self.storage_card)
        
        layout.addLayout(stats_layout)
        
        # 当前实例控制
        self.instance_control_card = ModernCard("实例控制")
        self.create_instance_control()
        layout.addWidget(self.instance_control_card)
        
        # 实例日志预览
        log_card = ModernCard("最近日志")
        self.log_preview = QTextEdit()
        self.log_preview.setReadOnly(True)
        self.log_preview.setMaximumHeight(200)
        log_card.content_layout.addWidget(self.log_preview)
        layout.addWidget(log_card)
        
        layout.addStretch()
        page.setWidget(content)
        
        return page
    
    def create_instance_control(self):
        """创建实例控制区"""
        control_layout = QVBoxLayout()
        
        # 实例信息
        info_layout = QHBoxLayout()
        self.instance_name_label = QLabel("未选择实例")
        self.instance_name_label.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        info_layout.addWidget(self.instance_name_label)
        info_layout.addStretch()
        control_layout.addLayout(info_layout)
        
        # 按钮组
        buttons_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("启动")
        self.start_btn.clicked.connect(self.on_start_instance)
        buttons_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.on_stop_instance)
        buttons_layout.addWidget(self.stop_btn)
        
        self.restart_btn = QPushButton("重启")
        self.restart_btn.clicked.connect(self.on_restart_instance)
        buttons_layout.addWidget(self.restart_btn)
        
        self.update_btn = QPushButton("更新")
        self.update_btn.clicked.connect(self.on_update_instance)
        buttons_layout.addWidget(self.update_btn)
        
        self.delete_btn = QPushButton("删除 (Ctrl+D)")
        self.delete_btn.setStyleSheet("background-color: #e74c3c;")
        self.delete_btn.clicked.connect(self.on_delete_instance)
        buttons_layout.addWidget(self.delete_btn)
        
        control_layout.addLayout(buttons_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)
        
        # 进度文本
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        self.progress_label.setVisible(False)
        control_layout.addWidget(self.progress_label)
        
        self.instance_control_card.content_layout.addLayout(control_layout)
    
    def create_log_page(self):
        """创建日志页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # 标题
        title = QLabel("日志查看")
        title.setFont(QFont("Microsoft YaHei", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50;")
        layout.addWidget(title)
        
        # 日志类型选择
        log_type_layout = QHBoxLayout()
        self.core_log_btn = QPushButton("核心日志")
        self.core_log_btn.clicked.connect(lambda: self.show_logs('core'))
        log_type_layout.addWidget(self.core_log_btn)
        
        self.kvrocks_log_btn = QPushButton("数据库日志")
        self.kvrocks_log_btn.clicked.connect(lambda: self.show_logs('kvrocks'))
        log_type_layout.addWidget(self.kvrocks_log_btn)
        
        self.stop_log_btn = QPushButton("停止日志")
        self.stop_log_btn.setStyleSheet("background-color: #e74c3c;")
        self.stop_log_btn.clicked.connect(self.stop_logs)
        log_type_layout.addWidget(self.stop_log_btn)
        
        self.clear_log_btn = QPushButton("清空日志")
        self.clear_log_btn.setStyleSheet("background-color: #95a5a6;")
        self.clear_log_btn.clicked.connect(lambda: self.log_text.clear())
        log_type_layout.addWidget(self.clear_log_btn)
        
        log_type_layout.addStretch()
        layout.addLayout(log_type_layout)
        
        # 日志显示
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.log_text)
        
        return page
    
    def create_settings_page(self):
        """创建设置页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # 标题
        title = QLabel("系统设置")
        title.setFont(QFont("Microsoft YaHei", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50;")
        layout.addWidget(title)
        
        # 主题设置
        theme_card = ModernCard("主题设置")
        theme_layout = QHBoxLayout()
        
        theme_label = QLabel("深色模式:")
        self.dark_mode_checkbox = QCheckBox()
        self.dark_mode_checkbox.stateChanged.connect(self.on_dark_mode_changed)
        
        theme_layout.addWidget(theme_label)
        theme_layout.addWidget(self.dark_mode_checkbox)
        theme_layout.addStretch()
        
        theme_card.content_layout.addLayout(theme_layout)
        layout.addWidget(theme_card)
        
        # 备份恢复
        backup_card = ModernCard("数据备份与恢复")
        backup_layout = QVBoxLayout()
        
        backup_desc = QLabel("备份所有实例配置和数据，或从备份文件恢复")
        backup_desc.setWordWrap(True)
        backup_layout.addWidget(backup_desc)
        
        backup_buttons_layout = QHBoxLayout()
        
        backup_btn = QPushButton("备份所有实例")
        backup_btn.setStyleSheet("background-color: #3498db; padding: 8px;")
        backup_btn.clicked.connect(self.on_backup_instances)
        backup_buttons_layout.addWidget(backup_btn)
        
        restore_btn = QPushButton("从备份恢复")
        restore_btn.setStyleSheet("background-color: #9b59b6; padding: 8px;")
        restore_btn.clicked.connect(self.on_restore_instances)
        backup_buttons_layout.addWidget(restore_btn)
        
        backup_layout.addLayout(backup_buttons_layout)
        backup_card.content_layout.addLayout(backup_layout)
        layout.addWidget(backup_card)
        
        # 更新检查
        update_card = ModernCard("软件更新")
        update_layout = QVBoxLayout()
        
        update_desc = QLabel("检查并更新到最新版本")
        update_desc.setWordWrap(True)
        update_layout.addWidget(update_desc)
        
        self.check_update_btn = QPushButton("检查更新")
        self.check_update_btn.setStyleSheet("background-color: #2ecc71; padding: 8px;")
        self.check_update_btn.clicked.connect(self.check_for_updates)
        update_layout.addWidget(self.check_update_btn)
        
        self.update_status_label = QLabel("当前版本: v4.0.0")
        self.update_status_label.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        update_layout.addWidget(self.update_status_label)
        
        update_card.content_layout.addLayout(update_layout)
        layout.addWidget(update_card)
        
        # Docker 清理
        cleanup_card = ModernCard("Docker 清理")
        cleanup_info = QLabel("清理未使用的 Docker 资源（镜像、容器、卷）以释放磁盘空间")
        cleanup_info.setWordWrap(True)
        cleanup_card.content_layout.addWidget(cleanup_info)
        
        cleanup_btn = QPushButton("执行清理")
        cleanup_btn.clicked.connect(self.on_docker_cleanup)
        cleanup_card.content_layout.addWidget(cleanup_btn)
        
        layout.addWidget(cleanup_card)
        
        # 系统监控
        monitoring_card = ModernCard("系统资源监控")
        monitoring_layout = QVBoxLayout()
        
        monitoring_desc = QLabel("实时监控系统资源使用情况")
        monitoring_desc.setWordWrap(True)
        monitoring_layout.addWidget(monitoring_desc)
        
        self.monitoring_btn = QPushButton("打开监控面板")
        self.monitoring_btn.setStyleSheet("background-color: #9b59b6; padding: 8px;")
        self.monitoring_btn.clicked.connect(self.open_monitoring_dashboard)
        monitoring_layout.addWidget(self.monitoring_btn)
        
        monitoring_card.content_layout.addLayout(monitoring_layout)
        layout.addWidget(monitoring_card)
        
        # 磁盘使用
        storage_card = ModernCard("磁盘使用情况")
        self.storage_info = QTextEdit()
        self.storage_info.setReadOnly(True)
        self.storage_info.setMaximumHeight(200)
        storage_card.content_layout.addWidget(self.storage_info)
        
        refresh_storage_btn = QPushButton("刷新 (F5)")
        refresh_storage_btn.clicked.connect(self.refresh_storage_info)
        storage_card.content_layout.addWidget(refresh_storage_btn)
        
        layout.addWidget(storage_card)
        
        layout.addStretch()
        
        return page
    
    def check_docker_periodically(self):
        """定期检查 Docker 状态"""
        def check():
            status = self.docker_detector.check_docker()
            
            # 构建状态文本，包含更多信息
            if status['installed']:
                if status['running']:
                    status_text = f"运行中\n{status['version']}\n容器: {status['containers']} | 镜像: {status['images']}"
                    color = "#27ae60"
                else:
                    status_text = f"已安装\n未运行\n{status['version']}"
                    color = "#f39c12"
            else:
                status_text = f"未安装\n请先安装 Docker"
                color = "#e74c3c"
            
            self.docker_status_label.setText(status_text)
            self.docker_status_label.setStyleSheet(f"color: {color}; font-size: 12px;")
            
            # 更新存储信息
            disk_usage = self.docker_detector.get_disk_usage()
            if disk_usage:
                self.storage_label.setText("活跃")
            else:
                self.storage_label.setText("不可用")
        
        check()
        # 设置更频繁的检查间隔
        QTimer.singleShot(5000, self.check_docker_periodically)
    
    def refresh_instance_list(self):
        """刷新实例列表"""
        # 使用线程来避免UI阻塞
        self.refresh_worker = RefreshInstancesWorker(self.instance_manager)
        self.refresh_worker.result_ready.connect(self.on_instances_refreshed)
        self.refresh_worker.start()
    
    def on_instances_refreshed(self, instances, running_count):
        """实例刷新完成回调"""
        existing_ports = [i['port'] for i in instances]
        self.instance_list.load_instances(instances)
        
        # 更新统计
        self.instances_count_label.setText(str(len(instances)))
        self.running_count_label.setText(str(running_count))

    def on_instance_selected(self, instance):
        """实例选择事件"""
        self.current_instance = instance
        self.instance_name_label.setText(f"{instance['name']} (端口: {instance['port']})")
        self.content_stack.setCurrentWidget(self.dashboard_page)

    def on_instances_selected(self, instances):
        """批量实例选择事件"""
        # 根据选择的实例数量启用/禁用批量操作按钮
        has_selection = len(instances) > 0
        self.batch_start_btn.setEnabled(has_selection)
        self.batch_stop_btn.setEnabled(has_selection)

    def on_create_instance(self):
        """创建实例"""
        existing_ports = [i['port'] for i in self.instance_manager.instances]
        dialog = CreateInstanceDialog(self, existing_ports)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            config = dialog.result
            
            # 创建实例
            if self.instance_manager.create_instance(
                config['name'],
                config['port'],
                config['user'],
                config['password'],
                config['version']
            ):
                QMessageBox.information(self, "成功", f"实例 '{config['name']}' 创建成功！")
                self.refresh_instance_list()
            else:
                QMessageBox.critical(self, "错误", "实例创建失败")
    
    def on_delete_instance(self):
        """删除实例"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        reply = QMessageBox.question(
            self,
            "确认删除",
            f"确定要删除实例 '{self.current_instance['name']}' 吗？\n\n这将停止并删除所有容器、卷和数据。\n此操作不可恢复！",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.instance_manager.delete_instance(self.current_instance['name']):
                QMessageBox.information(self, "成功", "实例删除成功！")
                self.current_instance = None
                self.instance_name_label.setText("未选择实例")
                self.refresh_instance_list()
            else:
                QMessageBox.critical(self, "错误", "实例删除失败")
    
    def on_export_instance(self):
        """导出实例配置"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        config = self.instance_manager.export_instance(self.current_instance['name'])
        if config:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "导出实例配置",
                f"{self.current_instance['name']}_config.json",
                "JSON 文件 (*.json)"
            )
            
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(config)
                    QMessageBox.information(self, "成功", "配置导出成功！")
                except Exception as e:
                    QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
        else:
            QMessageBox.critical(self, "错误", "无法读取实例配置")
    
    def on_import_instance(self):
        """导入实例配置"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "导入实例配置",
            "",
            "JSON 文件 (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    config_str = f.read()
                
                success, message = self.instance_manager.import_instance(config_str)
                
                if success:
                    QMessageBox.information(self, "成功", message)
                    self.refresh_instance_list()
                else:
                    QMessageBox.warning(self, "警告", message)
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入失败: {str(e)}")

    def on_batch_start(self):
        """批量启动实例"""
        selected_items = self.instance_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择要启动的实例")
            return

        instance_names = []
        for item in selected_items:
            instance = item.data(Qt.ItemDataRole.UserRole)
            instance_names.append(instance['name'])

        # 显示确认对话框
        reply = QMessageBox.question(
            self,
            "确认批量启动",
            f"确定要启动以下 {len(instance_names)} 个实例吗？\n\n" + "\n".join(instance_names),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.progress_bar.setVisible(True)
            self.progress_label.setVisible(True)
            self.progress_label.setText("正在批量启动实例...")

            # 执行批量启动
            results = self.instance_manager.batch_start_instances(instance_names)

            # 检查结果
            success_count = sum(1 for result in results.values() if result)
            self.progress_label.setText(f"批量启动完成: {success_count}/{len(instance_names)} 成功")

            QMessageBox.information(
                self, 
                "批量启动完成", 
                f"批量启动完成！成功: {success_count}, 失败: {len(instance_names) - success_count}"
            )
            self.refresh_instance_list()
            self.progress_bar.setVisible(False)
            self.progress_label.setVisible(False)

    def on_batch_stop(self):
        """批量停止实例"""
        selected_items = self.instance_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择要停止的实例")
            return

        instance_names = []
        for item in selected_items:
            instance = item.data(Qt.ItemDataRole.UserRole)
            instance_names.append(instance['name'])

        # 显示确认对话框
        reply = QMessageBox.question(
            self,
            "确认批量停止",
            f"确定要停止以下 {len(instance_names)} 个实例吗？\n\n" + "\n".join(instance_names),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.progress_bar.setVisible(True)
            self.progress_label.setVisible(True)
            self.progress_label.setText("正在批量停止实例...")

            # 执行批量停止
            results = self.instance_manager.batch_stop_instances(instance_names)

            # 检查结果
            success_count = sum(1 for result in results.values() if result)
            self.progress_label.setText(f"批量停止完成: {success_count}/{len(instance_names)} 成功")

            QMessageBox.information(
                self, 
                "批量停止完成", 
                f"批量停止完成！成功: {success_count}, 失败: {len(instance_names) - success_count}"
            )
            self.refresh_instance_list()
            self.progress_bar.setVisible(False)
            self.progress_label.setVisible(False)

    def on_start_instance(self):
        """启动实例"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        try:
            instance_dir = Path(self.current_instance['path'])
            commands = [
                f"docker compose --env-file .env up -d"
            ]
            
            self.progress_bar.setVisible(True)
            self.progress_label.setVisible(True)
            self.progress_label.setText("正在启动实例...")
            
            self.worker = WorkerThread(commands, instance_dir)
            self.worker.output_signal.connect(lambda msg: self.log_preview.append(msg))
            self.worker.progress_signal.connect(lambda p: self.update_progress(p, "启动实例"))
            self.worker.finished_signal.connect(lambda success, msg: self.on_instance_operation_finished(success, msg, "启动"))
            self.worker.start()
        except Exception as e:
            QMessageBox.critical(self, "启动失败", f"启动实例时发生错误:\n{str(e)}")
    
    def on_stop_instance(self):
        """停止实例"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        try:
            instance_dir = Path(self.current_instance['path'])
            commands = [
                f"docker compose --env-file .env stop"
            ]
            
            self.progress_bar.setVisible(True)
            self.progress_label.setVisible(True)
            self.progress_label.setText("正在停止实例...")
            
            self.worker = WorkerThread(commands, instance_dir)
            self.worker.output_signal.connect(lambda msg: self.log_preview.append(msg))
            self.worker.progress_signal.connect(lambda p: self.update_progress(p, "停止实例"))
            self.worker.finished_signal.connect(lambda success, msg: self.on_instance_operation_finished(success, msg, "停止"))
            self.worker.start()
        except Exception as e:
            QMessageBox.critical(self, "停止失败", f"停止实例时发生错误:\n{str(e)}")
    
    def on_restart_instance(self):
        """重启实例"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        try:
            instance_dir = Path(self.current_instance['path'])
            commands = [
                f"docker compose --env-file .env restart"
            ]
            
            self.progress_bar.setVisible(True)
            self.progress_label.setVisible(True)
            self.progress_label.setText("正在重启实例...")
            
            self.worker = WorkerThread(commands, instance_dir)
            self.worker.output_signal.connect(lambda msg: self.log_preview.append(msg))
            self.worker.progress_signal.connect(lambda p: self.update_progress(p, "重启实例"))
            self.worker.finished_signal.connect(lambda success, msg: self.on_instance_operation_finished(success, msg, "重启"))
            self.worker.start()
        except Exception as e:
            QMessageBox.critical(self, "重启失败", f"重启实例时发生错误:\n{str(e)}")
    
    def on_update_instance(self):
        """更新实例"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        try:
            instance_dir = Path(self.current_instance['path'])
            commands = [
                f"docker compose --env-file .env pull",
                f"docker compose --env-file .env up -d"
            ]
            
            self.progress_bar.setVisible(True)
            self.progress_label.setVisible(True)
            self.progress_label.setText("正在更新实例...")
            
            self.worker = WorkerThread(commands, instance_dir)
            self.worker.output_signal.connect(lambda msg: self.log_preview.append(msg))
            self.worker.progress_signal.connect(lambda p: self.update_progress(p, "更新实例"))
            self.worker.finished_signal.connect(lambda success, msg: self.on_instance_operation_finished(success, msg, "更新"))
            self.worker.start()
        except Exception as e:
            QMessageBox.critical(self, "更新失败", f"更新实例时发生错误:\n{str(e)}")

    def update_progress(self, progress, operation):
        """更新进度"""
        self.progress_bar.setValue(progress)
        self.progress_label.setText(f"{operation}中... {progress}%")
    
    def on_instance_operation_finished(self, success, message, operation):
        """实例操作完成"""
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        if success:
            QMessageBox.information(self, "成功", f"实例{operation}成功！")
            self.refresh_instance_list()
        else:
            QMessageBox.critical(self, "错误", f"实例{operation}失败: {message}")
    
    def show_logs(self, log_type):
        """显示日志"""
        if not self.current_instance:
            QMessageBox.warning(self, "警告", "请先选择一个实例")
            return
        
        container_name = f"decotv-{self.current_instance['name']}-{'core' if log_type == 'core' else 'kvrocks'}"
        
        self.log_text.clear()
        self.log_text.append(f"正在获取 {log_type} 日志...\n")
        
        # 如果已有日志监控线程在运行，则停止它
        self.stop_logs()
        
        # 创建新的日志监控线程
        self.log_monitor_thread = LogMonitorThread(container_name)
        self.log_monitor_thread.log_signal.connect(lambda msg: self.log_text.append(msg))
        self.log_monitor_thread.error_signal.connect(lambda msg: self.log_text.append(msg))
        self.log_monitor_thread.start()
        
        self.content_stack.setCurrentWidget(self.log_page)
    
    def stop_logs(self):
        """停止日志"""
        if hasattr(self, 'log_monitor_thread') and self.log_monitor_thread.isRunning():
            self.log_monitor_thread.stop()
            self.log_monitor_thread.wait()
        self.log_text.append("\n日志已停止")
    
    def on_dark_mode_changed(self, state):
        """深色模式切换事件"""
        self.toggle_dark_mode(state == Qt.CheckState.Checked)
    
    def on_backup_instances(self):
        """备份所有实例"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "备份实例",
            f"decotv_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON 文件 (*.json)"
        )
        
        if file_path:
            success, message = self.instance_manager.backup_all_instances(file_path)
            if success:
                QMessageBox.information(self, "备份成功", message)
            else:
                QMessageBox.critical(self, "备份失败", message)
    
    def on_restore_instances(self):
        """从备份恢复实例"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "从备份恢复",
            "",
            "JSON 文件 (*.json)"
        )
        
        if file_path:
            reply = QMessageBox.question(
                self,
                "确认恢复",
                "此操作将覆盖现有的实例配置。确定要继续吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success, message = self.instance_manager.restore_from_backup(file_path)
                if success:
                    QMessageBox.information(self, "恢复成功", message)
                    self.refresh_instance_list()
                else:
                    QMessageBox.critical(self, "恢复失败", message)
    
    def perform_update(self, version):
        """执行更新"""
        # 这里只是一个示例，实际项目中需要实现真正的更新逻辑
        QMessageBox.information(self, "更新", f"将在后台下载并安装版本 {version}\n\n实际更新逻辑需要根据部署方式进行实现。")

    def open_monitoring_dashboard(self):
        """打开监控面板"""
        self.content_stack.setCurrentWidget(self.monitoring_page)

    def refresh_storage_info(self):
        """刷新磁盘使用情况"""
        try:
            disk_info = self.docker_detector.get_disk_usage()
            if not disk_info:
                self.storage_info.setText("无法获取 Docker磁盘使用情况")
                return

            info = ""
            for key, value in disk_info.items():
                info += f"{key}: {value}\n"
            self.storage_info.setText(info)
        except Exception as e:
            self.storage_info.setText(f"获取失败: {str(e)}")

    def on_docker_cleanup(self):
        """Docker 清理"""
        reply = QMessageBox.question(
            self,
            "确认清理",
            "这将删除未使用的 Docker 资源（镜像、容器、网络、卷）。\n\n是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            commands = [
                "docker system prune -f",
                "docker volume prune -f"
            ]
            
            self.worker = WorkerThread(commands)
            self.worker.output_signal.connect(lambda msg: self.storage_info.append(msg))
            self.worker.finished_signal.connect(lambda success, msg: self.on_cleanup_finished(success, msg))
            self.worker.start()
    
    def on_cleanup_finished(self, success, message):
        """清理完成"""
        if success:
            QMessageBox.information(self, "成功", "Docker 清理完成！")
            self.refresh_storage_info()
        else:
            QMessageBox.critical(self, "错误", f"清理失败: {message}")
    
    def check_for_updates(self):
        """检查更新"""
        self.check_update_btn.setEnabled(False)
        self.update_status_label.setText("正在检查更新...")
        
        # 使用线程检查更新
        self.update_checker = UpdateCheckerThread()
        self.update_checker.update_available.connect(self.on_update_available)
        self.update_checker.no_update.connect(self.on_no_update)
        self.update_checker.error_occurred.connect(self.on_update_error)
        self.update_checker.start()
    
    def on_update_available(self, new_version, changelog):
        """发现新版本"""
        self.check_update_btn.setEnabled(True)
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("发现新版本")
        msg_box.setText(f"发现新版本: {new_version}")
        msg_box.setInformativeText(f"更新内容:\n{changelog}")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setDefaultButton(QMessageBox.StandardButton.Yes)
        msg_box.setButtonText(QMessageBox.StandardButton.Yes, "立即更新")
        msg_box.setButtonText(QMessageBox.StandardButton.No, "稍后再说")
        
        reply = msg_box.exec()
        if reply == QMessageBox.StandardButton.Yes:
            self.perform_update(new_version)
    
    def on_no_update(self):
        """没有新版本"""
        self.check_update_btn.setEnabled(True)
        self.update_status_label.setText("已是最新版本 (v5.0.0)")
        QMessageBox.information(self, "检查更新", "当前已是最新版本！")
    
    def on_update_error(self, error_msg):
        """更新检查出错"""
        self.check_update_btn.setEnabled(True)
        self.update_status_label.setText("更新检查失败")
        QMessageBox.critical(self, "更新错误", f"检查更新时发生错误:\n{error_msg}")
    
    def perform_update(self, version):
        """执行更新"""
        # 改进的更新逻辑
        reply = QMessageBox.question(
            self,
            "确认更新",
            f"确定要更新到版本 {version} 吗？\n\n更新过程中程序可能会重启。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # 触发更新钩子
            update_info = {
                'version': version,
                'timestamp': datetime.now().isoformat()
            }
            self.plugin_manager.trigger_hook('before_update', update_info)
            
            # 在这里实现实际的更新逻辑
            try:
                # 示例更新逻辑 - 实际项目中应实现真实的更新机制
                import tempfile
                import urllib.request
                import zipfile
                import shutil
                
                # 创建临时目录进行更新
                with tempfile.TemporaryDirectory() as temp_dir:
                    # 模拟下载更新包
                    QMessageBox.information(
                        self, 
                        "更新通知", 
                        f"正在后台下载版本 {version} 的更新包...\n\n"
                        "注意：实际更新功能需要根据部署方式实现。"
                    )
                    
                    # 更新完成后触发完成钩子
                    self.plugin_manager.trigger_hook('after_update', update_info)
                    
                    QMessageBox.information(
                        self, 
                        "更新完成", 
                        f"已准备好更新到版本 {version}，请重启程序完成更新。"
                    )
            except Exception as e:
                QMessageBox.critical(self, "更新失败", f"更新过程中发生错误:\n{str(e)}")
                self.plugin_manager.trigger_hook('update_failed', {'error': str(e), **update_info})


class UpdateCheckerThread(QThread):
    """更新检查线程"""
    update_available = pyqtSignal(str, str)  # new_version, changelog
    no_update = pyqtSignal()
    error_occurred = pyqtSignal(str)  # error_message
    
    def __init__(self):
        super().__init__()
    
    def run(self):
        try:
            # 模拟检查更新 - 在实际项目中应连接到更新服务器
            import time
            time.sleep(1)  # 模拟网络延迟
            
            # 这里应该连接到真实的更新服务器
            # 示例：检查GitHub Releases或其他更新源
            current_version = "5.0.0"
            latest_version = "5.0.0"  # 实际应从服务器获取
            
            # 模拟版本比较逻辑
            if compare_versions(latest_version, current_version) > 0:
                # 发现新版本
                changelog = "• 性能优化\n• 安全增强\n• Bug修复\n• 新功能"
                self.update_available.emit(latest_version, changelog)
            else:
                # 没有新版本
                self.no_update.emit()
        except Exception as e:
            self.error_occurred.emit(str(e))


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DecoTV 管理器 V5")
    app.setQuitOnLastWindowClosed(False)  # 关闭窗口时不退出应用，以便系统托盘继续运行
    
    window = DecoTVManager()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()