import subprocess
import time
import signal
import platform
import threading
import queue
import sys
import os
import select

class XrayManager:
    def __init__(self, xray_path="xray.exe", config_path="config.json"):
        """初始化 Xray 管理器，设置路径和平台相关参数"""
        self.xray_path = xray_path
        self.config_path = config_path
        self.process = None
        self.is_windows = platform.system() == "Windows"
        self.log_queue = queue.Queue()
        self.stop_logging = threading.Event()
        self._validate_paths()

    def _validate_paths(self):
        """验证 Xray 可执行文件和配置文件是否存在"""
        if not os.path.isfile(self.xray_path):
            print(f"错误: Xray 可执行文件 '{self.xray_path}' 不存在。")
            sys.exit(1)
        if not os.path.isfile(self.config_path):
            print(f"错误: 配置文件 '{self.config_path}' 不存在。")
            sys.exit(1)

    def start(self):
        """启动 Xray 代理进程"""
        if self.is_running():
            print("Xray 已在运行。")
            return False
        try:
            self.process = subprocess.Popen(
                [self.xray_path, "-c", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if self.is_windows else 0
            )
            time.sleep(1)  # 短暂等待以检查进程是否成功启动
            if self.process.poll() is not None:
                error_output = self.process.stdout.read() or "无输出"
                print(f"启动 Xray 失败: {error_output}")
                self.process = None
                return False
            print(f"Xray 已启动，PID: {self.process.pid}")
            return True
        except FileNotFoundError:
            print(f"错误: Xray 可执行文件 '{self.xray_path}' 未找到。")
            return False
        except Exception as e:
            print(f"启动 Xray 时出错: {e}")
            return False

    def stop(self):
        """停止 Xray 代理进程"""
        if not self.is_running():
            print("Xray 未运行。")
            return False
        try:
            if self.is_windows:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            else:
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            print("Xray 已停止。")
            self.process = None
            return True
        except Exception as e:
            print(f"停止 Xray 时出错: {e}")
            return False

    def restart(self):
        """重启 Xray 代理进程"""
        print("正在重启 Xray...")
        self.stop()
        time.sleep(1)  # 确保进程完全停止
        return self.start()

    def reload_config(self):
        """重载 Xray 配置文件（Windows 下通过重启实现）"""
        if not self.is_running():
            print("Xray 未运行，正在启动...")
            return self.start()
        print("正在重载 Xray 配置...")
        return self.restart()

    def is_running(self):
        """检查 Xray 进程是否在运行"""
        return self.process is not None and self.process.poll() is None

    def _read_stream(self, stream, stream_name):
        """读取输出流并将数据放入队列，兼容 Windows 和非 Windows 系统"""
        if not self.is_windows:
            try:
                import fcntl
                fd = stream.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            except Exception as e:
                self.log_queue.put((stream_name, f"设置非阻塞模式失败: {e}"))
                return

        while not self.stop_logging.is_set() and self.is_running():
            try:
                if self.is_windows:
                    line = stream.readline()
                    if not line:
                        break
                    self.log_queue.put((stream_name, line.strip()))
                else:
                    rlist, _, _ = select.select([stream.fileno()], [], [], 0.1)
                    if stream.fileno() in rlist:
                        line = stream.readline()
                        if not line:
                            break
                        self.log_queue.put((stream_name, line.strip()))
                    else:
                        time.sleep(0.01)
            except (ValueError, BrokenPipeError, OSError) as e:
                self.log_queue.put((stream_name, f"读取 {stream_name} 时出错 (管道可能已关闭): {e}"))
                break
            except Exception as e:
                self.log_queue.put((stream_name, f"读取 {stream_name} 时出错: {e}"))
                break
        self.log_queue.put((stream_name, None))

    def view_logs(self):
        """实时查看 Xray stdout 日志，按 Ctrl+C 退出"""
        if not self.is_running():
            print("Xray 未运行。")
            return
        if self.process.stdout is None:
            print("错误: Xray 的 stdout 不可用。")
            return
        print("正在显示 Xray stdout 日志（按 Ctrl+C 停止查看）...")

        # 保存原始信号处理程序
        original_handler = signal.getsignal(signal.SIGINT)
        
        # 设置临时信号处理程序，仅抛出 KeyboardInterrupt
        def temp_signal_handler(sig, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, temp_signal_handler)

        self.stop_logging.clear()
        while not self.log_queue.empty():
            self.log_queue.get()

        stdout_thread = threading.Thread(
            target=self._read_stream, args=(self.process.stdout, "stdout")
        )
        stdout_thread.daemon = True
        stdout_thread.start()

        try:
            while self.is_running() and not self.stop_logging.is_set():
                try:
                    stream_name, line = self.log_queue.get(timeout=0.1)
                    if line is None:
                        break
                    if line:
                        print(f"[{stream_name}] {line}")
                except queue.Empty:
                    continue
        except KeyboardInterrupt:
            print("\n已停止查看日志，Xray 仍在运行。")
        except Exception as e:
            print(f"查看日志时出错: {e}")
        finally:
            self.stop_logging.set()
            stdout_thread.join(timeout=0.1)
            while not self.log_queue.empty():
                try:
                    self.log_queue.get_nowait()
                except queue.Empty:
                    break
            signal.signal(signal.SIGINT, original_handler)

# Global flag to track Ctrl+C
ctrl_c_flag = False

def signal_handler(sig, frame):
    """全局处理 Ctrl+C 信号，设置标志而不直接抛出异常"""
    global ctrl_c_flag
    ctrl_c_flag = True  # Set flag to indicate Ctrl+C was pressed

def main():
    """主函数，运行 Xray 管理器菜单"""
    global ctrl_c_flag
    signal.signal(signal.SIGINT, signal_handler)
    xray_manager = XrayManager()

    while True:
        ctrl_c_flag = False  # Reset Ctrl+C flag at the start of each loop
        print("\nXray 代理管理器")
        print("1. 启动 Xray")
        print("2. 停止 Xray")
        print("3. 重启 Xray")
        print("4. 重载配置")
        print("5. 检查状态")
        print("6. 查看 stdout 日志")
        print("7. 退出")
        try:
            choice = input("输入你的选择 (1-7): ").strip()
            if ctrl_c_flag:
                print("\n检测到 Ctrl+C，请继续选择操作。")
                continue
            if choice == "1":
                xray_manager.start()
            elif choice == "2":
                xray_manager.stop()
            elif choice == "3":
                xray_manager.restart()
            elif choice == "4":
                xray_manager.reload_config()
            elif choice == "5":
                status = "运行中" if xray_manager.is_running() else "未运行"
                print(f"Xray 状态: {status}")
            elif choice == "6":
                xray_manager.view_logs()
            elif choice == "7":
                if xray_manager.is_running():
                    xray_manager.stop()
                print("正在退出...")
                break
            else:
                print("无效选择，请输入 1-7。")
        except KeyboardInterrupt:
            print("\n检测到 Ctrl+C，请继续选择操作。")
        except Exception as e:
            if str(e):
                print(f"操作时出错: {e}")
            continue

if __name__ == "__main__":
    main()