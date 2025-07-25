import shutil
import sys
import logging
import urllib
import weakref
import winreg
from importlib import resources
from pathlib import Path

import requests
from PyQt5.QtGui import QTextCharFormat, QColor, QFont, QIcon, QSyntaxHighlighter, QTextCursor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QAction, QVBoxLayout, QWidget, QLineEdit,
    QTabWidget, QToolBar, QStatusBar, QInputDialog, QTextEdit, QMessageBox,
    QFileDialog, QMenu, QLabel, QProgressBar, QDockWidget
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile, QWebEngineSettings, QWebEngineDownloadItem
from PyQt5.QtNetwork import QNetworkProxy
from PyQt5.QtCore import QUrl, Qt, QThread, pyqtSignal, QTimer, QEventLoop
import re
from bs4 import BeautifulSoup
try:
    import orjson as json
except ImportError:
    import json

# 配置日志记录
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('browser.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# 禁用 DownloadIfNotExists
import browserforge.download

def hook_download_if_not_exists(**flags: bool) -> None:
    pass

browserforge.download.DownloadIfNotExists = hook_download_if_not_exists
logging.debug("已禁用 browserforge.download.DownloadIfNotExists")

# Hook extract_json
try:
    from browserforge.bayesian_network import extract_json
except ImportError:
    logging.warning("无法导入 browserforge.network.extract_json，跳过 Hook")
    extract_json = None

def hook_extract_json(original_extract_json):
    def hooked_extract_json(path: Path) -> dict:
        cache_dir = Path.cwd() / "data" / "browserforge" / "headers" / "data"
        logging.debug(f"Hook extract_json: 原始路径 {path}, 重定向到 {cache_dir}")
        if path.name in ["input-network.zip", "headers-order.json", "browser-helper-file.json", "header-network.zip"]:
            redirected_path = cache_dir / path.name
        else:
            redirected_path = path

        if not redirected_path.exists():
            logging.warning(f"缓存文件 {redirected_path} 不存在，尝试使用原始路径 {path}")
            if path.exists():
                return original_extract_json(path)
            else:
                logging.error(f"文件 {path} 和 {redirected_path} 均不存在")
                return {}
        logging.debug(f"使用缓存文件: {redirected_path}")
        return original_extract_json(redirected_path)
    return hooked_extract_json

if extract_json is not None:
    try:
        import browserforge.bayesian_network
        browserforge.bayesian_network.extract_json = hook_extract_json(extract_json)
        logging.debug("成功 Hook browserforge.network.extract_json")
    except Exception as e:
        logging.error(f"Hook extract_json 失败: {str(e)}")

from browserforge.headers import HeaderGenerator

class FormatterThread(QThread):
    formatted = pyqtSignal(str)

    def __init__(self, html_content):
        super().__init__()
        self.html_content = html_content

    def run(self):
        try:
            logging.debug("开始异步格式化 HTML")
            soup = BeautifulSoup(self.html_content, 'html.parser')
            formatted_content = soup.prettify()
            logging.debug(f"格式化后内容长度: {len(formatted_content)}")
            self.formatted.emit(formatted_content)
        except Exception as e:
            logging.error(f"异步格式化 HTML 时发生错误: {str(e)}")
            formatted_content = self.simple_format(self.html_content)
            self.formatted.emit(formatted_content)

    def simple_format(self, content):
        try:
            lines = content.replace('>', '>\n').replace('<', '\n<').split('\n')
            formatted = []
            indent_level = 0
            indent = "  "
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('</'):
                    indent_level = max(0, indent_level - 1)
                formatted.append(indent * indent_level + line)
                if line.startswith('<') and not line.startswith('</') and not line.endswith('/>'):
                    indent_level += 1
            return '\n'.join(formatted)
        except Exception as e:
            logging.error(f"简单格式化失败: {str(e)}")
            return content.replace('\x00', '').encode('utf-8', errors='ignore').decode('utf-8')

class HtmlHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        logging.debug("初始化 HTML 高亮器")
        self.highlighting_rules = []
        tag_format = QTextCharFormat()
        tag_format.setForeground(QColor("#0000FF"))
        tag_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((re.compile(r'</?\w+(?=\s|>|/)'), tag_format))
        attribute_format = QTextCharFormat()
        attribute_format.setForeground(QColor("#800080"))
        self.highlighting_rules.append((re.compile(r'\b\w+\s*=\s*"[^"]*"'), attribute_format))
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#008000"))
        self.highlighting_rules.append((re.compile(r'"[^"]*"'), string_format))
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#808080"))
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((re.compile(r'<!--[\s\S]*?-->'), comment_format))
        css_selector_format = QTextCharFormat()
        css_selector_format.setForeground(QColor("#008080"))
        css_selector_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((re.compile(r'([^{]+)\{'), css_selector_format))
        css_property_format = QTextCharFormat()
        css_property_format.setForeground(QColor("#000080"))
        self.highlighting_rules.append((re.compile(r'\b\w[\w-]*\s*:\s*'), css_property_format))
        css_value_format = QTextCharFormat()
        css_value_format.setForeground(QColor("#800000"))
        self.highlighting_rules.append((re.compile(r':\s*[^;]+;'), css_value_format))
        css_brace_format = QTextCharFormat()
        css_brace_format.setForeground(QColor("#8B0000"))
        css_brace_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((re.compile(r'[{}]'), css_brace_format))
        entity_format = QTextCharFormat()
        entity_format.setForeground(QColor("#FFA500"))
        self.highlighting_rules.append((re.compile(r'&\w+;'), entity_format))

    def highlightBlock(self, text):
        try:
            for pattern, format in self.highlighting_rules:
                for match in pattern.finditer(text):
                    start, end = match.start(), match.end()
                    self.setFormat(start, end - start, format)
            if '<style' in text.lower():
                style_start = text.lower().find('<style')
                style_end = text.lower().find('</style>')
                if style_end == -1:
                    style_end = len(text)
                for pattern, format in self.highlighting_rules[4:8]:
                    for match in pattern.finditer(text, style_start, style_end):
                        start, end = match.start(), match.end()
                        self.setFormat(start, end - start, format)
        except Exception as e:
            logging.error(f"高亮文本块时发生错误: {str(e)}")
            raise

class WebEnginePage(QWebEnginePage):
    def __init__(self, view, profile):
        super().__init__(profile, view)
        self._view = view
        self.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        self.settings().setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, True)
        logging.debug("初始化 WebEnginePage，JavaScript 已启用")
        self.urlChanged.connect(self.handle_url_changed)
        self.loadFinished.connect(self.inject_navigation_script)

    def handle_url_changed(self, url):
        logging.debug(f"URL 变化: {url.toString()}")
        self._view.setUrl(url)

    def inject_navigation_script(self, ok):
        if ok:
            self.runJavaScript("""
                (function() {
                    document.addEventListener('click', function(event) {
                        let target = event.target.closest('a');
                        if (target && target.href) {
                            console.log('Link clicked: ' + target.href);
                            window.location.href = target.href;
                        }
                    });
                })();
            """, lambda result: logging.debug(f"注入导航脚本结果: {result}"))

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        logging.debug(f"导航请求: URL={url.toString()}, 类型={nav_type}, 主框架={is_main_frame}")
        return True

class BrowserTab(QWidget):
    def __init__(self, parent=None, profile=None):
        super().__init__(parent)
        self._parent = parent
        logging.debug("初始化 BrowserTab")
        self.layout = QVBoxLayout(self)
        try:
            self.view = QWebEngineView(self)
            self.page = WebEnginePage(self.view, profile)
            self.view.setPage(self.page)
            self.view.setContextMenuPolicy(Qt.CustomContextMenu)
            self.view.customContextMenuRequested.connect(self._parent.context_menu)
            self.layout.addWidget(self.view)
            self.setLayout(self.layout)
            logging.debug("BrowserTab 初始化成功")
        except Exception as e:
            logging.error(f"初始化 BrowserTab 失败: {str(e)}")
            raise

    def set_url(self, url_string):
        try:
            if not url_string:
                url_string = "https://google.com"
            if not url_string.startswith(('http://', 'https://')):
                url_string = f"https://{url_string}"
            self.view.setUrl(QUrl(url_string))
            logging.debug(f"设置 URL: {url_string}")
        except Exception as e:
            logging.error(f"设置 URL {url_string} 失败: {str(e)}")

    def get_url(self):
        return self.view.url().toString()


class DownloadManager:
    def __init__(self, parent):
        self.parent_ref = weakref.ref(parent)  # 使用 weakref 跟踪父窗口
        self.downloads = {}  # 存储下载任务和对应的进度条窗口
        logging.debug("DownloadManager 初始化")

    def handle_download(self, download_item):
        try:
            parent = self.parent_ref()  # 获取父窗口引用
            if not parent:
                logging.error("父窗口已销毁，取消下载")
                download_item.cancel()
                return

            # 获取建议文件名
            suggested_path = download_item.suggestedFileName()
            if not suggested_path:
                suggested_path = download_item.url().fileName() or "download"

            # 弹出保存对话框
            file_path, _ = QFileDialog.getSaveFileName(
                parent,
                "保存下载文件",
                suggested_path,
                "All Files (*)"
            )
            if not file_path:
                logging.debug("用户取消下载")
                download_item.cancel()
                return

            # 创建浮动进度条窗口
            dock_widget = QDockWidget(f"下载: {Path(file_path).name}", parent)
            dock_widget.setFloating(True)
            dock_widget.setAllowedAreas(Qt.NoDockWidgetArea)
            dock_widget.setFeatures(QDockWidget.DockWidgetClosable)
            dock_widget.setGeometry(parent.x() + 50, parent.y() + 50, 300, 100)

            # 设置进度条和标签
            container = QWidget()
            layout = QVBoxLayout()
            label = QLabel(f"正在下载: {Path(file_path).name}")
            progress_bar = QProgressBar()
            progress_bar.setValue(0)
            progress_bar.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            layout.addWidget(progress_bar)
            container.setLayout(layout)
            dock_widget.setWidget(container)
            dock_widget.show()

            download_item.setPath(file_path)
            download_item.accept()
            download_id = id(download_item)
            self.downloads[download_id] = {
                "item": download_item,
                "dock_widget": dock_widget,
                "progress_bar": progress_bar
            }

            def update_progress(received, total):
                try:
                    parent = self.parent_ref()
                    if not parent or not self.downloads.get(download_id):
                        logging.error("父窗口或下载任务已销毁，停止更新进度")
                        return
                    if total > 0:
                        progress = int((received / total) * 100)
                        progress_bar.setValue(progress)
                        logging.debug(f"下载进度: {Path(file_path).name} - {progress}%")
                    if download_item.isFinished():
                        dock_widget.close()
                        del self.downloads[download_id]
                        QMessageBox.information(parent, "下载完成", f"文件已保存至: {file_path}")
                        logging.debug(f"下载完成: {file_path}")
                except Exception as e:
                    logging.error(f"更新下载进度失败: {str(e)}")

            def handle_finished():
                try:
                    parent = self.parent_ref()
                    if not parent or not self.downloads.get(download_id):
                        logging.error("父窗口或下载任务已销毁，下载处理终止")
                        return
                    if download_item.state() == QWebEngineDownloadItem.DownloadCompleted:
                        logging.debug(f"下载完成: {file_path}")
                        dock_widget.close()
                        del self.downloads[download_id]
                        QMessageBox.information(parent, "下载完成", f"文件已保存至: {file_path}")
                    elif download_item.state() == QWebEngineDownloadItem.DownloadCancelled:
                        logging.debug(f"下载取消: {file_path}")
                        dock_widget.close()
                        del self.downloads[download_id]
                    elif download_item.state() == QWebEngineDownloadItem.DownloadInterrupted:
                        logging.error(f"下载中断: {file_path}")
                        dock_widget.close()
                        del self.downloads[download_id]
                        QMessageBox.warning(parent, "错误", f"下载中断: {file_path}")
                except Exception as e:
                    logging.error(f"处理下载完成事件失败: {str(e)}")

            download_item.downloadProgress.connect(update_progress)
            download_item.finished.connect(handle_finished)
            logging.debug(f"开始下载: {file_path}")
        except Exception as e:
            logging.error(f"处理下载失败: {str(e)}")
            parent = self.parent_ref()
            if parent:
                QMessageBox.warning(parent, "错误", f"下载失败: {str(e)}")

class SimpleBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        logging.debug("开始初始化 SimpleBrowser")
        try:
            self.setWindowTitle("PP浏览器-搞笑版")
            self.setGeometry(100, 100, 1600, 900)
            self.default_profile = QWebEngineProfile("CustomProfile", self)
            self.download_manager = DownloadManager(self)
            self.default_profile.downloadRequested.connect(self.download_manager.handle_download)
            self.update_request_headers()
            logging.debug("获取 WebEngineProfile 成功")
            self.central_widget = QWidget(self)
            self.layout = QVBoxLayout(self.central_widget)
            self.setCentralWidget(self.central_widget)
            self.toolbar = QToolBar("导航工具栏", self)
            self.addToolBar(self.toolbar)
            self.back_button = QAction("⬅️ 返回", self)
            self.back_button.triggered.connect(self.go_back)
            self.toolbar.addAction(self.back_button)
            self.forward_button = QAction("➡️ 前进", self)
            self.forward_button.triggered.connect(self.go_forward)
            self.toolbar.addAction(self.forward_button)
            self.reload_button = QAction("🔄 刷新", self)
            self.reload_button.setShortcut("F5")
            self.reload_button.triggered.connect(self.reload_current_page)
            self.toolbar.addAction(self.reload_button)
            self.tab_widget = QTabWidget(self)
            self.tab_widget.setTabsClosable(True)
            self.tab_widget.tabCloseRequested.connect(self.close_tab)
            self.tab_widget.currentChanged.connect(self.update_ui_for_current_tab)
            self.layout.addWidget(self.tab_widget)
            self.new_tab_action = QAction(QIcon(), "➕ 新建标签页", self)
            self.new_tab_action.setToolTip("新建标签页")
            self.new_tab_action.triggered.connect(self.add_new_tab)
            self.toolbar.addAction(self.new_tab_action)
            self.url_bar = QLineEdit(self)
            self.url_bar.returnPressed.connect(self.load_url)
            self.toolbar.addWidget(self.url_bar)
            self.status_bar = QStatusBar(self)
            self.setStatusBar(self.status_bar)
            menubar = self.menuBar()
            file_menu = menubar.addMenu("文件")
            view_menu = menubar.addMenu("视图")
            settings_menu = menubar.addMenu("设置")
            new_tab_action_menu = QAction("新建标签页", self)
            new_tab_action_menu.setShortcut("Ctrl+T")
            new_tab_action_menu.triggered.connect(self.add_new_tab)
            file_menu.addAction(new_tab_action_menu)
            exit_action = QAction("退出", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)
            dev_tools_action = QAction("开发者工具", self)
            dev_tools_action.setShortcut("F12")
            dev_tools_action.triggered.connect(self.toggle_dev_tools)
            view_menu.addAction(dev_tools_action)
            view_source_action = QAction("查看页面源代码", self)
            view_source_action.setShortcut("Ctrl+U")
            view_source_action.triggered.connect(self.view_page_source)
            view_menu.addAction(view_source_action)
            set_ua_action = QAction("设置 User-Agent", self)
            set_ua_action.triggered.connect(self.set_user_agent)
            settings_menu.addAction(set_ua_action)
            set_proxy_action = QAction("设置 SOCKS5 代理", self)
            set_proxy_action.triggered.connect(self.set_socks5_proxy)
            settings_menu.addAction(set_proxy_action)
            clear_data_action = QAction("清除浏览器数据", self)
            clear_data_action.triggered.connect(self.clear_browser_data)
            settings_menu.addAction(clear_data_action)
            self.add_new_tab(QUrl("https://google.com"))
            logging.debug("SimpleBrowser 初始化完成")
        except Exception as e:
            logging.error(f"初始化 SimpleBrowser 失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"无法初始化浏览器: {str(e)}")
            sys.exit(1)

    def update_request_headers(self):
        try:
            cache_dir = Path.cwd() / "data" / "browserforge" / "headers" / "data"
            cache_dir.mkdir(parents=True, exist_ok=True)
            required_files = [
                "headers-order.json",
                "input-network.zip",
                "browser-helper-file.json",
                "header-network.zip"
            ]
            self.configure_system_proxy()
            all_files_exist = all((cache_dir / file).exists() for file in required_files)
            if not all_files_exist:
                logging.debug(f"部分指纹库文件缺失，尝试从 site-packages 复制")
                try:
                    with resources.path('browserforge.headers', 'data') as pkg_data_dir:
                        pkg_data_dir = Path(pkg_data_dir)
                    if pkg_data_dir and pkg_data_dir.exists():
                        for file in required_files:
                            src_file = pkg_data_dir / file
                            if src_file.exists():
                                shutil.copy(src_file, cache_dir / file)
                                logging.debug(f"已缓存 {file} 到 {cache_dir / file}")
                            else:
                                logging.warning(f"数据文件 {src_file} 不存在")
                    else:
                        logging.warning("site-packages 路径不可用，跳过复制")
                except Exception as e:
                    logging.error(f"复制文件失败: {str(e)}")
            header_gen = HeaderGenerator()
            headers = header_gen.generate()
            user_agent = headers.get('User-Agent',
                                     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36')
            self.default_profile.setHttpUserAgent(user_agent)
            self.default_profile.setHttpAcceptLanguage("zh-CN,zh;q=0.9,en;q=0.8")
            logging.debug(f"设置 User-Agent: {user_agent}, Accept-Language: zh-CN")
        except Exception as e:
            logging.error(f"设置 User-Agent 失败: {str(e)}")
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
            self.default_profile.setHttpUserAgent(user_agent)
            self.default_profile.setHttpAcceptLanguage("zh-CN,zh;q=0.9,en;q=0.8")
            logging.debug(f"使用默认 User-Agent: {user_agent}")
            QMessageBox.warning(self, "警告", f"无法加载指纹库，使用默认 User-Agent: {str(e)}")

    def configure_system_proxy(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if proxy_enable:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    logging.debug(f"检测到系统代理: {proxy_server}")
                    if proxy_server:
                        proxy_parts = proxy_server.split(";")
                        for part in proxy_parts:
                            if part.startswith("http=") or part.startswith("https=") or part.startswith("socks="):
                                proxy_host_port = part.split("=")[1]
                                if ":" in proxy_host_port:
                                    proxy_host, proxy_port = proxy_host_port.split(":")
                                    proxy = QNetworkProxy()
                                    proxy_type = QNetworkProxy.Socks5Proxy if "socks" in part else QNetworkProxy.HttpProxy
                                    proxy.setType(proxy_type)
                                    proxy.setHostName(proxy_host)
                                    proxy.setPort(int(proxy_port))
                                    QNetworkProxy.setApplicationProxy(proxy)
                                    proxy_url = f"{proxy_type.name.lower()}://{proxy_host}:{proxy_port}"
                                    urllib.request.install_opener(
                                        urllib.request.build_opener(
                                            urllib.request.ProxyHandler({
                                                "http": proxy_url,
                                                "https": proxy_url
                                            })
                                        )
                                    )
                                    requests_session = requests.Session()
                                    requests_session.proxies = {
                                        "http": proxy_url,
                                        "https": proxy_url
                                    }
                                    requests.get = requests_session.get
                                    logging.debug(f"设置系统代理: {proxy_host}:{proxy_port} ({proxy_type.name})")
                                    return proxy_url
        except Exception as e:
            logging.error(f"配置系统代理失败: {str(e)}")
        return None

    def current_tab(self):
        return self.tab_widget.currentWidget()

    def add_new_tab(self, url=None):
        try:
            tab = BrowserTab(self, profile=self.default_profile)
            if url:
                tab.set_url(url.toString())
            else:
                tab.set_url("https://google.com")
            index = self.tab_widget.addTab(tab, f"标签页 {self.tab_widget.count() + 1}")
            self.tab_widget.setCurrentIndex(index)
            tab.view.urlChanged.connect(self.update_url_bar)
            tab.view.loadProgress.connect(self.update_load_progress)
            tab.view.titleChanged.connect(
                lambda title, t=tab: self.tab_widget.setTabText(self.tab_widget.indexOf(t), title or f"标签页 {self.tab_widget.indexOf(t) + 1}"))
            tab.view.loadFinished.connect(self.update_ui_for_current_tab)
            tab.view.page().linkHovered.connect(self.handle_link_hovered)
            logging.debug("新标签页添加成功")
            self.update_ui_for_current_tab()
        except Exception as e:
            logging.error(f"添加新标签页失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"无法添加新标签页: {str(e)}")

    def close_tab(self, index):
        if self.tab_widget.count() < 2:
            QMessageBox.information(self, "提示", "无法关闭最后一个标签页。")
            return
        self.tab_widget.removeTab(index)
        self.update_ui_for_current_tab()

    def load_url(self):
        if self.current_tab():
            self.current_tab().set_url(self.url_bar.text())

    def update_url_bar(self, url=None):
        if self.current_tab():
            display_url = url.toString() if url else self.current_tab().get_url()
            self.url_bar.setText(display_url)
            self.url_bar.setCursorPosition(0)

    def update_load_progress(self, progress):
        if self.current_tab():
            if progress < 100:
                self.status_bar.showMessage(f"加载中... {progress}%")
            else:
                self.status_bar.showMessage("加载完成", 2000)

    def update_ui_for_current_tab(self):
        current_tab = self.current_tab()
        if current_tab:
            self.update_url_bar()
            self.back_button.setEnabled(current_tab.view.history().canGoBack())
            self.forward_button.setEnabled(current_tab.view.history().canGoForward())
            self.reload_button.setEnabled(True)
        else:
            self.url_bar.clear()
            self.back_button.setEnabled(False)
            self.forward_button.setEnabled(False)
            self.reload_button.setEnabled(False)
            self.status_bar.clearMessage()

    def handle_link_hovered(self, url):
        self.status_bar.showMessage(url)
        logging.debug(f"悬停链接: {url}")

    def context_menu(self, pos):
        if not self.current_tab():
            return
        menu = QMenu(self)
        view_source_action = menu.addAction("查看网页源代码")
        open_devtools_action = menu.addAction("打开开发者工具")
        save_page_action = menu.addAction("保存网页")
        view_source_action.triggered.connect(self.view_page_source)
        open_devtools_action.triggered.connect(self.toggle_dev_tools)
        save_page_action.triggered.connect(self.save_page)
        menu.exec_(self.current_tab().view.mapToGlobal(pos))

    def go_back(self):
        if self.current_tab():
            self.current_tab().view.back()

    def go_forward(self):
        if self.current_tab():
            self.current_tab().view.forward()

    def reload_current_page(self):
        if self.current_tab():
            self.current_tab().view.reload()
            logging.debug("刷新当前页面")

    def view_page_source(self):
        if self.current_tab():
            self.current_tab().view.page().toHtml(self._display_page_source)
        else:
            QMessageBox.warning(self, "警告", "没有可用的页面来查看源代码。")

    def _display_page_source(self, html_content):
        try:
            logging.debug("开始显示页面源代码")
            source_window = QMainWindow(self)
            source_window.setWindowTitle("页面源代码")
            source_window.setGeometry(150, 150, 1000, 600)
            text_edit = QTextEdit(source_window)
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Courier New", 10))
            loading_label = QLabel("正在格式化内容，请稍候...", source_window)
            loading_label.setGeometry(50, 50, 300, 30)
            loading_label.show()
            default_format = QTextCharFormat()
            default_format.setForeground(QColor("black"))
            text_edit.setCurrentCharFormat(default_format)
            initial_content = html_content.replace('\x00', '').encode('utf-8', errors='ignore').decode('utf-8')[:5000]
            text_edit.setPlainText(initial_content)
            logging.debug(f"初始内容长度: {len(initial_content)}")
            source_window.highlighter = HtmlHighlighter(text_edit.document())
            logging.debug("高亮器已绑定到 QTextEdit")

            def on_formatted(formatted_content):
                try:
                    source_window.formatted_content = formatted_content
                    text_edit.setPlainText(formatted_content[:5000])
                    loading_label.hide()
                    logging.debug(f"格式化内容已加载，长度: {len(formatted_content)}")
                except Exception as e:
                    logging.error(f"设置格式化内容时发生错误: {str(e)}")
                    raise

            formatter_thread = FormatterThread(html_content)
            formatter_thread.formatted.connect(on_formatted)
            formatter_thread.start()

            def load_more_content():
                try:
                    if not hasattr(source_window, 'formatted_content'):
                        return
                    current_text = text_edit.toPlainText()
                    total_length = len(source_window.formatted_content)
                    if len(current_text) < total_length:
                        scrollbar = text_edit.verticalScrollBar()
                        if scrollbar.value() > scrollbar.maximum() * 0.8:
                            chunk = source_window.formatted_content[len(current_text):len(current_text) + 5000]
                            text_edit.moveCursor(QTextCursor.End)
                            text_edit.insertPlainText(chunk)
                            logging.debug(f"追加内容，当前长度: {len(text_edit.toPlainText())}")
                except Exception as e:
                    logging.error(f"动态加载内容时发生错误: {str(e)}")

            text_edit.verticalScrollBar().valueChanged.connect(load_more_content)
            source_window.setCentralWidget(text_edit)
            source_window.show()
            logging.debug("页面源代码显示完成")
        except Exception as e:
            logging.error(f"显示源代码时发生错误: {str(e)}")
            raise

    def save_page(self):
        if not self.current_tab():
            QMessageBox.warning(self, "警告", "没有可用的页面来保存。")
            return
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "保存网页", "", "HTML Files (*.html);;All Files (*)")
            if file_path:
                def save_html(html_content):
                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        QMessageBox.information(self, "保存网页", "网页已保存成功。")
                        logging.debug(f"网页保存至: {file_path}")
                    except Exception as e:
                        logging.error(f"保存网页失败: {str(e)}")
                        QMessageBox.warning(self, "错误", f"无法保存网页: {str(e)}")
                self.current_tab().view.page().toHtml(save_html)
            else:
                logging.debug("用户取消保存网页")
        except Exception as e:
            logging.error(f"保存网页失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"无法保存网页: {str(e)}")

    def toggle_dev_tools(self):
        if not self.current_tab():
            QMessageBox.warning(self, "警告", "没有可用的页面来打开开发者工具。")
            return
        try:
            current_view = self.current_tab().view
            current_page = current_view.page()
            if not current_page:
                logging.error("当前页面未正确初始化")
                QMessageBox.warning(self, "警告", "当前页面未正确初始化。")
                return
            dev_tools_page = QWebEnginePage(self.default_profile, self)
            dev_tools_view = QWebEngineView(self)
            dev_tools_view.setPage(dev_tools_page)
            current_page.setDevToolsPage(dev_tools_page)
            dev_tools_window = QMainWindow(self)
            dev_tools_window.setCentralWidget(dev_tools_view)
            dev_tools_window.setWindowTitle("开发者工具")
            dev_tools_window.setGeometry(self.x() + 50, self.y() + 50, 800, 600)
            dev_tools_window.show()
            logging.debug("开发者工具打开成功")
        except Exception as e:
            logging.error(f"打开开发者工具失败: {str(e)}")
            QMessageBox.warning(self, "警告", f"无法打开开发者工具: {str(e)}")

    def clear_browser_data(self):
        try:
            logging.debug("开始清除浏览器数据")
            cookie_store = self.default_profile.cookieStore()
            loop = QEventLoop()
            cookie_store.cookieRemoved.connect(loop.quit)
            cookie_store.deleteAllCookies()
            logging.debug("正在清空 cookies...")
            QTimer.singleShot(5000, loop.quit)
            loop.exec_()
            logging.debug("Cookies 已清空")
            self.default_profile.clearHttpCache()
            logging.debug("HTTP 缓存已清空")
            for i in range(self.tab_widget.count()):
                tab = self.tab_widget.widget(i)
                if tab and tab.view:
                    tab.view.page().runJavaScript("""
                        localStorage.clear();
                        sessionStorage.clear();
                        indexedDB.databases().then(dbs => {
                            dbs.forEach(db => indexedDB.deleteDatabase(db.name));
                        });
                    """, lambda result: logging.debug(f"标签页 {i + 1} Web Storage 清除结果: {result}"))
                    logging.debug(f"标签页 {i + 1} localStorage、sessionStorage 和 IndexedDB 已清空")
                    tab.view.reload()
                    logging.debug(f"刷新标签页 {i + 1}")
            QMessageBox.information(self, "清除浏览器数据", "已成功清除 cookies、缓存、localStorage、sessionStorage 和 IndexedDB，所有标签页已刷新。")
        except Exception as e:
            logging.error(f"清除浏览器数据失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"无法清除浏览器数据: {str(e)}")

    def set_user_agent(self):
        current_ua = self.default_profile.httpUserAgent()
        new_ua, ok = QInputDialog.getText(self, "设置 User-Agent", "请输入新的 User-Agent:", QLineEdit.Normal, current_ua)
        if ok and new_ua:
            try:
                self.default_profile.setHttpUserAgent(new_ua)
                QMessageBox.information(self, "User-Agent 设置", "User-Agent 已更新，请刷新页面。")
                logging.debug(f"设置 User-Agent: {new_ua}")
            except Exception as e:
                logging.error(f"设置 User-Agent 失败: {str(e)}")
                QMessageBox.warning(self, "错误", f"无法设置 User-Agent: {str(e)}")
        elif ok and not new_ua:
            QMessageBox.warning(self, "User-Agent 设置", "User-Agent 不能为空。")

    def set_socks5_proxy(self):
        proxy_host, ok_host = QInputDialog.getText(self, "设置 SOCKS5 代理", "请输入代理 IP 地址:")
        if not ok_host or not proxy_host:
            return
        proxy_port_str, ok_port = QInputDialog.getText(self, "设置 SOCKS5 代理", "请输入代理端口:")
        if not ok_port or not proxy_port_str:
            return
        try:
            proxy_port = int(proxy_port_str)
            if not (0 < proxy_port < 65536):
                raise ValueError("无效的端口号")
            proxy = QNetworkProxy()
            proxy.setType(QNetworkProxy.Socks5Proxy)
            proxy.setHostName(proxy_host)
            proxy.setPort(proxy_port)
            QNetworkProxy.setApplicationProxy(proxy)
            QMessageBox.information(self, "SOCKS5 代理设置", "SOCKS5 代理已设置，请刷新页面。")
            logging.debug(f"设置 SOCKS5 代理: {proxy_host}:{proxy_port}")
        except Exception as e:
            logging.error(f"设置 SOCKS5 代理失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"无法设置 SOCKS5 代理: {str(e)}")

    def closeEvent(self, event):
        logging.debug("关闭应用程序")
        event.accept()

if __name__ == "__main__":
    logging.debug("应用程序启动")
    try:
        app = QApplication(sys.argv)
        logging.debug("QApplication 初始化成功")
        window = SimpleBrowser()
        logging.debug("SimpleBrowser 窗口创建成功")
        window.show()
        logging.debug("窗口显示")
        sys.exit(app.exec_())
    except Exception as e:
        logging.critical(f"应用程序启动失败: {str(e)}")
        sys.exit(1)