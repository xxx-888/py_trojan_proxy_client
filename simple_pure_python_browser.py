import sys
import logging
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QAction, QVBoxLayout, QWidget, QLineEdit,
    QTabWidget, QToolBar, QStatusBar, QInputDialog, QTextEdit, QMessageBox,
    QPushButton, QFileDialog, QMenu, QTabBar
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile
from PyQt5.QtNetwork import QNetworkProxy
from PyQt5.QtCore import QUrl, Qt
import webbrowser
from browserforge.headers import HeaderGenerator
import re

# 配置日志记录，输出到控制台和文件
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('browser.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# 自定义 WebEnginePage，用于处理导航请求
class WebEnginePage(QWebEnginePage):
    def __init__(self, view, profile):
        super().__init__(profile, view)
        self._view = view
        logging.debug("初始化 WebEnginePage")

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        # 处理导航请求，决定是否在应用内打开链接
        logging.debug(f"导航请求: {url.toString()}, 类型: {nav_type}, 主框架: {is_main_frame}")
        if nav_type == QWebEnginePage.NavigationTypeLinkClicked and is_main_frame:
            current_url = self._view.url().toString()
            if any(domain in current_url for domain in ["google.com", "bing.com"]):
                return True
            webbrowser.open(url.toString())
            return False
        return True

# 浏览器标签页的 Widget
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
        # 设置当前标签页的 URL
        try:
            if not url_string:
                url_string = "https://example.com"
            if not url_string.startswith(('http://', 'https://')):
                url_string = f"https://{url_string}"
            self.view.setUrl(QUrl(url_string))
            logging.debug(f"设置 URL: {url_string}")
        except Exception as e:
            logging.error(f"设置 URL {url_string} 失败: {str(e)}")

    def get_url(self):
        # 获取当前标签页的 URL
        return self.view.url().toString()

# 主浏览器窗口
class SimpleBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        logging.debug("开始初始化 SimpleBrowser")
        try:
            # 设置窗口标题和大小
            self.setWindowTitle("多标签 PyQt 浏览器")
            self.setGeometry(100, 100, 1600, 900)

            # 初始化自定义 WebEngineProfile
            self.default_profile = QWebEngineProfile("CustomProfile", self)
            self.update_request_headers()  # 设置初始请求头
            logging.debug("获取 WebEngineProfile 成功")

            # 创建主布局
            self.central_widget = QWidget(self)
            self.layout = QVBoxLayout(self.central_widget)
            self.setCentralWidget(self.central_widget)

            # 添加工具栏
            self.toolbar = QToolBar("导航工具栏", self)
            self.addToolBar(self.toolbar)

            # 添加导航按钮
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

            # 地址栏
            self.url_bar = QLineEdit(self)
            self.url_bar.returnPressed.connect(self.load_url)
            self.toolbar.addWidget(self.url_bar)

            # 添加标签页控件
            self.tab_widget = QTabWidget(self)
            self.tab_widget.setTabsClosable(True)
            self.tab_widget.tabCloseRequested.connect(self.close_tab)
            self.tab_widget.currentChanged.connect(self.update_ui_for_current_tab)
            self.layout.addWidget(self.tab_widget)

            # 添加“新增标签页”按钮到工具栏
            self.new_tab_action = QAction(QIcon(), "➕", self)
            self.new_tab_action.setToolTip("新建标签页")
            self.new_tab_action.triggered.connect(self.add_new_tab)
            self.toolbar.addAction(self.new_tab_action)

            # 创建状态栏
            self.status_bar = QStatusBar(self)
            self.setStatusBar(self.status_bar)

            # 创建菜单栏
            menubar = self.menuBar()
            file_menu = menubar.addMenu("文件")
            view_menu = menubar.addMenu("视图")
            settings_menu = menubar.addMenu("设置")

            # 文件菜单动作
            new_tab_action_menu = QAction("新建标签页", self)
            new_tab_action_menu.setShortcut("Ctrl+T")
            new_tab_action_menu.triggered.connect(self.add_new_tab)
            file_menu.addAction(new_tab_action_menu)

            exit_action = QAction("退出", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

            # 视图菜单动作
            dev_tools_action = QAction("开发者工具", self)
            dev_tools_action.setShortcut("F12")
            dev_tools_action.triggered.connect(self.toggle_dev_tools)
            view_menu.addAction(dev_tools_action)

            view_source_action = QAction("查看页面源代码", self)
            view_source_action.setShortcut("Ctrl+U")
            view_source_action.triggered.connect(self.view_page_source)
            view_menu.addAction(view_source_action)

            # 设置菜单动作
            set_ua_action = QAction("设置 User-Agent", self)
            set_ua_action.triggered.connect(self.set_user_agent)
            settings_menu.addAction(set_ua_action)

            set_proxy_action = QAction("设置 SOCKS5 代理", self)
            set_proxy_action.triggered.connect(self.set_socks5_proxy)
            settings_menu.addAction(set_proxy_action)

            # 创建初始标签页
            self.add_new_tab(QUrl("https://example.com"))
            logging.debug("SimpleBrowser 初始化完成")
        except Exception as e:
            logging.error(f"初始化 SimpleBrowser 失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"无法初始化浏览器: {str(e)}")
            sys.exit(1)

    def update_request_headers(self):
        # 使用 browserforge 生成 User-Agent 并设置
        try:
            header_gen = HeaderGenerator()
            headers = header_gen.generate()
            user_agent = headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36')
            self.default_profile.setHttpUserAgent(user_agent)
            logging.debug(f"设置 User-Agent: {user_agent}")
        except Exception as e:
            logging.error(f"设置 User-Agent 失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"无法设置 User-Agent: {str(e)}")

    def current_tab(self):
        # 返回当前选中的浏览器标签页
        return self.tab_widget.currentWidget()

    def add_new_tab(self, url=None):
        # 添加一个新的浏览器标签页
        try:
            tab = BrowserTab(self, profile=self.default_profile)
            if url:
                tab.set_url(url.toString())
            else:
                tab.set_url("https://example.com")

            index = self.tab_widget.addTab(tab, f"标签页 {self.tab_widget.count() + 1}")
            self.tab_widget.setCurrentIndex(index)

            # 连接新标签页的信号
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
        # 关闭指定索引的标签页
        if self.tab_widget.count() < 2:
            QMessageBox.information(self, "提示", "无法关闭最后一个标签页。")
            return
        self.tab_widget.removeTab(index)
        self.update_ui_for_current_tab()

    def load_url(self):
        # 从地址栏加载 URL
        if self.current_tab():
            self.current_tab().set_url(self.url_bar.text())

    def update_url_bar(self, url=None):
        # 更新地址栏显示当前标签页的 URL
        if self.current_tab():
            display_url = url.toString() if url else self.current_tab().get_url()
            self.url_bar.setText(display_url)
            self.url_bar.setCursorPosition(0)

    def update_load_progress(self, progress):
        # 更新状态栏的加载进度
        if self.current_tab():
            if progress < 100:
                self.status_bar.showMessage(f"加载中... {progress}%")
            else:
                self.status_bar.showMessage("加载完成", 2000)

    def update_ui_for_current_tab(self):
        # 当当前标签页改变时，更新 UI（地址栏、按钮状态等）
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
        # 处理链接悬停事件，在状态栏显示链接 URL
        self.status_bar.showMessage(url)
        logging.debug(f"悬停链接: {url}")

    def context_menu(self, pos):
        # 自定义右键菜单
        if not self.current_tab():
            return
        menu = QMenu(self)
        view_source_action = menu.addAction("查看网页源代码")
        save_page_action = menu.addAction("保存网页")
        view_source_action.triggered.connect(self.view_page_source)
        save_page_action.triggered.connect(self.save_page)
        menu.exec_(self.current_tab().view.mapToGlobal(pos))

    def go_back(self):
        # 返回上一页
        if self.current_tab():
            self.current_tab().view.back()

    def go_forward(self):
        # 前进到下一页
        if self.current_tab():
            self.current_tab().view.forward()

    def reload_current_page(self):
        # 重新加载当前标签页
        if self.current_tab():
            self.current_tab().view.reload()
            logging.debug("刷新当前页面")

    def view_page_source(self):
        # 查看当前页面的 HTML 源代码
        if self.current_tab():
            self.current_tab().view.page().toHtml(self._display_page_source)
        else:
            QMessageBox.warning(self, "警告", "没有可用的页面来查看源代码。")

    def _display_page_source(self, html_content):
        # 显示获取到的 HTML 源代码，带简单语法高亮
        source_window = QMainWindow(self)
        source_window.setWindowTitle("页面源代码")
        source_window.setGeometry(150, 150, 1600, 900)
        text_edit = QTextEdit(source_window)
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier New", 10))

        # 应用简单 HTML 语法高亮
        cursor = text_edit.textCursor()
        text_edit.setPlainText(html_content)
        cursor.select(QTextCursor.Document)
        default_format = QTextCharFormat()
        default_format.setForeground(QColor("black"))
        cursor.setCharFormat(default_format)

        # 定义高亮规则
        tag_format = QTextCharFormat()
        tag_format.setForeground(QColor("blue"))
        attribute_format = QTextCharFormat()
        attribute_format.setForeground(QColor("purple"))
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("green"))
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("gray"))

        # 高亮 HTML 标签
        for match in re.finditer(r'<[^>]+>', html_content):
            cursor.setPosition(match.start())
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, match.end() - match.start())
            cursor.setCharFormat(tag_format)

        # 高亮属性
        for match in re.finditer(r'\b\w+\s*=\s*"[^"]*"', html_content):
            cursor.setPosition(match.start())
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, match.end() - match.start())
            cursor.setCharFormat(attribute_format)

        # 高亮字符串
        for match in re.finditer(r'"[^"]*"', html_content):
            cursor.setPosition(match.start())
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, match.end() - match.start())
            cursor.setCharFormat(string_format)

        # 高亮注释
        for match in re.finditer(r'<!--[\s\S]*?-->', html_content):
            cursor.setPosition(match.start())
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, match.end() - match.start())
            cursor.setCharFormat(comment_format)

        source_window.setCentralWidget(text_edit)
        source_window.show()
        logging.debug("显示页面源代码")

    def save_page(self):
        # 保存当前页面为 HTML 文件
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
        # 使用 setDevToolsPage 打开开发者工具
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

            # 创建开发者工具页面和视图
            dev_tools_page = QWebEnginePage(self.default_profile, self)
            dev_tools_view = QWebEngineView(self)
            dev_tools_view.setPage(dev_tools_page)

            # 使用 setDevToolsPage 关联开发者工具页面
            current_page.setDevToolsPage(dev_tools_page)

            # 显示开发者工具窗口
            dev_tools_window = QMainWindow(self)
            dev_tools_window.setCentralWidget(dev_tools_view)
            dev_tools_window.setWindowTitle("开发者工具")
            dev_tools_window.setGeometry(self.x() + 50, self.y() + 50, 1600, 900)
            dev_tools_window.show()
            logging.debug("开发者工具打开成功")
        except Exception as e:
            logging.error(f"打开开发者工具失败: {str(e)}")
            QMessageBox.warning(self, "警告", f"无法打开开发者工具: {str(e)}")

    def set_user_agent(self):
        # 设置浏览器的 User-Agent
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
        # 设置 SOCKS5 代理 IP 和端口
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
        # 重写关闭事件，确保应用程序正常退出
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