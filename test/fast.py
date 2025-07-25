from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Header
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
import os
import subprocess
import uvicorn
import string
import mimetypes
from typing import Dict, Optional

app = FastAPI()

# 默认账号和密码
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password123"

# 模拟会话存储（简单实现，生产环境建议使用数据库或Redis）
sessions: Dict[str, bool] = {}

# 获取所有可用盘符
def get_available_drives():
    return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]

# 文件编辑请求模型
class FileEditRequest(BaseModel):
    path: str
    content: str

# 命令执行请求模型
class CommandRequest(BaseModel):
    command: str

# 登录请求模型
class LoginRequest(BaseModel):
    username: str
    password: str

# 前端HTML页面（包含登录页面和主界面）
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件共享服务</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-4 max-w-4xl">
        <!-- 登录页面 -->
        <div id="loginPage" class="hidden">
            <h1 class="text-2xl font-bold mb-4">登录</h1>
            <div class="mb-4">
                <label class="block text-sm font-medium mb-1">用户名</label>
                <input id="username" type="text" placeholder="输入用户名" 
                       class="w-full p-2 border rounded">
            </div>
            <div class="mb-4">
                <label class="block text-sm font-medium mb-1">密码</label>
                <input id="password" type="password" placeholder="输入密码" 
                       class="w-full p-2 border rounded">
            </div>
            <button onclick="login()" 
                    class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                登录
            </button>
            <p id="loginError" class="text-red-500 mt-2 hidden"></p>
        </div>

        <!-- 主界面 -->
        <div id="mainPage" class="hidden">
            <h1 class="text-2xl font-bold mb-4">文件共享服务</h1>
            
            <!-- 文件浏览 -->
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">文件浏览</h2>
                <div class="flex items-center mb-2">
                    <button onclick="goBack()" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600 mr-2">后退</button>
                    <select id="driveSelect" onchange="changeDrive()" class="p-2 border rounded mr-2">
                        <option value="">选择盘符</option>
                    </select>
                    <input id="pathInput" type="text" placeholder="输入路径" 
                           class="flex-1 p-2 border rounded" value="C:/">
                    <button onclick="listFiles()" 
                            class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 ml-2">
                        浏览
                    </button>
                </div>
                <div id="fileList" class="mt-2"></div>
                <div id="fileContent" class="mt-2">
                    <textarea id="fileText" class="w-full h-40 p-2 border rounded hidden" 
                              placeholder="文件内容"></textarea>
                    <div id="fileActions" class="mt-2 hidden">
                        <button onclick="saveFile()" 
                                class="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600">
                            保存文件
                        </button>
                        <button onclick="deleteFile()" 
                                class="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600 ml-2">
                            删除文件
                        </button>
                    </div>
                </div>
                <div class="mt-2">
                    <input id="fileUpload" type="file" class="p-2 border rounded">
                    <button onclick="uploadFile()" 
                            class="bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600 mt-2">
                        上传文件
                    </button>
                </div>
            </div>

            <!-- 命令执行 -->
            <div>
                <h2 class="text-xl font-semibold mb-2">命令执行</h2>
                <input id="commandInput" type="text" placeholder="输入命令（如 dir C:\\）" 
                       class="w-full p-2 border rounded mb-2">
                <button onclick="executeCommand()" 
                        class="bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600">
                    执行
                </button>
                <pre id="commandOutput" class="mt-2 p-2 bg-gray-800 text-white rounded whitespace-pre-wrap break-words"></pre>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = "";
        let historyStack = [];

        // 检查登录状态
        function checkLogin() {
            const token = localStorage.getItem("authToken");
            if (token) {
                document.getElementById("loginPage").classList.add("hidden");
                document.getElementById("mainPage").classList.remove("hidden");
                initDrives();
            } else {
                document.getElementById("loginPage").classList.remove("hidden");
                document.getElementById("mainPage").classList.add("hidden");
            }
        }

        // 登录
        async function login() {
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            try {
                const response = await fetch(`${API_BASE}/login`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password })
                });
                if (!response.ok) {
                    const error = await response.json();
                    document.getElementById("loginError").innerText = `错误: ${error.detail}`;
                    document.getElementById("loginError").classList.remove("hidden");
                    return;
                }
                const data = await response.json();
                localStorage.setItem("authToken", data.token);
                checkLogin();
            } catch (error) {
                document.getElementById("loginError").innerText = `登录失败: ${error.message}`;
                document.getElementById("loginError").classList.remove("hidden");
            }
        }

        // 获取请求头
        function getHeaders() {
            const token = localStorage.getItem("authToken");
            return token ? { "Authorization": `Bearer ${token}` } : {};
        }

        // 初始化盘符列表
        async function initDrives() {
            try {
                const response = await fetch(`${API_BASE}/drives`, {
                    headers: getHeaders()
                });
                if (response.status === 401) {
                    localStorage.removeItem("authToken");
                    checkLogin();
                    return;
                }
                if (!response.ok) throw new Error("无法获取盘符列表");
                const drives = await response.json();
                const select = document.getElementById("driveSelect");
                drives.forEach(drive => {
                    const option = document.createElement("option");
                    option.value = drive;
                    option.text = drive;
                    select.appendChild(option);
                });
            } catch (error) {
                alert(`初始化盘符失败: ${error.message}`);
            }
        }

        // 列出文件和目录
        async function listFiles() {
            const path = document.getElementById("pathInput").value;
            try {
                const response = await fetch(`${API_BASE}/files/${encodeURIComponent(path)}`, {
                    headers: getHeaders()
                });
                if (response.status === 401) {
                    localStorage.removeItem("authToken");
                    checkLogin();
                    return;
                }
                if (!response.ok) {
                    const error = await response.json();
                    alert(`错误: ${error.detail}`);
                    return;
                }
                const contentType = response.headers.get("content-type");
                if (contentType.includes("application/json")) {
                    const data = await response.json();
                    const fileList = document.getElementById("fileList");
                    fileList.innerHTML = data.files.map(file => 
                        `<div class="flex justify-between">
                            <span class="cursor-pointer text-blue-500 hover:underline" 
                                  onclick="openPath('${path.replace(/\\\\/g, '/')}/${file}')">${file}</span>
                            <a href="${API_BASE}/files/${encodeURIComponent(path.replace(/\\\\/g, '/') + '/' + file)}?token=${encodeURIComponent(localStorage.getItem("authToken") || '')}" 
                               download="${file}" 
                               class="text-green-500 hover:underline">下载</a>
                        </div>`
                    ).join("");
                    document.getElementById("fileText").classList.add("hidden");
                    document.getElementById("fileActions").classList.add("hidden");
                    historyStack.push(path);
                } else {
                    const text = await response.text();
                    document.getElementById("fileText").value = text;
                    document.getElementById("fileText").classList.remove("hidden");
                    document.getElementById("fileActions").classList.remove("hidden");
                    document.getElementById("fileList").innerHTML = "";
                }
            } catch (error) {
                alert(`请求失败: ${error.message}`);
            }
        }

        // 打开路径
        async function openPath(path) {
            document.getElementById("pathInput").value = path;
            await listFiles();
        }

        // 后退导航
        function goBack() {
            historyStack.pop();
            const prevPath = historyStack.length > 0 ? historyStack[historyStack.length - 1] : "C:/";
            document.getElementById("pathInput").value = prevPath;
            listFiles();
        }

        // 切换盘符
        function changeDrive() {
            const drive = document.getElementById("driveSelect").value;
            if (drive) {
                document.getElementById("pathInput").value = drive;
                listFiles();
            }
        }

        // 保存文件
        async function saveFile() {
            const path = document.getElementById("pathInput").value;
            const content = document.getElementById("fileText").value;
            try {
                const response = await fetch(`${API_BASE}/files/${encodeURIComponent(path)}`, {
                    method: "POST",
                    headers: { 
                        "Content-Type": "application/json",
                        ...getHeaders()
                    },
                    body: JSON.stringify({ path, content })
                });
                if (response.status === 401) {
                    localStorage.removeItem("authToken");
                    checkLogin();
                    return;
                }
                if (!response.ok) {
                    const error = await response.json();
                    alert(`错误: ${error.detail}`);
                    return;
                }
                const data = await response.json();
                alert(data.message);
            } catch (error) {
                alert(`保存失败: ${error.message}`);
            }
        }

        // 删除文件
        async function deleteFile() {
            const path = document.getElementById("pathInput").value;
            try {
                const response = await fetch(`${API_BASE}/files/${encodeURIComponent(path)}`, {
                    method: "DELETE",
                    headers: getHeaders()
                });
                if (response.status === 401) {
                    localStorage.removeItem("authToken");
                    checkLogin();
                    return;
                }
                if (!response.ok) {
                    const error = await response.json();
                    alert(`错误: ${error.detail}`);
                    return;
                }
                const data = await response.json();
                alert(data.message);
                document.getElementById("fileText").classList.add("hidden");
                document.getElementById("fileActions").classList.add("hidden");
                document.getElementById("pathInput").value = path.substring(0, path.lastIndexOf("/"));
                listFiles();
            } catch (error) {
                alert(`删除失败: ${error.message}`);
            }
        }

        // 上传文件
        async function uploadFile() {
            const fileInput = document.getElementById("fileUpload");
            const path = document.getElementById("pathInput").value;
            if (!fileInput.files.length) {
                alert("请选择一个文件");
                return;
            }
            const file = fileInput.files[0];
            const formData = new FormData();
            formData.append("file", file);
            try {
                const response = await fetch(`${API_BASE}/upload/${encodeURIComponent(path)}`, {
                    method: "POST",
                    headers: getHeaders(),
                    body: formData
                });
                if (response.status === 401) {
                    localStorage.removeItem("authToken");
                    checkLogin();
                    return;
                }
                if (!response.ok) {
                    const error = await response.json();
                    alert(`错误: ${error.detail}`);
                    return;
                }
                const data = await response.json();
                alert(data.message);
                listFiles();
            } catch (error) {
                alert(`上传失败: ${error.message}`);
            }
        }

        // 执行命令
        async function executeCommand() {
            const command = document.getElementById("commandInput").value;
            try {
                const response = await fetch(`${API_BASE}/execute`, {
                    method: "POST",
                    headers: { 
                        "Content-Type": "application/json",
                        ...getHeaders()
                    },
                    body: JSON.stringify({ command })
                });
                if (response.status === 401) {
                    localStorage.removeItem("authToken");
                    checkLogin();
                    return;
                }
                if (!response.ok) {
                    const error = await response.json();
                    alert(`错误: ${error.detail}`);
                    return;
                }
                const data = await response.json();
                document.getElementById("commandOutput").innerText = 
                    `输出:\\n${data.stdout}\\n错误:\\n${data.stderr}\\n返回码: ${data.returncode}`;
            } catch (error) {
                alert(`命令执行失败: ${error.message}`);
            }
        }

        // 初始化页面，检查登录状态
        window.onload = checkLogin;
    </script>
</body>
</html>
"""

# 验证会话令牌
async def verify_token(authorization: Optional[str] = Header(None)):
    # 简单令牌验证，生产环境建议使用更安全的机制
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="无效的授权头")
    token = authorization.replace("Bearer ", "")
    if token not in sessions or not sessions[token]:
        raise HTTPException(status_code=401, detail="无效或过期的会话")
    return token

@app.get("/")
async def serve_index():
    # 提供网页界面（登录页面或主界面）
    return HTMLResponse(content=HTML_CONTENT)

@app.post("/login")
async def login(request: LoginRequest):
    # 处理用户登录请求
    if request.username == DEFAULT_USERNAME and request.password == DEFAULT_PASSWORD:
        # 生成简单令牌（生产环境建议使用JWT）
        token = f"token_{request.username}_{os.urandom(8).hex()}"
        sessions[token] = True
        return {"token": token}
    raise HTTPException(status_code=401, detail="用户名或密码错误")

@app.get("/drives", dependencies=[Depends(verify_token)])
async def list_drives():
    # 获取并返回所有可用盘符
    return get_available_drives()

@app.get("/files/{path:path}")
async def read_file(path: str, token: Optional[str] = None):
    # 读取文件或列出目录内容
    
    file_path = os.path.abspath(path.replace("/", "\\"))
    drives = get_available_drives()
    if not any(file_path.startswith(drive) for drive in drives):
        raise HTTPException(status_code=403, detail="访问被拒绝：路径不在可用盘符中")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件或目录不存在")
    if os.path.isdir(file_path):
        try:
            return {"files": os.listdir(file_path)}
        except PermissionError:
            raise HTTPException(status_code=403, detail="权限不足")
    try:
        mime_type, _ = mimetypes.guess_type(file_path)
        return FileResponse(file_path, media_type=mime_type or "application/octet-stream")
    except PermissionError:
        raise HTTPException(status_code=403, detail="权限不足")

@app.post("/files/{path:path}", dependencies=[Depends(verify_token)])
async def write_file(path: str, request: FileEditRequest):
    # 编辑或创建文本文件
    file_path = os.path.abspath(path.replace("/", "\\"))
    drives = get_available_drives()
    if not any(file_path.startswith(drive) for drive in drives):
        raise HTTPException(status_code=403, detail="访问被拒绝：路径不在可用盘符中")
    if not os.path.exists(os.path.dirname(file_path)):
        raise HTTPException(status_code=400, detail="目录不存在")
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(request.content)
        return {"message": "文件更新成功"}
    except PermissionError:
        raise HTTPException(status_code=403, detail="权限不足")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/files/{path:path}", dependencies=[Depends(verify_token)])
async def delete_file(path: str):
    # 删除指定文件
    file_path = os.path.abspath(path.replace("/", "\\"))
    drives = get_available_drives()
    if not any(file_path.startswith(drive) for drive in drives):
        raise HTTPException(status_code=403, detail="访问被拒绝：路径不在可用盘符中")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件不存在")
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
        else:
            raise HTTPException(status_code=400, detail="无法删除目录")
        return {"message": "文件删除成功"}
    except PermissionError:
        raise HTTPException(status_code=403, detail="权限不足")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload/{path:path}", dependencies=[Depends(verify_token)])
async def upload_file(path: str, file: UploadFile = File(...)):
    # 上传文件到指定目录
    file_path = os.path.abspath(os.path.join(path.replace("/", "\\"), file.filename))
    drives = get_available_drives()
    if not any(file_path.startswith(drive) for drive in drives):
        raise HTTPException(status_code=403, detail="访问被拒绝：路径不在可用盘符中")
    if not os.path.exists(os.path.dirname(file_path)):
        raise HTTPException(status_code=400, detail="目录不存在")
    try:
        with open(file_path, "wb") as f:
            f.write(await file.read())
        return {"message": "文件上传成功"}
    except PermissionError:
        raise HTTPException(status_code=403, detail="权限不足")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/execute", dependencies=[Depends(verify_token)])
async def execute_command(request: CommandRequest):
    # 执行系统命令并返回结果
    try:
        result = subprocess.run(
            request.command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",  # 使用UTF-8编码
            errors="replace",  # 替换无法解码的字符
            timeout=30
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="命令执行超时")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)