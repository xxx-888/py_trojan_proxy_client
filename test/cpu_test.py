import time
import decimal
import multiprocessing
import psutil
import math
import subprocess
import sys


# 设置 decimal 模块的精度，数字越大，计算越精确，CPU 耗时越多
decimal.getcontext().prec = 20000

# 在模块顶层导入 pynvml (即 nvidia-ml-py)
try:
    import pynvml # 导入整个 pynvml 模块
    NVML_IMPORTED = True # 标记 pynvml 是否成功导入
except ImportError:
    NVML_IMPORTED = False

# --- GPU Stress Test Specific Imports ---
# 尝试导入 numba 及其 cuda 模块
try:
    from numba import cuda
    import numpy as np
    NUMBA_CUDA_IMPORTED = True # 标记 numba.cuda 是否成功导入
except ImportError:
    NUMBA_CUDA_IMPORTED = False
    print("警告: 未能导入 Numba 或 CUDA 模块。GPU 压力测试将不可用。请确保 'numba' 和 'numpy' 已安装，且 CUDA 环境已正确配置。")


# --- CPU 密集型任务函数 ---
def calculate_pi_chudnovsky():
    """
    使用 Chudnovsky 算法计算高精度圆周率。
    这是一个计算密集型的算法，适合测试CPU性能。
    """
    K = 6
    C = 426880 * decimal.Decimal(10005).sqrt()
    SUM = 0

    for k in range(K):
        term_M = (-1)**k * decimal.Decimal(math.factorial(6*k)) * (545140134*k + 13591409)
        term_L = decimal.Decimal(math.factorial(3*k)) * (decimal.Decimal(math.factorial(k))**3)
        term_X = decimal.Decimal((-262537412640768000)**k)

        SUM += term_M / (term_L * term_X)

    pi = C / SUM
    return pi

def cpu_intensive_pi_task():
    """
    一个高度消耗CPU的函数，通过重复计算圆周率来模拟负载。
    """
    while True:
        _ = calculate_pi_chudnovsky()


# --- Numba CUDA Kernel for GPU Stress (Matrix Multiplication) ---
@cuda.jit
def gpu_matrix_mul(A, B, C):
    """
    CUDA 核函数：执行矩阵乘法 C = A @ B。
    这是一个更密集的计算任务，有助于提高 GPU 利用率。
    假设 A 是 M x K, B 是 K x N, C 是 M x N
    """
    # 获取当前线程在网格中的全局位置
    row, col = cuda.grid(2) # 2D 网格

    if row < C.shape[0] and col < C.shape[1]:
        tmp = 0.
        for k in range(A.shape[1]): # K dimension
            tmp += A[row, k] * B[k, col]
        C[row, col] = tmp

def gpu_intensive_compute_task():
    """
    一个高度消耗GPU的函数，通过Numba和CUDA执行连续的矩阵乘法来模拟负载。
    """
    if not NUMBA_CUDA_IMPORTED:
        sys.stderr.write("GPU 压力测试进程：Numba 或 CUDA 模块未导入，无法执行 GPU 负载。\n")
        return


    # 定义矩阵维度
    # 对于 GTX 1050 Ti (4GB VRAM):
    # M x K * K x N = M x N
    # 假设方阵 K x K 乘 K x K = K x K
    # 每个 float32 元素 4 字节。三个 KxK 矩阵大概 3 * K*K*4 字节。
    # 4GB = 4 * 1024 * 1024 * 1024 字节
    # 如果 K=2048: 3 * 2048 * 2048 * 4 bytes = 3 * 4194304 * 4 bytes = ~48MB (太小)
    # 如果 K=8192: 3 * 8192 * 8192 * 4 bytes = 3 * 67108864 * 4 bytes = ~805MB
    # 如果 K=16384: 3 * 16384 * 16384 * 4 bytes = 3 * 268435456 * 4 bytes = ~3.2GB
    # 尝试一个比较大的 K 值，接近显存上限但不过载
    MATRIX_DIM = 10000 # 尝试 10000x10000 的矩阵

    try:
        M, K_dim, N = MATRIX_DIM, MATRIX_DIM, MATRIX_DIM
        # 使用 numpy 创建 host 上的数组
        A = np.random.rand(M, K_dim).astype(np.float32)
        B = np.random.rand(K_dim, N).astype(np.float32)
        C = np.empty((M, N), dtype=np.float32) # 结果矩阵

        # 将数据传输到 GPU
        d_A = cuda.to_device(A)
        d_B = cuda.to_device(B)
        d_C = cuda.to_device(C)

        # 配置 CUDA 核函数的执行网格 (2D Grid for 2D Matrix)
        threadsperblock = (16, 16) # 典型的 16x16 线程块
        # blockspergrid = (ceil(M/threadsperblock[0]), ceil(N/threadsperblock[1]))
        blockspergrid_x = math.ceil(C.shape[0] / threadsperblock[0])
        blockspergrid_y = math.ceil(C.shape[1] / threadsperblock[1])
        blockspergrid = (blockspergrid_x, blockspergrid_y)

        sys.stdout.write(f"GPU 压力测试进程：正在执行 {MATRIX_DIM}x{MATRIX_DIM} 矩阵乘法 CUDA 计算...\n")
        while True:
            # 持续调用 CUDA 核函数
            gpu_matrix_mul[blockspergrid, threadsperblock](d_A, d_B, d_C)
            # 移除 time.sleep() 以便持续最大化 GPU 负载
            # cuda.synchronize() # 可以在需要确保一个核函数完全完成后再启动下一个时使用
    except cuda.cudadrv.error.CUDAAPIError as e:
        sys.stderr.write(f"GPU 压力测试进程：CUDA API 错误 - {e}。请检查 CUDA 驱动和工具包安装。\n")
        if "out of memory" in str(e).lower():
            sys.stderr.write("提示: 可能是显存不足。尝试减小 MATRIX_DIM。\n")
    except Exception as e:
        sys.stderr.write(f"GPU 压力测试进程：发生未知错误 - {e}。请检查 Numba 和 CUDA 环境。\n")
    finally:
        sys.stdout.write("GPU 压力测试进程已停止。\n")


# --- 获取 CPU 频率的函数 (针对 Windows，使用 PowerShell) ---
def get_windows_cpu_frequency_powershell():
    """
    通过执行 PowerShell 命令获取 Windows CPU 实时频率。
    """
    powershell_command = '''
    $MaxClockSpeed = (Get-CimInstance CIM_Processor).MaxClockSpeed;
    (Get-Counter "\\Processor Information(_Total)\\% Processor Performance").CounterSamples.CookedValue | ForEach-Object { $MaxClockSpeed * ($_ / 100) }
    '''
    try:
        result = subprocess.run(['powershell.exe', '-Command', powershell_command],
                                capture_output=True, text=True, check=True,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                timeout=5)

        output_lines = result.stdout.strip().split('\n')
        for line in reversed(output_lines):
            line = line.strip()
            if line:
                try:
                    freq_mhz = float(line)
                    return freq_mhz
                except ValueError:
                    continue
        return None

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"\nPowerShell 命令执行失败 (错误码: {e.returncode}): {e.stderr.strip()}\n")
    except subprocess.TimeoutExpired:
        sys.stderr.write("\nPowerShell 命令执行超时。\n")
    except Exception as e:
        sys.stderr.write(f"\n获取CPU频率时发生未知错误: {e}\n")
    return None

# 用于 NVML 状态的全局变量
_nvml_handle = None
_nvml_available = False
_gpu_count = 0
_gpu_name = "N/A" # 存储 GPU 名称

def init_nvml():
    """
    初始化 NVML 库，并获取 GPU 句柄和名称。只执行一次。
    """
    global _nvml_handle, _nvml_available, _gpu_count, _gpu_name

    # 如果 pynvml 没有成功导入，则直接返回 False
    if not NVML_IMPORTED:
        sys.stdout.write("GPU 监控功能将不可用。请确保已安装 'nvidia-ml-py' (pip install nvidia-ml-py) 且有 NVIDIA 显卡。\n")
        return False

    if _nvml_available: # 如果已经初始化，则不再重复
        return True

    try:
        pynvml.nvmlInit()
        _gpu_count = pynvml.nvmlDeviceGetCount()
        if _gpu_count > 0:
            _nvml_handle = pynvml.nvmlDeviceGetHandleByIndex(0) # 获取第一个 GPU 的句柄 (索引 0)
            _gpu_name = pynvml.nvmlDeviceGetName(_nvml_handle) # 获取 GPU 名称
            _nvml_available = True
            sys.stdout.write(f"检测到 {_gpu_count} 块 NVIDIA GPU: {_gpu_name}。\n") # 只在此处打印一次
            return True
        else:
            sys.stdout.write("未检测到 NVIDIA GPU，或 NVML 初始化失败。\n")
            pynvml.nvmlShutdown()
            return False
    except pynvml.NVMLError as e:
        sys.stderr.write(f"NVML 初始化失败: {e}\n")
        sys.stdout.write("GPU 监控功能将不可用。请确保 NVIDIA 驱动已正确安装。\n")
        return False
    except Exception as e:
        sys.stderr.write(f"初始化 NVIDIA GPU 监控时发生未知错误: {e}\n")
        return False

def shutdown_nvml():
    """
    关闭 NVML 库。
    """
    global _nvml_available
    if _nvml_available and NVML_IMPORTED:
        try:
            pynvml.nvmlShutdown()
            _nvml_available = False # 重置状态
        except Exception as e:
            sys.stderr.write(f"\n关闭 NVML 失败: {e}\n")

def get_nvidia_gpu_usage():
    """
    获取 NVIDIA GPU 核心利用率和显存使用率。
    返回一个字典，包含每个指标的值或错误信息。
    """
    stats = {
        'gpu_percent': "未获取到",
        'used_vram_mb': "未获取到",
        'total_vram_mb': "未获取到",
        'vram_percent': "未获取到",
    }

    if not _nvml_available or _nvml_handle is None:
        return stats # 返回包含“未获取到”的字典

    # 尝试获取每个指标，并独立捕获错误
    try:
        utilization = pynvml.nvmlDeviceGetUtilizationRates(_nvml_handle)
        stats['gpu_percent'] = utilization.gpu
    except pynvml.NVMLError:
        stats['gpu_percent'] = "未获取到"
    except Exception:
        stats['gpu_percent'] = "错误"

    try:
        memory = pynvml.nvmlDeviceGetMemoryInfo(_nvml_handle)
        stats['total_vram_mb'] = memory.total / (1024**2)
        stats['used_vram_mb'] = memory.used / (1024**2)
        stats['vram_percent'] = (stats['used_vram_mb'] / stats['total_vram_mb']) * 100 if stats['total_vram_mb'] > 0 else 0
    except pynvml.NVMLError:
        stats['used_vram_mb'] = "未获取到"
        stats['total_vram_mb'] = "未获取到"
        stats['vram_percent'] = "未获取到"
    except Exception:
        stats['used_vram_mb'] = "错误"
        stats['total_vram_mb'] = "错误"
        stats['vram_percent'] = "错误"

    return stats


def get_windows_cpu_name_wmi():
    """
    通过执行 WMIC 命令获取 Windows CPU 的产品名称。
    """
    try:
        result = subprocess.run(['wmic', 'cpu', 'get', 'name', '/value'],
                                capture_output=True, text=True, check=True,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                timeout=5)
        output = result.stdout.strip()
        for line in output.split('\n'):
            if line.startswith('Name='):
                return line.split('=', 1)[1].strip()
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"\nWMIC 命令执行失败 (错误码: {e.returncode}): {e.stderr.strip()}\n")
    except subprocess.TimeoutExpired:
        sys.stderr.write("\nWMIC 命令执行超时。\n")
    except Exception as e:
        sys.stderr.write(f"\n获取CPU名称时发生未知错误: {e}\n")
    return None


def monitor_system_stats():
    """
    定期监控并打印CPU频率、内存占用和GPU统计信息，并在一行动态更新。
    """
    # 在监控进程内部初始化 NVML，确保只执行一次
    gpu_monitor_enabled = init_nvml() # 存储 GPU 监控是否激活

    # 一次性获取 CPU 名称
    cpu_name = get_windows_cpu_name_wmi() or "Unknown CPU"

    sys.stdout.write("\n--- 系统性能实时监测 ---\n")
    sys.stdout.write(f"CPU: {cpu_name}\n")
    if gpu_monitor_enabled:
        sys.stdout.write(f"GPU: {_gpu_name}\n") # 使用全局变量 _gpu_name
    sys.stdout.write("CPU 频率、内存和 GPU 统计信息将在下方动态更新。\n")
    sys.stdout.write("-----------------------------------------------\n")

    max_line_length = 0

    try:
        while True:
            # 获取 CPU 频率
            cpu_freq_mhz = None
            if psutil.WINDOWS:
                cpu_freq_mhz = get_windows_cpu_frequency_powershell()
            if cpu_freq_mhz is None:
                try:
                    psutil_freq = psutil.cpu_freq()
                    if psutil_freq:
                        cpu_freq_mhz = psutil_freq.current
                except Exception:
                    pass

            # 获取内存占用
            mem_info = psutil.virtual_memory()
            total_mem_gb = mem_info.total / (1024**3)
            used_mem_gb = mem_info.used / (1024**3)
            used_mem_percent = mem_info.percent

            # 获取 GPU 统计信息
            gpu_stats = {}
            if gpu_monitor_enabled:
                gpu_stats = get_nvidia_gpu_usage()

            # 构建要打印的字符串
            freq_str = f"{cpu_freq_mhz / 1000:.2f} GHz" if cpu_freq_mhz is not None else "N/A"
            mem_str = f"内存: {used_mem_gb:.2f}/{total_mem_gb:.2f}GB ({used_mem_percent:.1f}%)"

            gpu_status_str = "GPU: 未启用/未检测到"
            if gpu_monitor_enabled:
                # 显卡占用
                gpu_percent_str = f"占用 {gpu_stats['gpu_percent']:.1f}%" if isinstance(gpu_stats['gpu_percent'], (int, float)) else f"占用 {str(gpu_stats['gpu_percent'])}"

                # 显存
                if isinstance(gpu_stats['used_vram_mb'], (int, float)) and isinstance(gpu_stats['total_vram_mb'], (int, float)):
                    vram_str = f"显存: {gpu_stats['used_vram_mb']:.0f}/{gpu_stats['total_vram_mb']:.0f}MB ({gpu_stats['vram_percent']:.1f}%)"
                else:
                    vram_str = f"显存: {gpu_stats['used_vram_mb']}/{gpu_stats['total_vram_mb']} ({gpu_stats['vram_percent']})"

                # 组合字符串
                gpu_status_str = f"GPU: {gpu_percent_str} | {vram_str}"

            output_line = f"CPU 频率: {freq_str} | {mem_str} | {gpu_status_str}"

            sys.stdout.write(' ' * max_line_length + '\r')
            sys.stdout.write(output_line + '\r')
            sys.stdout.flush()

            max_line_length = max(max_line_length, len(output_line))

            time.sleep(1)
    except KeyboardInterrupt:
        sys.stdout.write(' ' * max_line_length + '\r')
        sys.stdout.write("停止系统性能监测。\n")
        sys.stdout.flush()
    finally:
        shutdown_nvml()

def run_stress_test(num_cores):
    """
    创建与CPU逻辑核心数相同的进程来施加负载。
    同时启动一个 GPU 压力测试进程。
    """
    print(f"正在启动 {num_cores} 个CPU密集型进程...")
    processes = []
    # for i in range(num_cores):
    #     p = multiprocessing.Process(target=cpu_intensive_pi_task, name=f"PI_CPU_Core_{i}")
    #     processes.append(p)
    #     p.start()

    # 启动一个独立的进程来施加 GPU 负载
    gpu_stress_process = None
    # if NVML_IMPORTED and NUMBA_CUDA_IMPORTED: # 只有当 pynvml 和 numba.cuda 都成功导入时才尝试启动 GPU 压力测试
    #     print("正在启动 GPU 压力测试进程...")
    #     gpu_stress_process = multiprocessing.Process(target=gpu_intensive_compute_task, name="GPU_Stress")
    #     gpu_stress_process.start()
    # else:
    #     print("未检测到 NVIDIA 显卡或 CUDA/Numba 环境不完整，跳过 GPU 压力测试。")


    # 启动一个独立的进程来监控系统性能
    monitor_process = multiprocessing.Process(target=monitor_system_stats, name="System_Monitor")
    monitor_process.start()

    print("\n进程已启动，CPU和/或GPU将处于高负载状态。")
    print("按 Enter 键停止所有进程...")
    input()

    # 停止所有子进程
    monitor_process.terminate()
    monitor_process.join()
    if gpu_stress_process: # 如果 GPU 压力测试进程启动了，也终止它
        gpu_stress_process.terminate()
        gpu_stress_process.join()
    for p in processes:
        p.terminate()
        p.join()

    print("所有进程已停止。")

if __name__ == "__main__":
    num_logical_cores = multiprocessing.cpu_count()
    print(f"您的CPU有 {num_logical_cores} 个逻辑核心。")
    run_stress_test(num_logical_cores)