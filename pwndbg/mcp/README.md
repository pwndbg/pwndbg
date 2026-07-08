# pwndbg MCP Server

AI Agent 接口，用于通过 Model Context Protocol 访问 pwndbg 的动态调试功能。

## 功能特性

- **寄存器状态查询**: 获取当前 CPU 寄存器状态
- **内存检查**: 读取和显示内存内容（十六进制和 ASCII）
- **堆分析**: 分析堆状态和内存块
- **栈分析**: 查看栈帧和调用栈
- **断点管理**: 添加、删除、列出断点
- **执行控制**: 继续执行、单步执行
- **符号搜索**: 搜索内存中的模式
- **命令执行**: 执行任意 pwndbg/GDB 命令

## 工具列表

### 1. `execute_command`
执行 pwndbg/GDB 命令并返回输出。

```python
result = execute_command(command="vmmap")
```

### 2. `get_registers`
获取当前 CPU 寄存器状态。

```python
result = get_registers()
# 返回: {"registers": {"rax": 0x0, ...}, "pc": 0x401000, "sp": 0x7fffffffe000, "flags": {...}}
```

### 3. `inspect_memory`
读取并显示内存内容。

```python
result = inspect_memory(address=0x401000, size=64)
# 返回: {"address": "0x401000", "data": "48 65 6c 6c ...", "ascii_repr": "Hell..."}
```

### 4. `heap_analysis`
分析当前堆状态。

```python
result = heap_analysis()
# 返回: {"chunks": [...], "top": 0x602000, "system_mem": 0x21000, ...}
```

### 5. `stack_analysis`
分析当前栈帧。

```python
result = stack_analysis()
# 返回: {"frames": [{"level": 0, "address": 0x401000, "function": "main", ...}, ...]}
```

### 6. `search_pattern`
在内存中搜索模式。

```python
result = search_pattern(pattern="48 65 6c 6c", address=0x400000, size=0x1000)
# 返回: {"matches": [{"address": 0x401000, "pattern": "48 65 6c 6c"}, ...]}
```

### 7. `manage_breakpoint`
管理断点。

```python
# 添加断点
result = manage_breakpoint(action="add", location="0x401000")

# 列出断点
result = manage_breakpoint(action="list")

# 删除断点
result = manage_breakpoint(action="delete", breakpoint_id="1")
```

### 8. `control_execution`
控制程序执行。

```python
# 继续执行
result = control_execution(action="continue")

# 单步执行
result = control_execution(action="stepi")

# 执行到下一个函数
result = control_execution(action="nexti")
```

## 安装

```bash
pip install mcp
```

## 使用方法

### 作为独立服务器运行

```bash
python -m pwndbg.mcp.server --stdio
```

### 在 GDB 中使用

```bash
gdb ./binary
(gdb) source /path/to/pwndbg/mcp/server.py
```

### 传输方式

支持三种传输方式：

1. **stdio**（默认）:
   ```bash
   python -m pwndbg.mcp.server --stdio
   ```

2. **SSE**:
   ```bash
   python -m pwndbg.mcp.server --sse --host 127.0.0.1 --port 8000
   ```

3. **HTTP**:
   ```bash
   python -m pwndbg.mcp.server --http --host 127.0.0.1 --port 8000
   ```

## AI Agent 集成示例

### Claude Desktop 配置

在 `claude_desktop_config.json` 中添加：

```json
{
  "mcpServers": {
    "pwndbg": {
      "command": "python",
      "args": ["-m", "pwndbg.mcp.server", "--stdio"]
    }
  }
}
```

### 使用示例

```python
from mcp import Client

async def analyze_binary():
    async with Client("pwndbg") as client:
        # 获取寄存器状态
        regs = await client.call_tool("get_registers", {})
        print(f"PC: {regs['pc']}, SP: {regs['sp']}")
        
        # 检查内存
        mem = await client.call_tool("inspect_memory", {
            "address": 0x401000,
            "size": 64
        })
        print(f"Memory: {mem['ascii_repr']}")
        
        # 堆分析
        heap = await client.call_tool("heap_analysis", {})
        print(f"Top chunk: {heap['top']}")
```

## 常见使用场景

### 1. 漏洞分析

```python
# 1. 加载二进制并运行到断点
await client.call_tool("manage_breakpoint", {
    "action": "add",
    "location": "vulnerable_function"
})
await client.call_tool("control_execution", {"action": "continue"})

# 2. 检查寄存器状态
regs = await client.call_tool("get_registers", {})

# 3. 检查输入缓冲区
mem = await client.call_tool("inspect_memory", {
    "address": regs["registers"]["rsp"],
    "size": 256
})
```

### 2. 堆溢出分析

```python
# 1. 在 malloc 处设置断点
await client.call_tool("manage_breakpoint", {
    "action": "add",
    "location": "malloc"
})

# 2. 运行到断点
await client.call_tool("control_execution", {"action": "continue"})

# 3. 分析堆状态
heap = await client.call_tool("heap_analysis", {})

# 4. 检查分配的内存块
for chunk in heap["chunks"]:
    print(f"Chunk at {chunk['address']}: size={chunk['size']}")
```

### 3. 逆向工程辅助

```python
# 1. 搜索特定模式
matches = await client.call_tool("search_pattern", {
    "pattern": "48 65 6c 6c 6f",  # "Hello"
    "address": 0x400000,
    "size": 0x10000
})

# 2. 反汇编函数
disasm = await client.call_tool("execute_command", {
    "command": "disassemble 0x401000 50"
})

# 3. 分析调用栈
stack = await client.call_tool("stack_analysis", {})
```

## 测试

运行测试套件：

```bash
pytest pwndbg/tests/test_mcp_tools.py -v
```

测试覆盖率：80%

## 错误处理

所有工具返回统一的错误格式：

```python
{
    "status": "error",
    "message": "Error description",
    "code": "ERROR_CODE"
}
```

常见错误码：
- `NOT_INITIALIZED`: pwndbg 未初始化
- `INVALID_ADDRESS`: 无效的内存地址
- `BREAKPOINT_NOT_FOUND`: 断点未找到
- `EXECUTION_ERROR`: 执行错误

## 依赖项

- Python 3.8+
- pwndbg
- mcp (Model Context Protocol SDK)
- GDB with Python support

## 许可证

与 pwndbg 项目相同。

## 贡献

欢迎提交 Issue 和 Pull Request。

## 相关链接

- [pwndbg 项目](https://github.com/pwndbg/pwndbg)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
