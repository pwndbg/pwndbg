---
tool_name: pwndbg
mcp_server: pwndbg.mcp.server
version: 1.0
author: AI Assistant
created: 2026-07-08
updated: 2026-07-08
tags: [debugger, dynamic-analysis, gdb, exploit-development]
---

# pwndbg MCP Skill

## 概述

pwndbg 是一个强大的 GDB 插件，专为逆向工程和漏洞利用开发设计。通过 MCP Server，AI Agent 可以动态调试程序、分析内存、检查寄存器和控制执行流程。

### 主要功能

- **动态调试**: 实时调试运行中的程序
- **内存分析**: 检查和修改内存内容
- **寄存器监控**: 查看和修改 CPU 寄存器状态
- **堆栈分析**: 分析堆分配和调用栈
- **断点管理**: 设置和管理断点
- **模式搜索**: 在内存中搜索特定模式

### 适用场景

- CTF Pwn 题求解
- 漏洞利用开发
- 恶意代码动态分析
- 程序行为分析
- 内存损坏漏洞研究

## 工具选择指南

### 何时使用 pwndbg

- 需要动态调试程序执行流程
- 需要实时查看内存和寄存器状态
- 需要分析堆分配和释放
- 需要在特定位置设置断点
- 需要单步执行指令

### 与其他工具的对比

| 工具 | 类型 | 优势 | 劣势 |
|------|------|------|------|
| pwndbg | 动态调试 | 实时分析、交互式调试 | 需要运行环境 |
| Ghidra | 静态分析 | 反编译、无需运行 | 无法观察运行时状态 |
| angr | 符号执行 | 自动路径探索 | 性能开销大 |
| radare2 | 静态/动态 | 多平台支持 | 学习曲线陡峭 |

### 典型使用场景

1. **缓冲区溢出分析**: 检查栈帧布局、返回地址覆盖
2. **堆漏洞分析**: 分析堆块分配、UAF、Double Free
3. **格式化字符串漏洞**: 观察栈上的输入数据
4. **ROP 链验证**: 验证 gadget 地址和执行流程

## 支持的工具

### 核心工具

- `execute_command` - 执行 GDB/pwndbg 命令
- `get_registers` - 获取寄存器状态
- `inspect_memory` - 检查内存内容
- `heap_analysis` - 堆分析
- `stack_analysis` - 栈分析
- `search_pattern` - 模式搜索
- `manage_breakpoint` - 断点管理
- `control_execution` - 执行控制

## 参数最佳实践

### execute_command

```python
# 推荐：使用 pwndbg 特定命令
result = execute_command(command="vmmap")
result = execute_command(command="heap")
result = execute_command(command="telescope $rsp 20")

# 避免：执行会改变程序状态的命令（除非有意为之）
# execute_command(command="continue")  # 使用 control_execution 代替
```

### inspect_memory

```python
# 推荐：指定合适的 size 参数
result = inspect_memory(address=0x400000, size=64)  # 查看 64 字节

# 查看栈内容
result = inspect_memory(address=registers["rsp"], size=128)

# 查看堆块
result = inspect_memory(address=heap_chunk_addr, size=chunk_size)
```

### manage_breakpoint

```python
# 添加断点
result = manage_breakpoint(action="add", location="0x401000")
result = manage_breakpoint(action="add", location="main")
result = manage_breakpoint(action="add", location="*0x401000")  # 绝对地址

# 列出断点
result = manage_breakpoint(action="list")

# 删除断点
result = manage_breakpoint(action="delete", breakpoint_id="1")
```

### control_execution

```python
# 继续执行
result = control_execution(action="continue")

# 单步执行
result = control_execution(action="stepi")  # 指令级
result = control_execution(action="nexti")  # 函数级

# 执行到返回
result = control_execution(action="finish")
```

## 错误处理

参考 [MCP_ERROR_HANDLING.md](../MCP_ERROR_HANDLING.md) 中的错误码定义。

### 调试器相关错误 (3000-3999)

| 错误码 | 名称 | 解决方案 |
|--------|------|----------|
| 3001 | DEBUGGER_NOT_ATTACHED | 先启动或附加到目标程序 |
| 3002 | BREAKPOINT_FAILED | 检查地址是否有效、是否有执行权限 |
| 3003 | EXECUTION_FAILED | 检查程序是否处于可执行状态 |
| 3004 | MEMORY_READ_FAILED | 检查地址是否可访问、是否已映射 |
| 3005 | MEMORY_WRITE_FAILED | 检查内存保护属性（是否可写） |
| 3006 | REGISTER_ACCESS_FAILED | 检查寄存器名称是否正确 |
| 3007 | PROCESS_NOT_FOUND | 检查目标进程 PID 是否正确 |
| 3008 | SESSION_EXPIRED | 重新启动调试会话 |

### 常见错误及解决方案

**错误 1: 无法读取内存**
```
Error: MEMORY_READ_FAILED - Cannot access memory at 0x...
```
解决方案：
- 检查地址是否在有效映射范围内（使用 `vmmap`）
- 检查内存保护属性（是否可读）
- 确认程序正在运行且未崩溃

**错误 2: 断点设置失败**
```
Error: BREAKPOINT_FAILED - Cannot set breakpoint at 0x...
```
解决方案：
- 检查地址是否指向有效指令
- 确认代码段有执行权限
- 尝试使用符号名称而非地址

**错误 3: 程序已终止**
```
Error: EXECUTION_FAILED - Program is not running
```
解决方案：
- 重新启动程序（`run` 命令）
- 检查程序是否因信号终止
- 检查是否有 core dump

## Workflow 示例

### 基础工作流：分析缓冲区溢出

```python
async def analyze_buffer_overflow():
    # 1. 启动程序
    await execute_command(command="run")
    
    # 2. 在 vulnerable 函数设置断点
    await manage_breakpoint(action="add", location="vulnerable_func")
    
    # 3. 继续执行到断点
    await control_execution(action="continue")
    
    # 4. 检查栈帧布局
    stack = await stack_analysis()
    print(f"Stack frames: {stack}")
    
    # 5. 检查缓冲区位置
    buf_addr = 0x7fffffffe000  # 从栈分析中获取
    memory = await inspect_memory(address=buf_addr, size=64)
    print(f"Buffer content: {memory}")
    
    # 6. 检查返回地址
    rsp = (await get_registers())["rsp"]
    ret_addr = await inspect_memory(address=rsp, size=8)
    print(f"Return address: {ret_addr}")
    
    # 7. 单步执行观察覆盖
    await control_execution(action="stepi")
```

### 高级工作流：堆漏洞分析

```python
async def analyze_heap_vulnerability():
    # 1. 启动程序
    await execute_command(command="run")
    
    # 2. 在 malloc 设置断点
    await manage_breakpoint(action="add", location="malloc")
    
    # 3. 继续执行
    await control_execution(action="continue")
    
    # 4. 分析堆状态
    heap_info = await heap_analysis()
    print(f"Heap chunks: {heap_info['chunks']}")
    
    # 5. 检查特定堆块
    chunk_addr = 0x602000  # 从堆分析中获取
    chunk_data = await inspect_memory(address=chunk_addr, size=32)
    print(f"Chunk data: {chunk_data}")
    
    # 6. 执行到 free
    await manage_breakpoint(action="add", location="free")
    await control_execution(action="continue")
    
    # 7. 再次检查堆状态
    heap_after_free = await heap_analysis()
    print(f"Heap after free: {heap_after_free}")
```

### 多工具协作：结合静态和动态分析

```python
async def combined_analysis(binary_path):
    # 1. 使用 Ghidra 进行静态分析
    ghidra_result = await ghidra_client.call_tool(
        "get_functions", {}
    )
    
    # 2. 识别可疑函数
    suspicious_funcs = [f for f in ghidra_result["functions"] 
                       if "vuln" in f["name"].lower()]
    
    # 3. 使用 pwndbg 动态验证
    for func in suspicious_funcs:
        await manage_breakpoint(
            action="add", 
            location=hex(func["address"])
        )
    
    # 4. 运行程序
    await execute_command(command="run")
    
    # 5. 在每个断点收集信息
    while True:
        regs = await get_registers()
        stack = await stack_analysis()
        print(f"Hit breakpoint at {hex(regs['pc'])}")
        print(f"Stack: {stack}")
        
        # 继续执行
        result = await control_execution(action="continue")
        if result["status"] == "program_exited":
            break
```

## Prompt 模板

### 基础调用模板

```python
# 调用 pwndbg MCP 工具
async def debug_with_pwndbg():
    # 获取寄存器
    result = await mcp_client.call_tool(
        tool_name="get_registers",
        arguments={}
    )
    
    if result["status"] == "success":
        regs = result["data"]
        print(f"PC: {hex(regs['pc'])}")
        print(f"SP: {hex(regs['sp'])}")
    else:
        print(f"Error: {result['error_message']}")
```

### 高级分析模板

```python
# 自动化漏洞分析
async def automated_vulnerability_analysis():
    """
    自动化分析流程：
    1. 启动程序
    2. 设置关键断点
    3. 收集运行时信息
    4. 识别潜在漏洞
    """
    # 启动程序
    await mcp_client.call_tool("execute_command", {"command": "run"})
    
    # 设置断点
    breakpoints = ["malloc", "free", "strcpy", "sprintf"]
    for bp in breakpoints:
        await mcp_client.call_tool(
            "manage_breakpoint",
            {"action": "add", "location": bp}
        )
    
    # 收集信息
    while True:
        # 继续执行
        result = await mcp_client.call_tool(
            "control_execution",
            {"action": "continue"}
        )
        
        if result.get("stopped_by_breakpoint"):
            # 获取当前状态
            regs = await mcp_client.call_tool("get_registers", {})
            stack = await mcp_client.call_tool("stack_analysis", {})
            
            # 分析
            print(f"Hit at {hex(regs['data']['pc'])}")
            analyze_context(regs, stack)
        else:
            break
```

### 自动化脚本模板

```python
#!/usr/bin/env python3
"""
pwndbg MCP 自动化分析脚本
"""
import asyncio
from mcp import Client

async def main():
    async with Client("pwndbg") as client:
        # 启动程序
        await client.call_tool("execute_command", {"command": "run"})
        
        # 获取初始状态
        regs = await client.call_tool("get_registers", {})
        print(f"Initial PC: {hex(regs['data']['pc'])}")
        
        # 设置断点
        await client.call_tool(
            "manage_breakpoint",
            {"action": "add", "location": "main"}
        )
        
        # 继续执行
        await client.call_tool("control_execution", {"action": "continue"})
        
        # 获取断点处状态
        regs = await client.call_tool("get_registers", {})
        stack = await client.call_tool("stack_analysis", {})
        
        print(f"Hit main at {hex(regs['data']['pc'])}")
        print(f"Stack frames: {len(stack['data']['frames'])}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 最佳实践

### 性能优化建议

1. **减少不必要的内存读取**
   - 只读取需要的内存区域
   - 使用合适的 size 参数
   - 缓存已读取的内存内容

2. **合理使用断点**
   - 避免在热点路径设置断点
   - 使用条件断点减少中断次数
   - 及时删除不需要的断点

3. **批量操作**
   - 使用 `execute_command` 批量执行多个命令
   - 减少 MCP 调用次数

### 安全注意事项

1. **隔离环境**
   - 在虚拟机或容器中运行调试
   - 避免调试不受信任的程序
   - 限制程序的文件系统访问

2. **数据保护**
   - 不要将敏感数据写入日志
   - 清理调试过程中产生的临时文件
   - 注意内存中的敏感信息

3. **权限控制**
   - 使用最小权限运行调试器
   - 避免以 root 权限调试普通程序
   - 注意 ptrace 权限设置

### 常见问题解答

**Q: 如何在调试过程中修改寄存器值？**
A: 使用 `execute_command` 执行 `set $rax = 0x1234` 命令。

**Q: 如何查看堆的所有分配块？**
A: 使用 `heap_analysis` 工具，或使用 `execute_command` 执行 `heap` 命令。

**Q: 如何在特定条件满足时才中断？**
A: 使用 `execute_command` 设置条件断点：`break *0x401000 if $rax == 0`。

**Q: 如何分析多线程程序？**
A: 使用 `execute_command` 执行 `info threads` 查看线程，使用 `thread <n>` 切换线程。

**Q: 如何处理 ASLR？**
A: 使用 `execute_command` 执行 `set disable-randomization off` 关闭 ASLR 禁用，或分析相对偏移。

---

**相关资源**
- [pwndbg 项目](https://github.com/pwndbg/pwndbg)
- [MCP 协议](https://modelcontextprotocol.io/)
- [错误处理规范](../MCP_ERROR_HANDLING.md)
