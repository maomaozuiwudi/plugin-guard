---
name: plugin-guard
description: Hermes 插件安全检测与功能分析工具。在安装任何第三方插件/skill前，先扫描分析其代码安全性和功能。
category: security
version: 1.0.0
author: 工具猫
license: MIT
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [security, audit, analysis, protection]
    related_skills: []
    category: security
---

# PluginGuard — Hermes 插件安检工具

> 在安装任何第三方插件/skill前，先扫一梭子，确保安全。

## 简介

PluginGuard 是一个纯 Python 标准库实现的安全检测与功能分析工具。它可以扫描任意 Hermes 插件/技能目录（或 GitHub 仓库链接），自动分析：

- **功能分析**：解析 SKILL.md、统计工具调用、识别文件操作范围和网络请求
- **安全检测**：检测危险系统调用、配置篡改、网络外联、动态导入绕过、编码混淆等 11 类风险项
- **风险评分**：基于加权评分系统输出 0-100 分风险评分和 🟢🟡🟠🔴 四级风险等级

让"工具猫"琪琪再也不怕被第三方插件搞坏 Hermes 配置。

## 使用方法（楠楠调用）

### 方式一：扫描本地目录

```bash
python scripts/scan.py scan <本地路径>
```

示例：
```bash
python scripts/scan.py scan "C:\Users\Administrator\AppData\Local\hermes\skills\some-skill"
```

### 方式二：扫描 GitHub 仓库

```bash
python scripts/scan.py scan <GitHub URL>
```

示例：
```bash
python scripts/scan.py scan https://github.com/someuser/hermes-plugin
```

工具会自动 git clone 到临时目录再扫描，扫描完成后自动清理。

### 在楠楠（Hermes）中调用

```yaml
# 在技能/插件的 SKILL.md 指令中：
1. 调用 plugin-guard 扫描目标插件：
   delegate_task(agent="hermes", task='Run: python /path/to/plugin-guard/scripts/scan.py scan "目标路径"')
2. 阅读输出报告判断是否安全
```

或者直接将 PluginGuard 设置为前置检测步骤：
> "在安装任何第三方 Hermes 插件前，先使用 plugin-guard 扫描目标路径，读取风险等级和评分，只有 🟢 安全 或 🟡 需注意 级别才允许安装。"

## 检测规则说明

| 风险项 | 分值 | 说明 |
|--------|------|------|
| 写 ~/.hermes/config.yaml | 25分 | 直接写入 Hermes 主配置，可能篡改 LLM/API 设置 |
| 改 model/provider/api_key | 25分 | 间接修改配置中的关键字段 |
| importlib.import_module() 动态导入 | 25分 | 通过动态导入绕过静态检测 |
| 字符串拼接构造函数名 | 25分 | 用 `''.join()` 或 `+` 拼接危险函数名绕过检测 |
| os.system() / subprocess.Popen/call/run | 15分 | 执行系统命令 |
| requests.post/urllib 外发数据 | 15分 | 向外发送数据（数据泄露风险） |
| eval/exec/compile | 5分 | 动态执行代码 |
| 读 os.environ + 网络外发 组合 | 15分 | 读取环境变量（可能含 API key）并外发 |
| 写 ~/.hermes/ 下 skill/plugin 目录外的文件 | 15分 | 越权写入 Hermes 其他目录 |
| base64 编码可疑字符串 | 2分 | 隐藏恶意 payload |
| print/console.log 输出敏感信息 | 2分 | 日志泄露 |

### 风险等级

| 评分区间 | 等级 | 图标 | 结论 |
|----------|------|------|------|
| 0-20 | 安全 | 🟢 | ✅ 可安全安装 |
| 21-50 | 需注意 | 🟡 | ⚠️ 需确认 |
| 51-80 | 高风险 | 🟠 | ⚠️ 需确认 |
| 81-100 | 危险 | 🔴 | 🚫 禁止安装 |

## 输出解读指南

报告分为三大区域：

### 📋 功能分析
- **名称/类型**：从 SKILL.md 提取的插件元信息
- **一句话**：AI 基于代码分析的一句话总结
- **调用工具**：插件使用了哪些 Hermes 工具
- **文件操作/网络请求**：插件的 I/O 行为概览

### 🛡️ 安全评估
- **风险等级/评分**：综合评分的直观展示
- **五项检测清单**：✅ 通过 / ❌ 发现问题
- **风险项明细**：列出所有被检测到的具体风险点

### 💡 结论
- ✅ **可安全安装**：评分 0-20，放心装
- ⚠️ **需确认**：评分 21-80，需要人工审核后决定
- 🚫 **禁止安装**：评分 81-100，绝对不要装

## 注意事项

- PluginGuard 自身不产生任何副作用，只读不改
- 扫描 GitHub URL 需要系统安装 git
- 纯 Python 3 标准库实现，无需 pip install 任何依赖
- 扫描脚本大小写不敏感，兼容 Windows/Linux/macOS
