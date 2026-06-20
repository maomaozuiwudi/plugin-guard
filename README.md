# PluginGuard — Hermes 插件安检工具

> 🔍 装任何第三方 Skill/Plugin 之前，先扫一梭子，确保安全。

---

## 功能

PluginGuard 是一个纯 Python 标准库实现的 Hermes 插件安全检测工具。它可以扫描任意 Hermes 插件/技能目录（或 GitHub 仓库链接），自动完成两大分析模块：

### 📋 功能分析

| 功能 | 说明 |
|------|------|
| 名称/描述 | 解析 SKILL.md 的 YAML frontmatter |
| 一句话总结 | 自动归纳插件功能 |
| 工具调用 | 统计调用了哪些 Hermes 工具（web_search、terminal、write_file 等） |
| 文件操作范围 | 识别读写路径范围 |
| 网络请求 | 识别所有外部网络连接 |
| 脚本数量 | 统计 .py/.sh/.js 脚本数量 |

### 🛡️ 安全检测

覆盖 **11 类风险项**，四级风险评级：

| 风险等级 | 分值 | 检测项 |
|----------|------|--------|
| 🔴 严重 | 25分 | 写 config.yaml、改 model/provider/api_key、importlib 动态导入、字符串拼接绕过 |
| 🔴 高危 | 15分 | os.system/subprocess、POST/PUT 外发数据、os.environ+网络外发组合、写 ~/.hermes/ 系统路径 |
| 🟡 中危 | 5分 | eval/exec/compile 动态执行 |
| 🟢 低危 | 2分 | base64 编码可疑字符串、print 输出敏感信息 |

**评分标准：** 0-20 🟢 安全 → 21-50 🟡 需注意 → 51-80 🟠 高风险 → 81-100 🔴 危险

## 快速开始

```bash
# 扫描本地插件目录
python scripts/scan.py scan ~/.hermes/skills/某个技能/

# 扫描 GitHub 仓库
python scripts/scan.py scan https://github.com/xxx/xxx

# 批量扫描所有技能
python scripts/batch_scan.py
```

## 输出示例

```
╔══════════════════════════════════════════════════════╗
║  PluginGuard v1.0  安检报告                        ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  📋 功能分析                                      ║
║  名称: drawio-skill                                ║
║  一句话: 用自然语言生成draw.io图表                 ║
║  调用工具: terminal                                 ║
║  网络请求: 无                                       ║
║                                                      ║
║  🛡️ 安全评估                                      ║
║  风险等级: 🟢 安全                                  ║
║  风险评分: 2/100                                    ║
║  ✅ SKILL.md 格式正常                              ║
║  ✅ 无危险系统调用                                 ║
║  ✅ 无配置篡改                                     ║
║  ✅ 无网络外联                                     ║
║  ✅ 无可疑编码/绕过                                ║
║                                                      ║
║ 💡 结论: ✅ 可安全安装                             ║
╚══════════════════════════════════════════════════════╝
```

## 安装

```bash
# 作为 Hermes Skill 安装
hermes skills install plugin-guard

# 或手动部署
git clone https://github.com/maomaozuiwudi/plugin-guard.git
cp -r plugin-guard ~/.hermes/skills/
```

## 场景

- **装新插件前**：先跑 PluginGuard 扫一轮，确认没有恶意代码
- **审核社区插件**：下载 GitHub 仓库后扫一遍，判断是否安全
- **批量审计**：`batch_scan.py` 一键扫描所有已安装技能

## 技术栈

- 纯 Python 3 标准库，**零外部依赖**
- 跨平台（Windows / macOS / Linux）
- 静态源码分析 + 正则模式匹配 + 熵检测
- 支持本地路径和 GitHub URL 两种扫描入口

## ❓ 常见问题 (FAQ)

<details>
<summary><b>PluginGuard能检测哪些风险？</b></summary>

能检测 11 类安全风险，覆盖 4 级风险评级（安全、低危、中危、高危/严重），包括：恶意代码注入、未授权网络请求、敏感信息泄露、文件系统越权、OS命令执行、base64混淆/编码、eval/exec动态执行等。
</details>

<details>
<summary><b>需要联网吗？</b></summary>

不需要。PluginGuard 完全纯本地运行，不联网、不上传任何代码，所有扫描在本机完成，保障隐私安全。
</details>

<details>
<summary><b>支持扫描GitHub仓库链接吗？</b></summary>

支持。可以直接传入 GitHub 仓库 URL，工具自动拉取代码并扫描。也支持扫描本地 Hermes 技能目录。
</details>

<details>
<summary><b>和其他安全工具比有什么不同？</b></summary>

PluginGuard 专为 Hermes Agent 插件/技能生态设计，能识别 Hermes 特有的风险模式（如 web_search、terminal、write_file 的滥用）。对比通用安全工具（如 VirusTotal），检测范围更聚焦、误报率更低。
</details>

<details>
<summary><b>支持批量扫描多个插件吗？</b></summary>

支持。提供 batch_scan.py 脚本，可一次性扫描多个技能或插件目录，自动汇总输出风险报告。
</details>

<details>
<summary><b>风险评级是怎么划分的？</b></summary>

0-20 安全 → 21-50 低危 → 51-80 中危 → 81-100 高危/严重。评分基于风险类型组合与严重程度加权计算。
</details>

<details>
<summary><b>扫描结果可以导出吗？</b></summary>

目前支持控制台输出，可配合重定向 `>` 保存为文本文件，或通过 Hermes 结果回调机制集成到 CI/CD 流程中。
</details>

## 许可证

MIT

---

> 🤖 **更多AI工具推荐 → 关注小红书 @工具箱里的猫**  
> 分享最新AI工具评测、AI搜索玩法、效率提升技巧，每天更新。
