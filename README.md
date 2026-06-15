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

## 许可证

MIT
