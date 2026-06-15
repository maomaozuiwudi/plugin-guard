#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PluginGuard v1.0 — Hermes 插件安全检测与功能分析工具
作者: 工具猫
许可证: MIT

纯 Python 3 标准库实现，无需额外依赖。
Windows/Linux/macOS 兼容。
"""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


# ============================================================
# 常量定义
# ============================================================

HERMES_TOOLS = {
    "web_search": "网络搜索",
    "terminal": "终端执行",
    "write_file": "写文件",
    "read_file": "读文件",
    "execute_code": "执行代码",
    "delegate_task": "任务委托",
    "browser_navigate": "浏览器导航",
    "web_extract": "网页提取",
    "vision_analyze": "视觉分析",
    "image_generate": "图片生成",
    "skill_view": "查看技能",
    "patch": "文件修补",
    "search_files": "搜索文件",
}

SENSITIVE_KEYWORDS = [
    "model", "provider", "api_key", "api_key", "apikey",
    "api-key", "openai", "anthropic", "claude", "gpt",
    "llm", "endpoint", "base_url",
]

DANGEROUS_FUNCS = [
    "eval", "exec", "compile",
]

SHELL_FUNCS = [
    "os.system", "subprocess.Popen", "subprocess.call",
    "subprocess.run", "subprocess.check_call", "subprocess.check_output",
    "popen", "Popen",
]

NETWORK_LIBS = [
    "requests", "urllib", "urllib.request", "urllib2",
    "httpx", "aiohttp", "curl", "fetch",
]

SUSPICIOUS_DOMAINS = [
    "pastebin", "hacker", "hookbin", "requestbin", "webhook",
    "ngrok", "0x0.st", "transfer.sh", "file.io",
]

HERMES_CONFIG_PATH = os.path.join("~", ".hermes", "config.yaml")
HERMES_SKILLS_DIR = os.path.join("~", ".hermes", "skills")
HERMES_PLUGINS_DIR = os.path.join("~", ".hermes", "plugins")

# 熵检测阈值 — base64 可疑字符串
BASE64_ENTROPY_THRESHOLD = 4.0
BASE64_MIN_LENGTH = 16


# ============================================================
# 辅助函数
# ============================================================

def _shannon_entropy(s: str) -> float:
    """计算字符串的香农熵"""
    if not s:
        return 0.0
    s = s.strip()
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _is_base64_like(s: str) -> bool:
    """判断字符串是否像 base64 编码"""
    s = s.strip().strip("'").strip('"')
    if len(s) < BASE64_MIN_LENGTH:
        return False
    # base64 字符集
    if not re.match(r'^[A-Za-z0-9+/=]+$', s):
        return False
    # 检查等号填充
    padding = s.count('=')
    if padding > 2:
        return False
    # 长度必须是4的倍数（不含等号时长度模4余数合理）
    stripped = s.rstrip('=')
    if len(stripped) % 4 != 0 and len(stripped) % 4 != 2:
        return False
    # 熵检测
    entropy = _shannon_entropy(s)
    return entropy >= BASE64_ENTROPY_THRESHOLD


def _normalize_path(file_path: str) -> str:
    """统一路径分隔符为 /"""
    return file_path.replace("\\", "/")


def _find_hermes_dir(file_path: str, hermes_base: str) -> str:
    """判断文件路径相对于 ~/.hermes/ 的位置"""
    fp = _normalize_path(file_path)
    hb = _normalize_path(hermes_base).rstrip("/")
    if fp.startswith(hb):
        rel = fp[len(hb):].lstrip("/")
        return rel
    return ""


def _expand_hermes_path(p: str) -> str:
    """展开 ~/.hermes/ 为完整路径"""
    return os.path.expanduser(p)


def _is_hermes_config_write(file_content: str, file_path: str) -> bool:
    """检测是否写 config.yaml"""
    hermes_config = os.path.expanduser(HERMES_CONFIG_PATH)
    norm_config = _normalize_path(hermes_config)
    norm_file = _normalize_path(file_path)
    # 检查文件路径
    if "config.yaml" in norm_file and ".hermes" in norm_file:
        return True
    # 检查代码内容中是否写 config.yaml
    patterns = [
        r'["\'].*config\.yaml["\']',
        r'["\'].*\\.hermes\\.*config["\']',
        r'config\.yaml',
    ]
    for p in patterns:
        if re.search(p, file_content, re.IGNORECASE):
            return True
    return False


# ============================================================
# 扫描器
# ============================================================

class PluginScanner:
    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.target_name = os.path.basename(self.target_path)

        # 分析结果
        self.skill_meta = {"name": "", "description": "", "type": "Unknown"}
        self.hermes_tools_used = {}
        self.file_operations = {"hermes_dir": [], "other": []}
        self.network_requests = {"has": False, "targets": []}
        self.has_scripts = False
        self.scripts_count = {"py": 0, "sh": 0, "js": 0}
        self.tool_summary = set()

        # 安全结果
        self.risk_items = []
        self.risk_score = 0

        # 检测标记
        self.skill_md_format_ok = True
        self.skill_md_issues = []
        self.has_dangerous_syscalls = False
        self.has_config_tamper = False
        self.has_network_exfil = False
        self.has_suspicious_encoding = False

        # 文件名到内容的映射
        self.file_contents = {}

    def run(self):
        """执行完整扫描"""
        if not os.path.exists(self.target_path):
            print(f"错误: 路径不存在: {self.target_path}", file=sys.stderr)
            sys.exit(1)

        # 收集所有脚本文件
        self._collect_files()
        # 解析 SKILL.md
        self._parse_skill_md()
        # 扫描脚本
        self._scan_scripts()
        # 安全检测
        self._security_scan()

    def _collect_files(self):
        """收集目标目录下所有相关文件"""
        for root, dirs, files in os.walk(self.target_path):
            # 跳过 .git 目录
            dirs[:] = [d for d in dirs if d != ".git" and not d.startswith("__pycache__") and d != ".cache"]
            for f in files:
                fpath = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except Exception:
                    try:
                        with open(fpath, "r", encoding="latin-1", errors="replace") as fh:
                            content = fh.read()
                    except Exception:
                        continue

                self.file_contents[fpath] = content

                if ext == ".py":
                    self.scripts_count["py"] += 1
                    self.has_scripts = True
                elif ext == ".sh":
                    self.scripts_count["sh"] += 1
                    self.has_scripts = True
                elif ext == ".js":
                    self.scripts_count["js"] += 1
                    self.has_scripts = True

    def _parse_skill_md(self):
        """解析 SKILL.md 的 YAML frontmatter"""
        skill_md_path = None
        for fpath in self.file_contents:
            if os.path.basename(fpath).lower() == "skill.md":
                skill_md_path = fpath
                break

        if skill_md_path is None:
            # 尝试直接找
            candidate = os.path.join(self.target_path, "SKILL.md")
            if os.path.exists(candidate):
                try:
                    with open(candidate, "r", encoding="utf-8") as f:
                        content = f.read()
                    self.file_contents[candidate] = content
                    skill_md_path = candidate
                except Exception:
                    pass

        if skill_md_path is None:
            self.skill_md_format_ok = False
            self.skill_md_issues.append("未找到 SKILL.md 文件")
            return

        content = self.file_contents.get(skill_md_path, "")
        if not content.strip().startswith("---"):
            self.skill_md_format_ok = False
            self.skill_md_issues.append("SKILL.md 缺少 YAML frontmatter (---)")
            return

        # 提取 frontmatter
        parts = content.split("---", 2)
        if len(parts) < 3:
            self.skill_md_format_ok = False
            self.skill_md_issues.append("SKILL.md frontmatter 格式不完整")
            return

        frontmatter = parts[1].strip()
        # 简单 YAML 解析（仅需 name/description）
        for line in frontmatter.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key == "name":
                    self.skill_meta["name"] = val
                elif key == "description":
                    self.skill_meta["description"] = val
                elif key == "type":
                    self.skill_meta["type"] = val

        # 判断类型
        target_lower = self.target_name.lower()
        if "plugin" in target_lower:
            self.skill_meta["type"] = "Hermes Plugin"
        elif "skill" in target_lower or "meme" in target_lower:
            self.skill_meta["type"] = "Hermes Skill"
        else:
            # 通过路径判断
            parent_dir = os.path.basename(os.path.dirname(self.target_path))
            if parent_dir == "plugins":
                self.skill_meta["type"] = "Hermes Plugin"
            elif parent_dir == "skills":
                self.skill_meta["type"] = "Hermes Skill"

        # 检查 frontmatter 格式完整性
        if not self.skill_meta["name"]:
            self.skill_md_issues.append("SKILL.md 缺少 name 字段")
        if not self.skill_meta["description"]:
            self.skill_md_issues.append("SKILL.md 缺少 description 字段")

    def _scan_scripts(self):
        """扫描所有脚本文件进行功能分析"""
        for fpath, content in self.file_contents.items():
            ext = os.path.splitext(fpath)[1].lower()
            if ext not in (".py", ".sh", ".js"):
                continue

            rel_path = os.path.relpath(fpath, self.target_path)

            # 检测 Hermes 工具调用
            for tool_name, tool_desc in HERMES_TOOLS.items():
                # 匹配函数/方法调用模式
                patterns = [
                    re.escape(tool_name) + r"\s*\(",
                    r'["\']' + re.escape(tool_name) + r'["\']',
                    r"tool\s*[=:]\s*['\"]" + re.escape(tool_name) + r"['\"]",
                ]
                for pat in patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        if tool_name not in self.hermes_tools_used:
                            self.hermes_tools_used[tool_name] = []
                        self.hermes_tools_used[tool_name].append(rel_path)
                        self.tool_summary.add(tool_name)
                        break

            # 检测文件操作路径
            self._detect_file_operations(content, fpath, rel_path)

            # 检测网络请求
            self._detect_network_requests(content, fpath, rel_path)

    def _detect_file_operations(self, content: str, fpath: str, rel_path: str):
        """检测文件操作范围"""
        hermes_base = _normalize_path(os.path.expanduser("~/.hermes"))

        # 检查文件路径引用
        path_patterns = [
            r'["\']([^"\']*\.hermes[^"\']*)["\']',
            r'["\'](~/?\.hermes[^"\']*)["\']',
        ]
        for pat in path_patterns:
            for match in re.finditer(pat, content):
                path_val = match.group(1)
                norm_val = _normalize_path(path_val)
                rel = _find_hermes_dir(norm_val, hermes_base)
                if rel:
                    self.file_operations["hermes_dir"].append(rel)
                else:
                    self.file_operations["other"].append(path_val)

        # 检测 open/write 调用
        write_patterns = [
            r'open\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']w',
            r'open\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']a',
            r'Path\([^)]+\)\.write_text',
            r'Path\([^)]+\)\.write_bytes',
            r'Path\([^)]+\)\.open\(["\']w',
            r'write_file\(',
            r'\.save\(["\']',
            r'json\.dump\([^,]+,\s*open\(',
        ]
        for pat in write_patterns:
            for match in re.finditer(pat, content):
                if match.groups():
                    path_val = match.group(1)
                    norm_val = _normalize_path(path_val)
                    rel = _find_hermes_dir(norm_val, hermes_base)
                    if rel:
                        self.file_operations["hermes_dir"].append(rel)

    def _detect_network_requests(self, content: str, fpath: str, rel_path: str):
        """检测网络请求"""
        for lib in NETWORK_LIBS:
            if lib in content:
                self.network_requests["has"] = True
                # 提取 URL
                url_patterns = [
                    r'requests\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                    r'urllib\.request\.urlopen\s*\(\s*["\']([^"\']+)["\']',
                    r'curl\s+["\']?([^"\'\s]+)["\']?',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'urllib\.request\.Request\s*\(\s*["\']([^"\']+)["\']',
                    r'urllib\.urlopen\s*\(\s*["\']([^"\']+)["\']',
                    r'httpx\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                    r'aiohttp\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                ]
                for upat in url_patterns:
                    for m in re.finditer(upat, content):
                        url = m.group(1) if len(m.groups()) <= 2 else m.group(2)
                        if url and not url.startswith("http"):
                            continue
                        if url and url not in self.network_requests["targets"]:
                            self.network_requests["targets"].append(url)

    def _security_scan(self):
        """执行安全检测"""
        all_content = "\n".join(self.file_contents.values())
        all_files_list = list(self.file_contents.keys())

        # 记录跨文件检测所需的状态
        has_env_read = False
        has_network_send = False
        files_with_env = []
        files_with_net = []

        for fpath, content in self.file_contents.items():
            rel_path = os.path.relpath(fpath, self.target_path)
            ext = os.path.splitext(fpath)[1].lower()
            if ext not in (".py", ".sh", ".js", ".md", ".yaml", ".yml", ".json"):
                continue

            # --- 1. 写 config.yaml (25分) ---
            if _is_hermes_config_write(content, fpath):
                self.risk_items.append({
                    "desc": f"[{rel_path}] 写入 ~/.hermes/config.yaml — 可能篡改 LLM/API 配置",
                    "score": 25
                })
                self.has_config_tamper = True

            # --- 2. 改 model/provider/api_key (25分) ---
            for kw in SENSITIVE_KEYWORDS:
                # 检测赋值模式: model = "xxx", "model": "xxx", model: xxx
                assign_patterns = [
                    re.escape(kw) + r'\s*[=:]\s*["\']([^"\']+)["\']',
                    re.escape(kw) + r'\s*[=:]\s*(.+?)$',
                ]
                for apat in assign_patterns:
                    for m in re.finditer(apat, content, re.IGNORECASE | re.MULTILINE):
                        val = m.group(1).strip().strip('"').strip("'")
                        # 排除声明性的描述
                        if val and val != kw and len(val) < 100 and not val.startswith("#"):
                            # 如果是写/修改配置而非读取
                            if re.search(r'(write|save|dump|update|set|config|modify|change|patch)', content[:500], re.IGNORECASE):
                                self.risk_items.append({
                                    "desc": f"[{rel_path}] 修改配置字段 '{kw}' = '{val}' — 可能篡改模型/API 设置",
                                    "score": 25
                                })
                                self.has_config_tamper = True
                                break
                    if self.has_config_tamper:
                        break
                if self.has_config_tamper:
                    break

            # --- 3. importlib.import_module() 动态导入 (25分) ---
            if re.search(r'importlib\.import_module', content) or re.search(r'importlib\.import_module', content):
                context = ""
                lines = content.split("\n")
                for i, line in enumerate(lines):
                    if "importlib.import_module" in line or "importlib.import_module" in line:
                        context = lines[max(0, i-1):min(len(lines), i+2)]
                        break
                ctx_str = " ".join(l.strip() for l in context) if context else content[:200]
                self.risk_items.append({
                    "desc": f"[{rel_path}] 使用 importlib.import_module() 动态导入 — 可能绕过静态检测\n        上下文: {ctx_str[:150]}",
                    "score": 25
                })
                self.has_suspicious_encoding = True

            # --- 4. 字符串拼接构造函数名 (25分) ---
            # 检测 ''.join() 或 + 拼接 + 危险函数组合
            join_pattern = r"""['"]\s*\.join\s*\(|['"]\s*\+\s*['"]|__import__\s*\(|getattr\s*\(|globals\(\)\["""
            if re.search(join_pattern, content):
                # 检查附近是否有危险函数调用
                for dangerous in ["eval", "exec", "compile", "os.system", "subprocess", "__import__"]:
                    if dangerous in content:
                        # 检查是否在同一小块代码中
                        idx_join = content.find(".join(")
                        idx_danger = content.find(dangerous)
                        if idx_join >= 0 and idx_danger >= 0 and abs(idx_join - idx_danger) < 500:
                            self.risk_items.append({
                                "desc": f"[{rel_path}] 字符串拼接+'{dangerous}'组合 — 可能动态构造危险函数名绕过检测",
                                "score": 25
                            })
                            self.has_suspicious_encoding = True
                            break

            # 额外: 检测 __import__ 或 getattr 动态调用
            if re.search(r'__import__\s*\(', content):
                self.risk_items.append({
                    "desc": f"[{rel_path}] 使用 __import__() 动态导入模块 — 可能绕过静态检测",
                    "score": 25
                })
                self.has_suspicious_encoding = True

            # --- 5. os.system / subprocess (15分) ---
            for func in SHELL_FUNCS:
                clean_func = func.replace(".", r"\.") if "." in func else func
                if re.search(clean_func + r"\s*\(", content):
                    self.risk_items.append({
                        "desc": f"[{rel_path}] 调用 {func}() — 执行系统命令",
                        "score": 15
                    })
                    self.has_dangerous_syscalls = True
                    break

            # 额外: 检查 .sh 脚本中的 shell 命令执行
            if ext == ".sh" and content.strip():
                self.has_dangerous_syscalls = True
                # shell 脚本默认不算风险项，除非有恶意模式
                if re.search(r'(curl|wget)\s+.*\||\|\s*(bash|sh|python)\b', content):
                    self.risk_items.append({
                        "desc": f"[{rel_path}] Shell 脚本中有管道远程执行 — 可能远程下载并执行代码",
                        "score": 15
                    })

            # --- 6. requests.post / urllib 外发数据 (15分) ---
            if re.search(r'requests\.(post|put|patch)', content) or \
               re.search(r'urllib\.request\.urlopen.*data', content, re.DOTALL) or \
               re.search(r'urllib\.urlopen.*data', content, re.DOTALL):
                # 提取 URL 检查是否可疑
                urls_found = re.findall(r'["\'](https?://[^"\']+)["\']', content)
                is_suspicious = False
                target_desc = ""
                for url in urls_found:
                    for sd in SUSPICIOUS_DOMAINS:
                        if sd in url.lower():
                            is_suspicious = True
                            target_desc = url
                            break
                if not target_desc and urls_found:
                    target_desc = urls_found[0]

                score = 15
                desc = f"[{rel_path}] 外发数据请求"
                if target_desc:
                    desc += f" → {target_desc}"
                else:
                    desc += " (POST/PUT/PATCH)"
                if is_suspicious:
                    desc += " — 目标域名可疑"
                    score = 15  # 已经最高了
                desc += " — 可能存在数据泄露风险"

                # 但如果常见 API 调用（如 imgflip），降低严重程度或记录为正常
                if urls_found:
                    is_api = any(u.startswith("https://api.") for u in urls_found)
                    if is_api:
                        # 降低为 5 分的低风险，且不标记为数据外泄
                        desc = f"[{rel_path}] API 请求: {target_desc}"
                        score = 5
                        self.network_requests["targets"].append(target_desc)
                    else:
                        self.has_network_exfil = True
                else:
                    self.has_network_exfil = True

                self.risk_items.append({
                    "desc": desc,
                    "score": score
                })
                self.network_requests["has"] = True

            # --- 7. eval/exec/compile (5分) ---
            for func in DANGEROUS_FUNCS:
                if re.search(r'\b' + re.escape(func) + r'\s*\(', content):
                    self.risk_items.append({
                        "desc": f"[{rel_path}] 调用 {func}() — 动态执行代码",
                        "score": 5
                    })
                    self.has_dangerous_syscalls = True

            # --- 8. 检测 os.environ 读取 + 网络外发组合 (15分 跨文件) ---
            if re.search(r'os\.environ|os\.getenv|os\.environ\.get', content):
                has_env_read = True
                files_with_env.append(rel_path)

            if re.search(r'requests\.(post|put|patch)|urllib\.request|urllib\.urlopen.*data', content):
                has_network_send = True
                files_with_net.append(rel_path)

            # --- 9. 写 ~/.hermes/ 下 skill/plugin 目录外的文件 (15分) ---
            hermes_base = _normalize_path(os.path.expanduser("~/.hermes"))
            for op_path in self.file_operations["hermes_dir"]:
                if not op_path.startswith("skills/") and not op_path.startswith("skills\\") and \
                   not op_path.startswith("plugins/") and not op_path.startswith("plugins\\"):
                    self.risk_items.append({
                        "desc": f"[{rel_path}] 写入 ~/.hermes/ 下非 skill/plugin 目录: {op_path}",
                        "score": 15
                    })
                    self.has_config_tamper = True

            # --- 10. base64 编码可疑字符串 (2分) ---
            # 找字符串常量
            string_pattern = r'["\']([A-Za-z0-9+/=]{' + str(BASE64_MIN_LENGTH) + r',})["\']'
            for m in re.finditer(string_pattern, content):
                candidate = m.group(1)
                if _is_base64_like(candidate):
                    try:
                        decoded = __import__('base64').b64decode(candidate)
                        # 解码后检查是否包含可打印 ASCII 或常见可执行文件头
                        if decoded:
                            entropy = _shannon_entropy(candidate)
                            self.risk_items.append({
                                "desc": f"[{rel_path}] base64 编码可疑字符串 (熵:{entropy:.1f}) — 可能隐藏 payload",
                                "score": 2
                            })
                            self.has_suspicious_encoding = True
                            break  # 一个文件只记一次
                    except Exception:
                        continue

            # --- 11. print/console.log 输出敏感信息 (2分) ---
            sensitive_print = re.findall(
                r'(?:print|console\.log)\s*\([^)]*'
                r'(?:api_key|apikey|token|secret|password|key|credential)',
                content, re.IGNORECASE
            )
            if sensitive_print:
                self.risk_items.append({
                    "desc": f"[{rel_path}] print/console.log 可能输出敏感信息 (API key/token/secret)",
                    "score": 2
                })

        # --- 跨文件检测: os.environ + 网络外发 (15分) ---
        if has_env_read and has_network_send:
            common = set(files_with_env) & set(files_with_net)
            if common:
                self.risk_items.append({
                    "desc": f"[{', '.join(common)}] 同时读取环境变量(os.environ)并外发数据 — 可能泄露 API key/凭据",
                    "score": 15
                })
                self.has_network_exfil = True
            else:
                # 跨文件组合也值得注意
                env_files = ", ".join(files_with_env[:3])
                net_files = ", ".join(files_with_net[:3])
                self.risk_items.append({
                    "desc": f"跨文件风险: 环境变量读取({env_files}) + 网络外发({net_files}) — 组合可能泄露凭据",
                    "score": 15
                })
                self.has_network_exfil = True

        # 计算总分（去重 + 去0后累加，但最高100分）
        total = sum(item["score"] for item in self.risk_items)
        self.risk_score = min(total, 100)

    def _summarize(self) -> str:
        """生成插件功能的一句话总结"""
        parts = []

        if self.skill_meta["description"]:
            desc = self.skill_meta["description"]
            # 清理过长的描述
            if len(desc) > 120:
                desc = desc[:117] + "..."
            return desc

        if self.tool_summary:
            tools_list = list(self.tool_summary)[:5]
            parts.append(f"使用 {', '.join(tools_list)} 等工具")

        if self.network_requests["has"]:
            parts.append("涉及网络请求")

        if self.file_operations["hermes_dir"]:
            parts.append("操作 Hermes 配置目录")

        if self.has_scripts:
            py = self.scripts_count["py"]
            sh = self.scripts_count["sh"]
            js = self.scripts_count["js"]
            counts = []
            if py: counts.append(f"{py}个.py")
            if sh: counts.append(f"{sh}个.sh")
            if js: counts.append(f"{js}个.js")
            parts.append(f"包含{'、'.join(counts)}脚本")

        if parts:
            return "、".join(parts)
        return "未知功能（未检测到有效脚本或配置）"

    def _get_risk_level(self) -> tuple:
        """获取风险等级和结论"""
        score = self.risk_score
        if score <= 20:
            return "🟢 安全", "✅ 可安全安装"
        elif score <= 50:
            return "🟡 需注意", "⚠️ 需确认"
        elif score <= 80:
            return "🟠 高风险", "⚠️ 需确认"
        else:
            return "🔴 危险", "🚫 禁止安装"

    def _format_file_operations(self) -> str:
        """格式化文件操作路径"""
        lines = []
        if self.file_operations["hermes_dir"]:
            # 去重
            unique_ops = list(set(self.file_operations["hermes_dir"]))[:5]
            lines.append(f"~/.hermes/ 目录: {len(unique_ops)}项")
            for op in unique_ops[:3]:
                lines.append(f"  └ {op}")
            if len(unique_ops) > 3:
                lines.append(f"  └ ... 等{len(unique_ops)}项")
        if self.file_operations["other"]:
            unique_other = list(set(self.file_operations["other"]))[:3]
            lines.append(f"其他路径: {len(unique_other)}项")
            for op in unique_other:
                lines.append(f"  └ {op}")
        if not lines:
            lines.append("无特殊文件操作")
        return "\n".join(lines)

    def _format_network(self) -> str:
        """格式化网络请求信息"""
        if self.network_requests["has"]:
            targets = self.network_requests.get("targets", [])
            if targets:
                unique_targets = list(set(targets))[:5]
                target_str = ", ".join(unique_targets)
                return f"有 ({target_str})"
            return "有"
        return "无"

    def _format_tools(self) -> str:
        """格式化工具列表"""
        if not self.tool_summary:
            return "无"
        return ", ".join(sorted(self.tool_summary))

    def _format_check(self, condition: bool, label_pass: str, label_fail: str = "") -> str:
        """格式化检测复选框 - 通过时显示✅+正面描述，失败时显示❌+负面描述"""
        if condition:
            icon = "✅"
            label = label_pass
        else:
            icon = "❌"
            label = label_fail if label_fail else label_pass
        return f"{icon} {label}"

    def report(self):
        """生成完整安检报告"""
        risk_level, conclusion = self._get_risk_level()
        summary = self._summarize()

        # 检测状态（icon + 描述：有风险时显示❌和负面描述，安全时显示✅和正面描述）
        skill_md_pass = self.skill_md_format_ok and len(self.skill_md_issues) == 0
        syscall_pass = not self.has_dangerous_syscalls
        config_pass = not self.has_config_tamper
        network_pass = not self.has_network_exfil
        encoding_pass = not self.has_suspicious_encoding

        # 风险项明细
        risk_details = ""
        if self.risk_items:
            risk_lines = []
            for item in self.risk_items:
                risk_lines.append(f"  ● [+{item['score']}分] {item['desc']}")
            risk_details = "\n".join(risk_lines)
        else:
            risk_details = "  无"

        # 脚本信息
        script_info = []
        if self.scripts_count["py"]:
            script_info.append(f"{self.scripts_count['py']}个.py")
        if self.scripts_count["sh"]:
            script_info.append(f"{self.scripts_count['sh']}个.sh")
        if self.scripts_count["js"]:
            script_info.append(f"{self.scripts_count['js']}个.js")
        script_str = ", ".join(script_info) if script_info else "无"

        box_width = 56
        def w(txt):
            """自动折行"""
            return textwrap.fill(txt, width=box_width - 4)

        lines = [
            "╔" + "═" * (box_width - 2) + "╗",
            "║  PluginGuard v1.0  安检报告" + " " * (box_width - 32) + "║",
            "╠" + "═" * (box_width - 2) + "╣",
            "║" + " " * (box_width - 2) + "║",
            "║  📋 功能分析" + " " * (box_width - 18) + "║",
            "║  ─────────────────────────" + " " * (box_width - 32) + "║",
            f"║  名称: {self.skill_meta['name'] or self.target_name:<{box_width-12}}║",
            f"║  类型: {self.skill_meta['type']:<{box_width-12}}║",
            f"║  一句话: {summary:<{box_width-14}}║",
        ]

        # 工具可能很长，需要换行
        tools_str = self._format_tools()
        if len(tools_str) > box_width - 18:
            # 分成多行
            lines.append(f"║  调用工具:" + " " * (box_width - 16) + "║")
            wrapped_tools = textwrap.wrap(tools_str, width=box_width - 6)
            for wt in wrapped_tools:
                lines.append(f"║    {wt:<{box_width-6}}║")
        else:
            lines.append(f"║  调用工具: {tools_str:<{box_width-16}}║")

        # 文件操作
        file_op_str = self._format_file_operations().split("\n")
        lines.append(f"║  文件操作:" + " " * (box_width - 16) + "║")
        for fo in file_op_str:
            lines.append(f"║    {fo:<{box_width-6}}║")

        network_str = self._format_network()
        lines.append(f"║  网络请求: {network_str:<{box_width-16}}║")
        lines.append(f"║  脚本: {script_str:<{box_width-12}}║")
        lines.append("║" + " " * (box_width - 2) + "║")

        # 安全评估
        lines.append("║  🛡️ 安全评估" + " " * (box_width - 18) + "║")
        lines.append("║  ─────────────────────────" + " " * (box_width - 32) + "║")
        lines.append(f"║  风险等级: {risk_level:<{box_width-16}}║")
        lines.append(f"║  风险评分: {self.risk_score}/100" + " " * (box_width - 22) + "║")
        lines.append("║" + " " * (box_width - 2) + "║")

        # 检测清单（根据通过/失败使用不同文案）
        lines.append(f"║  {self._format_check(skill_md_pass, 'SKILL.md 格式正常'):<{box_width-4}}║")
        lines.append(f"║  {self._format_check(syscall_pass, '无危险系统调用', '发现危险系统调用'):<{box_width-4}}║")
        lines.append(f"║  {self._format_check(config_pass, '无配置篡改', '发现配置篡改'):<{box_width-4}}║")
        lines.append(f"║  {self._format_check(network_pass, '无网络外联', '发现网络外联'):<{box_width-4}}║")
        lines.append(f"║  {self._format_check(encoding_pass, '无可疑编码/绕过', '发现可疑编码/绕过'):<{box_width-4}}║")
        lines.append("║" + " " * (box_width - 2) + "║")

        # 风险明细
        lines.append("║  📌 风险项明细:" + " " * (box_width - 22) + "║")
        if risk_details.strip() == "无":
            lines.append(f"║   无" + " " * (box_width - 9) + "║")
        else:
            risk_display_lines = risk_details.split("\n")
            for rd_line in risk_display_lines:
                # 长行折行
                if len(rd_line) > box_width - 6:
                    wrapped_rd = textwrap.wrap(rd_line, width=box_width - 6)
                    for wr in wrapped_rd:
                        lines.append(f"║  {wr:<{box_width-4}}║")
                else:
                    lines.append(f"║  {rd_line:<{box_width-4}}║")
        lines.append("║" + " " * (box_width - 2) + "║")

        # 结论
        lines.append(f"║ 💡 结论: {conclusion}" + " " * (box_width - 18) + "║")
        lines.append("╚" + "═" * (box_width - 2) + "╝")

        return "\n".join(lines)


# ============================================================
# GitHub 下载支持
# ============================================================

def clone_github_repo(url: str) -> str:
    """克隆 GitHub 仓库到临时目录，返回路径"""
    # 验证 URL
    if not re.match(r'^https?://github\.com/', url):
        print(f"错误: 不是有效的 GitHub URL: {url}", file=sys.stderr)
        sys.exit(1)

    temp_dir = tempfile.mkdtemp(prefix="plugin_guard_")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, temp_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"错误: Git clone 失败: {result.stderr.strip()}", file=sys.stderr)
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.exit(1)
        print(f"[Info] 已克隆仓库到临时目录: {temp_dir}", file=sys.stderr)
        return temp_dir
    except FileNotFoundError:
        print("错误: 未找到 git 命令，请先安装 Git", file=sys.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("错误: Git clone 超时（120秒）", file=sys.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)


# ============================================================
# 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="PluginGuard v1.0 — Hermes 插件安全检测与功能分析工具"
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    scan_parser = subparsers.add_parser("scan", help="扫描插件/技能目录或 GitHub URL")
    scan_parser.add_argument("target", help="插件路径或 GitHub URL")

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        sys.exit(1)

    target = args.target

    # 判断是本地路径还是 GitHub URL
    is_github = target.startswith("http://github.com/") or \
                target.startswith("https://github.com/")

    temp_dir = None
    try:
        if is_github:
            temp_dir = clone_github_repo(target)
            scan_path = temp_dir
        else:
            scan_path = target

        scanner = PluginScanner(scan_path)
        scanner.run()
        report = scanner.report()
        print(report)

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
