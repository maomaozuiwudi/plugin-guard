"""PluginGuard 批量扫描 - 扫描 ecc-imports 全部技能"""
import subprocess, sys, os, json, time
from pathlib import Path

SCAN_SCRIPT = Path(__file__).parent / "scan.py"
TARGET_DIR = Path.home() / "AppData/Local/hermes/skills/ecc-imports"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def scan_one(skill_name):
    """扫描单个 skill，返回 (名称, 分数, 等级, 结论, 完整输出)"""
    skill_path = TARGET_DIR / skill_name
    if not skill_path.exists():
        return skill_name, -1, "路径不存在", "", ""

    try:
        r = subprocess.run(
            [sys.executable, str(SCAN_SCRIPT), "scan", str(skill_path)],
            capture_output=True, text=True, timeout=60
        )
        output = r.stdout
        # 提取关键信息
        risk_level = ""
        risk_score = -1
        conclusion = ""
        risk_count = 0

        for line in output.split("\n"):
            ls = line.strip()
            if "风险等级:" in ls:
                risk_level = ls.split("风险等级:")[-1].strip()
            elif "风险评分:" in ls:
                try:
                    score_str = ls.split("风险评分:")[-1].strip().split("/")[0].strip()
                    risk_score = int(score_str)
                except:
                    pass
            elif "结论:" in ls:
                conclusion = ls.split("结论:")[-1].strip()
            elif "+" in ls and "分]" in ls:
                risk_count += 1

        return skill_name, risk_score, risk_level, conclusion, output, risk_count
    except subprocess.TimeoutExpired:
        return skill_name, -1, "超时", "扫描超时(>60s)", "", 0
    except Exception as e:
        return skill_name, -1, "错误", str(e), "", 0

def main():
    skills = sorted([d.name for d in TARGET_DIR.iterdir() if d.is_dir()])
    total = len(skills)
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║  PluginGuard  ecc-imports  批量安检报告   ║{RESET}")
    print(f"{BOLD}{CYAN}╠══════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}{CYAN}║  技能总数: {total:<3}                           ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════╝{RESET}")
    print()

    results = []
    risky_skills = []
    clean_skills = []
    error_skills = []

    for i, skill in enumerate(skills, 1):
        print(f"[{i}/{total}] 扫描 {skill} ... ", end="", flush=True)
        result = scan_one(skill)
        results.append(result)

        name, score, level, conclusion, output, risk_count = result

        if score == -1:
            print(f"{RED}✗ {conclusion}{RESET}")
            error_skills.append((name, conclusion))
        elif score <= 20:
            print(f"{GREEN}✅ 安全({score}分){RESET}")
            clean_skills.append((name, score))
        elif score <= 50:
            print(f"{YELLOW}⚠️ 需注意({score}分){RESET}")
            risky_skills.append((name, score, level, conclusion, risk_count))
        elif score <= 80:
            print(f"{RED}🔴 高风险({score}分){RESET}")
            risky_skills.append((name, score, level, conclusion, risk_count))
        else:
            print(f"{RED}🔴 危险({score}分){RESET}")
            risky_skills.append((name, score, level, conclusion, risk_count))

    # ========== 汇总报告 ==========
    print(f"\n{BOLD}{'='*56}{RESET}")
    print(f"{BOLD}          📊 ecc-imports 安检汇总报告{RESET}")
    print(f"{BOLD}{'='*56}{RESET}")

    print(f"\n  总计: {total} 个技能")
    print(f"  {GREEN}🟢 安全: {len(clean_skills)} 个{RESET}")
    print(f"  {YELLOW}🟡 需注意: {len([s for s in risky_skills if s[1] <= 50])} 个{RESET}")
    print(f"  {RED}🔴 高风险: {len([s for s in risky_skills if s[1] > 50])} 个{RESET}")
    print(f"  {RED}✗ 错误: {len(error_skills)} 个{RESET}")

    if clean_skills:
        print(f"\n{GREEN}✅ 安全技能 ({len(clean_skills)}个):{RESET}")
        for name, score in sorted(clean_skills, key=lambda x: x[1]):
            print(f"  {GREEN}{name:<35} {score:>3}/100{RESET}")

    if risky_skills:
        print(f"\n{YELLOW}⚠️  需注意 / 高风险 ({len(risky_skills)}个):{RESET}")
        for name, score, level, conclusion, risk_count in sorted(risky_skills, key=lambda x: -x[1]):
            icon = "🟡" if score <= 50 else "🔴"
            color = YELLOW if score <= 50 else RED
            print(f"  {color}{icon} {name:<35} {score:>3}/100 [{level}] 风险项:{risk_count}{RESET}")

    if error_skills:
        print(f"\n{RED}✗ 扫描失败的:{RESET}")
        for name, err in error_skills:
            print(f"  {RED}  {name}: {err}{RESET}")

    # 输出风险详情
    for name, score, level, conclusion, risk_count in risky_skills:
        for _, _, _, _, output, _ in results:
            if _ == name:
                # 提取风险明细部分
                in_risk = False
                detail_lines = []
                for line in output.split("\n"):
                    if "📌 风险项明细:" in line:
                        in_risk = True
                        continue
                    if in_risk:
                        if "💡 结论:" in line:
                            break
                        if line.strip() and "无" not in line:
                            detail_lines.append(line.strip())
                if detail_lines:
                    print(f"\n{color}📋 {name} 风险详情:{RESET}")
                    for dl in detail_lines:
                        print(f"   {dl}")

    avg_score = sum(r[1] for r in results if r[1] >= 0) / max(len([r for r in results if r[1] >= 0]), 1)
    print(f"\n{BOLD}{'='*56}{RESET}")
    print(f"  整体安全评分: {CYAN}{avg_score:.1f}/100 (越低越安全){RESET}")
    print(f"  {GREEN}结论: ecc-imports 整体{'🟢 安全' if avg_score <= 10 else '🟡 基本安全' if avg_score <= 20 else '🔴 需审查'}{RESET}")
    print(f"{BOLD}{'='*56}{RESET}")

if __name__ == "__main__":
    main()
