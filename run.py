import requests
from time import sleep
import re

# -----------------------
# 下载规则列表
# -----------------------
FILTER_URLS = [
    ("comads", "https://raw.githubusercontent.com/jackszb/comads/main/comads.txt"),
    ("ppfeufer", "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist"),
    ("myadlist", "https://raw.githubusercontent.com/jackszb/MyAdList/main/dnsblock.txt"),
    ("217heidai", "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"),
    ("mullvad", "https://raw.githubusercontent.com/cogwheel0/mullvad-to-adguard/main/adguard/all/adblock.txt"),
]

OUTPUT_FILE = "merged_rules.txt"
SKIP_LOG_THRESHOLD = 100  # 剔除行数低于此值就不显示详细剔除信息

# -----------------------
# 精准剔除规则函数
# -----------------------
def is_supported_rule(line: str) -> bool:
    line = line.strip()
    if not line or line.startswith(("!", "#")):
        return False
    lower_line = line.lower()
    # 保留 0.0.0.0 hosts 行
    if lower_line.startswith("0.0.0.0 "):
        return True
    # 保留正则规则（以 / 开头和结尾）
    if line.startswith("/") and line.endswith("/"):
        return True
    # 剔除 IP 地址类型的规则
    if re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}", line):
        return False
    # 剔除带端口或路径的规则
    if ":" in line or "/path" in line or "$dnsrewrite" in line:
        return False
    # 保留特殊描述符规则（如 @@、||、| 等）
    if re.match(r"(^@@|^\|\||^\||\^|\*|\$)", line):
        return True
    # 保留域名规则（小写字母域名匹配）
    if re.match(r"^[a-z0-9]([a-z0-9\.-]*[a-z0-9])?$", lower_line):
        return True
    return False

# -----------------------
# 下载并合并规则
# -----------------------
all_rules = set()
for name, url in FILTER_URLS:
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            lines = [line.strip() for line in response.text.splitlines() if line.strip()]
            total_count = len(lines)
            rules = {line.lower() for line in lines if is_supported_rule(line)}  # 剔除不支持的规则
            filtered_count = len(rules)
            removed_count = total_count - filtered_count
            all_rules |= rules
            # 显示下载的规则信息
            if removed_count >= SKIP_LOG_THRESHOLD:
                print(f"{name}: 总行数={total_count}, 保留={filtered_count}, 剔除={removed_count}")
            else:
                print(f"{name}: 总行数={total_count}, 保留={filtered_count}")
            break
        except requests.RequestException as error:
            print(f"{name} 下载出错: {error}, 重试 {attempt + 1}/3")
            sleep(2 * (attempt + 1))
    else:
        print(f"{name} 下载失败，已跳过")

# -----------------------
# 去除空行并写入文件
# -----------------------
# 清理空行并确保规则无重复
all_rules = {rule for rule in all_rules if rule.strip()}  # 去掉空行
all_rules = sorted(all_rules)  # 排序
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(all_rules))

print(f"合并去重后总规则数: {len(all_rules)}")
