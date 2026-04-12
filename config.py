#!/usr/bin/env python3
"""配置文件"""

# ========== 数据库配置 ==========
DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '1234',
    'database': 'snort_db'
}

# ========== 规则文件配置 ==========
RULES_FILE = 'snort3-community.rules'  # 规则文件路径

# ========== 导入配置 ==========
BATCH_SIZE = 500                         # 批量插入数量
VERBOSE = True                           # 是否输出详细日志

# ========== 严重程度映射 ==========
SEVERITY_MAP = {
    'high': ['attempted-admin', 'attempted-user', 'successful-admin', 
             'successful-user', 'trojan-activity', 'botnet-cc', 
             'backdoor', 'shellcode-detect', 'virus'],
    'medium': ['attempted-dos', 'attempted-recon', 'protocol-command-decode']
}