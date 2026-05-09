#!/usr/bin/env python3
"""配置文件"""

import os

# ========== 数据库配置（支持环境变量，优先使用环境变量）==========
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '1234'),
    'database': os.getenv('DB_NAME', 'snort_db')
}

# ========== 规则文件配置 ==========
RULES_FILE = os.getenv('RULES_FILE', 'snort3-community.rules')

# ========== 导入配置 ==========
BATCH_SIZE = int(os.getenv('BATCH_SIZE', 500))
VERBOSE = os.getenv('VERBOSE', 'true').lower() == 'true'

# ========== 严重程度映射 ==========
SEVERITY_MAP = {
    'high': ['attempted-admin', 'attempted-user', 'successful-admin', 
             'successful-user', 'trojan-activity', 'botnet-cc', 
             'backdoor', 'shellcode-detect', 'virus'],
    'medium': ['attempted-dos', 'attempted-recon', 'protocol-command-decode']
}