#!/usr/bin/env python3
"""Snort 规则解析器 - 支持完整规则语法"""

import re
import hashlib
from typing import Optional, List, Dict, Any, Tuple
from models import SnortRule
from config import SEVERITY_MAP


def log(msg: str, level: str = 'INFO'):
    if VERBOSE:
        print(f"[{level}] {msg}")


class SnortRuleParser:
    """Snort 规则解析器"""
    
    # 协议列表
    PROTOCOLS = {'tcp', 'udp', 'icmp', 'ip', 'tcp/udp'}
    
    def __init__(self):
        self.stats = {'parsed': 0, 'errors': 0}
    
    def get_severity_by_classtype(self, classtype: Optional[str]) -> int:
        """根据classtype获取严重程度"""
        if not classtype:
            return 3
        
        classtype_lower = classtype.lower()
        
        for keyword in SEVERITY_MAP['high']:
            if keyword in classtype_lower:
                return 1
        
        for keyword in SEVERITY_MAP['medium']:
            if keyword in classtype_lower:
                return 2
        
        return 3
    
    def parse_ip_port(self, token: str) -> Tuple[Optional[str], Optional[str]]:
        """解析 IP:端口 格式，支持端口列表如 [21,25,443]"""
        if not token:
            return None, None
        
        # 处理 any 和变量
        if token == 'any' or token.startswith('$'):
            return token, None
        
        # 检查是否包含端口列表
        if '[' in token and ']' in token:
            # 格式: IP [port1,port2,...] 或 [port1,port2,...]
            match = re.match(r'(\S+)?\s*(\[.*?\])', token)
            if match:
                ip = match.group(1) if match.group(1) else 'any'
                port_list = match.group(2)
                return ip, port_list
        
        # 处理 IP:PORT 格式
        if ':' in token and not token.startswith('['):
            parts = token.split(':', 1)
            return parts[0], parts[1] if parts[1] else None
        
        # 只有 IP
        return token, None
    
    def parse_rule_header(self, line: str) -> Optional[Tuple]:
        """解析规则头部：action protocol src src_port direction dst dst_port"""
        
        # 移除规则选项部分
        header_part = line
        options_part = ""
        
        # 查找规则选项开始位置
        paren_pos = line.find('(')
        if paren_pos != -1:
            header_part = line[:paren_pos].strip()
            options_part = line[paren_pos+1:-1].strip() if line.endswith(')') else line[paren_pos+1:].strip()
        
        # 分割头部字段
        parts = header_part.split()
        if len(parts) < 6:
            return None
        
        action = parts[0]
        protocol = parts[1]
        
        # 查找方向符号的位置
        direction_idx = -1
        for i, part in enumerate(parts):
            if part in ['->', '<>', '<-']:
                direction_idx = i
                break
        
        if direction_idx == -1 or direction_idx < 2 or direction_idx >= len(parts) - 1:
            return None
        
        # 源部分（可能包含多个字段，如 IP 和端口列表）
        src_parts = parts[2:direction_idx]
        if len(src_parts) == 1:
            src_ip, src_port = self.parse_ip_port(src_parts[0])
        elif len(src_parts) == 2:
            src_ip, src_port = src_parts[0], src_parts[1]
        else:
            src_ip = ' '.join(src_parts[:-1])
            src_port = src_parts[-1]
            src_ip, src_port = self.parse_ip_port(f"{src_ip} {src_port}")
        
        direction = parts[direction_idx]
        
        # 目标部分
        dst_parts = parts[direction_idx+1:]
        if len(dst_parts) == 1:
            dst_ip, dst_port = self.parse_ip_port(dst_parts[0])
        elif len(dst_parts) == 2:
            dst_ip, dst_port = dst_parts[0], dst_parts[1]
        else:
            dst_ip = ' '.join(dst_parts[:-1])
            dst_port = dst_parts[-1]
            dst_ip, dst_port = self.parse_ip_port(f"{dst_ip} {dst_port}")
        
        return (action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_part)
    
    def parse_options(self, options_str: str) -> Dict[str, Any]:
        """解析规则选项部分"""
        options = {}
        contents = []
        
        # 匹配 key:value 或 key:"value"
        pattern = r'(\w+):(?:"([^"]+)"|([^;]+?))(?=;\s*\w+:|$)'
        
        # 处理转义字符
        options_str = options_str.replace('\\;', '\\\\;')
        
        for match in re.finditer(pattern, options_str):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3).strip()
            
            if key == 'content':
                # 解析 content 及其修饰符
                content_item = {
                    'pattern': value,
                    'type': 'content',
                    'negated': False
                }
                
                # 查找后续的修饰符（在同一个分号前）
                remaining = options_str[match.end():]
                for modifier in ['nocase', 'within', 'distance', 'depth', 'offset']:
                    mod_pattern = rf'{modifier}:(\d+)'
                    mod_match = re.search(mod_pattern, remaining[:100])
                    if mod_match and mod_match.start() < remaining.find(';'):
                        if modifier == 'nocase':
                            content_item['type'] = 'nocase'
                        else:
                            content_item[modifier] = int(mod_match.group(1))
                
                contents.append(content_item)
                options['contents'] = contents
            
            elif key == 'msg':
                options['msg'] = value
            elif key == 'sid':
                options['sid'] = int(value)
            elif key == 'rev':
                options['rev'] = int(value)
            elif key == 'classtype':
                options['classtype'] = value
            elif key == 'flow':
                options['flow'] = value
            elif key == 'metadata':
                options['metadata'] = value
            elif key == 'reference':
                options['reference'] = value
            elif key == 'depth':
                options['depth'] = int(value)
            elif key == 'byte_test':
                # 保存 byte_test 信息
                if 'byte_tests' not in options:
                    options['byte_tests'] = []
                options['byte_tests'].append(value)
            elif key == 'service':
                options['service'] = value
        
        return options
    
    def parse_rule(self, line: str) -> Optional[SnortRule]:
        """解析单条 Snort 规则"""
        line = line.strip()
        
        # 跳过注释和空行
        if not line or line.startswith('#'):
            return None
        
        # 检查是否是规则行
        action_match = re.match(r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop)', line)
        if not action_match:
            return None
        
        # 解析规则头部
        header = self.parse_rule_header(line)
        if not header:
            return None
        
        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_str = header
        
        # 解析选项
        options = self.parse_options(options_str)
        
        # 获取 SID（必需）
        if 'sid' not in options:
            return None
        
        # 计算规则哈希
        rule_hash = hashlib.md5(line.encode('utf-8')).hexdigest()
        
        # 确保 direction 是简单的方向符号
        if direction not in ['->', '<>', '<-']:
            # 如果 direction 包含其他内容，尝试提取真正的方向符号
            dir_match = re.search(r'(->|<>|<-)', direction)
            if dir_match:
                direction = dir_match.group(1)
            else:
                direction = '->'  # 默认值
        
        # 创建规则对象
        rule = SnortRule(
            sid=options['sid'],
            msg=options.get('msg', 'Unknown'),
            classtype=options.get('classtype'),
            rule_text=line,
            rule_hash=rule_hash,
            protocol=protocol,
            rev=options.get('rev', 1),
            severity=self.get_severity_by_classtype(options.get('classtype')),
            source_ip=src_ip,
            source_port=src_port,
            direction=direction,
            dest_ip=dst_ip,
            dest_port=dst_port,
            flow=options.get('flow'),
            contents=options.get('contents', []),
            metadata=options.get('metadata'),
            reference=options.get('reference')
        )
        
        self.stats['parsed'] += 1
        return rule
    
    def parse_file(self, filepath: str) -> List[SnortRule]:
        """解析规则文件"""
        rules = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    rule = self.parse_rule(line)
                    if rule:
                        rules.append(rule)
                    elif line.strip() and not line.startswith('#'):
                        # 记录无法解析的行（用于调试）
                        if VERBOSE:
                            log(f"无法解析第 {line_num} 行: {line[:100]}...", 'WARNING')
        except FileNotFoundError:
            print(f"[ERROR] 文件不存在: {filepath}")
            return []
        except Exception as e:
            print(f"[ERROR] 解析失败: {e}")
            return []
        
        return rules


# 导入 VERBOSE
from config import VERBOSE

parser = SnortRuleParser()