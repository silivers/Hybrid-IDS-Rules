#!/usr/bin/env python3
"""规则导入模块 - 从配置文件读取规则文件路径"""

import os
import sys
from config import RULES_FILE, BATCH_SIZE, VERBOSE
from database import db
from parser import parser as rule_parser


def log(msg: str, level: str = 'INFO'):
    if VERBOSE:
        print(f"[{level}] {msg}")


def import_rules_file(rules_file: str) -> dict:
    """导入规则文件到数据库"""
    stats = {'total': 0, 'imported': 0, 'failed': 0}
    
    log(f"开始解析规则文件: {rules_file}")
    
    # 解析规则
    rules = rule_parser.parse_file(rules_file)
    stats['total'] = len(rules)
    
    if not rules:
        log("未找到有效规则", 'WARNING')
        return stats
    
    log(f"解析完成，共 {len(rules)} 条规则，开始导入数据库...")
    
    # 批量导入
    batch = []
    for i, rule in enumerate(rules, 1):
        batch.append(rule)
        
        if len(batch) >= BATCH_SIZE:
            success, failed = db.insert_rules_batch(batch)
            stats['imported'] += success
            stats['failed'] += failed
            db.commit()
            log(f"已导入 {stats['imported']} / {stats['total']} 条规则...")
            batch = []
    
    # 导入剩余规则
    if batch:
        success, failed = db.insert_rules_batch(batch)
        stats['imported'] += success
        stats['failed'] += failed
        db.commit()
    
    return stats


def print_summary(stats: dict):
    """打印导入摘要"""
    print("\n" + "=" * 60)
    print("导入完成摘要")
    print("=" * 60)
    print(f"  解析到规则数: {stats['total']}")
    print(f"  成功导入数: {stats['imported']}")
    print(f"  失败数: {stats['failed']}")
    
    # 数据库统计
    total = db.get_rule_count()
    print(f"\n数据库当前规则总数: {total}")
    
    classtype_stats = db.get_classtype_stats()
    if classtype_stats:
        print("\n规则分类 TOP 10:")
        for row in classtype_stats:
            print(f"    {row[0]}: {row[1]} 条")


def main():
    """主函数"""
    # 检查规则文件是否存在
    if not os.path.isfile(RULES_FILE):
        log(f"规则文件不存在: {RULES_FILE}", 'ERROR')
        return 1
    
    # 创建数据库
    if not db.create_database():
        return 1
    
    # 连接数据库
    if not db.connect():
        return 1
    
    # 创建表
    if not db.create_tables():
        db.close()
        return 1
    
    # 导入规则
    stats = import_rules_file(RULES_FILE)
    print_summary(stats)
    
    db.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())