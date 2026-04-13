#!/usr/bin/env python3
"""
数据库结构文档生成器
读取现有数据库，输出完整的表结构文档（Markdown格式）
"""

import mysql.connector
from mysql.connector import Error
from datetime import datetime
from typing import List, Dict
import os
import sys

# 导入现有配置文件
try:
    from config import DB_CONFIG, VERBOSE
except ImportError:
    print("[ERROR] 无法导入 config.py，请确保文件存在于同一目录")
    sys.exit(1)

# 字段类型说明映射
FIELD_DESC_MAP = {
    'sid': '规则唯一标识符，Snort规则的标准ID',
    'msg': '威胁描述信息，用于告警输出',
    'classtype': '攻击分类，如 attempted-admin、trojan-activity',
    'rule_text': '完整的原始规则文本',
    'rule_hash': 'MD5哈希值，用于规则去重和快速查找',
    'protocol': '协议类型：tcp、udp、icmp、ip',
    'source_ip': '源IP地址（支持CIDR、变量如 $HOME_NET）',
    'source_port': '源端口（支持单个端口、列表如 [21,25,443]）',
    'direction': '流量方向：->（单向）、<>（双向）、<-（反向）',
    'dest_ip': '目标IP地址',
    'dest_port': '目标端口',
    'flow': '流方向：to_client、to_server、established',
    'metadata': '元数据，包含策略、引擎信息等',
    'reference': '外部参考链接（如CVE编号、Bugtraq ID）',
    'rev': '规则版本号',
    'severity': '严重程度：1=高、2=中、3=低',
    'enabled': '启用状态：1=启用、0=禁用',
    'created_at': '创建时间',
    'updated_at': '最后更新时间',
    'content_pattern': '需要匹配的字节序列（十六进制或文本）',
    'content_type': '匹配类型：content、nocase（忽略大小写）、regex（正则）',
    'offset_val': '从Payload开始偏移多少字节开始匹配',
    'depth_val': '从偏移位置开始检查的最大字节数',
    'within_val': '前一个匹配到当前匹配的最大距离',
    'distance_val': '前一个匹配到当前匹配的最小距离',
    'is_negated': '是否取反匹配（!content）',
    'position_order': '多个content的匹配顺序',
    'alert_id': '告警唯一ID',
    'timestamp': '告警发生时间',
    'src_ip': '源IP地址',
    'src_port': '源端口号',
    'dst_ip': '目标IP地址',
    'dst_port': '目标端口号',
    'payload_preview': 'Payload预览（前256字节）',
    'matched_content': '匹配到的content内容',
    'processed': '处理状态：0=未处理、1=已处理',
}

# 表的中文描述
TABLE_DESC = {
    'snort_rules': '规则主表 - 存储Snort规则的核心信息，是IDS匹配的主要数据源',
    'rule_contents': '规则内容匹配表 - 存储规则的content匹配条件，用于Payload深度检测',
    'snort_alerts': '告警表 - 记录所有触发的告警事件，用于安全分析和响应',
    'rule_stats': '规则分类统计视图 - 按classtype统计规则数量和平均严重程度',
}


def log(msg: str, level: str = 'INFO'):
    """日志输出函数"""
    if VERBOSE:
        print(f"[{level}] {msg}")


class DatabaseDocGenerator:
    """数据库文档生成器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.conn = None
        self.cursor = None
    
    def connect(self) -> bool:
        """连接数据库"""
        try:
            self.conn = mysql.connector.connect(**self.config)
            self.cursor = self.conn.cursor()
            log(f"已连接到数据库: {self.config['database']}")
            return True
        except Error as e:
            print(f"[ERROR] 数据库连接失败: {e}")
            return False
    
    def close(self):
        """关闭连接"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
    
    def get_all_tables(self) -> List[str]:
        """获取所有用户表"""
        self.cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = %s 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name
        """, (self.config['database'],))
        return [row[0] for row in self.cursor.fetchall()]
    
    def get_all_views(self) -> List[str]:
        """获取所有视图"""
        self.cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = %s 
            AND table_type = 'VIEW'
            ORDER BY table_name
        """, (self.config['database'],))
        return [row[0] for row in self.cursor.fetchall()]
    
    def get_table_columns(self, table_name: str) -> List[Dict]:
        """获取表的列信息"""
        self.cursor.execute("""
            SELECT 
                column_name,
                column_type,
                is_nullable,
                column_key,
                column_default,
                extra,
                data_type,
                character_maximum_length,
                numeric_precision,
                numeric_scale
            FROM information_schema.columns 
            WHERE table_schema = %s AND table_name = %s
            ORDER BY ordinal_position
        """, (self.config['database'], table_name))
        
        columns = []
        for row in self.cursor.fetchall():
            col = {
                'name': row[0],
                'type': row[1],
                'nullable': row[2],
                'key': row[3] or '',
                'default': row[4],
                'extra': row[5] or '',
                'data_type': row[6],
                'max_length': row[7],
                'numeric_precision': row[8],
                'numeric_scale': row[9],
            }
            columns.append(col)
        return columns
    
    def get_table_indexes(self, table_name: str) -> List[Dict]:
        """获取表的索引信息"""
        self.cursor.execute("""
            SELECT 
                index_name,
                non_unique,
                column_name,
                seq_in_index
            FROM information_schema.statistics 
            WHERE table_schema = %s AND table_name = %s
            ORDER BY index_name, seq_in_index
        """, (self.config['database'], table_name))
        
        indexes = {}
        for row in self.cursor.fetchall():
            idx_name = row[0]
            if idx_name not in indexes:
                indexes[idx_name] = {
                    'name': idx_name,
                    'unique': row[1] == 0,
                    'columns': []
                }
            indexes[idx_name]['columns'].append(row[2])
        
        return list(indexes.values())
    
    def get_table_foreign_keys(self, table_name: str) -> List[Dict]:
        """获取表的外键信息"""
        self.cursor.execute("""
            SELECT 
                constraint_name,
                column_name,
                referenced_table_name,
                referenced_column_name
            FROM information_schema.key_column_usage 
            WHERE table_schema = %s 
            AND table_name = %s 
            AND referenced_table_name IS NOT NULL
        """, (self.config['database'], table_name))
        
        fks = []
        for row in self.cursor.fetchall():
            fks.append({
                'name': row[0],
                'column': row[1],
                'ref_table': row[2],
                'ref_column': row[3]
            })
        return fks
    
    def get_table_row_count(self, table_name: str) -> int:
        """获取表的行数"""
        try:
            self.cursor.execute(f"SELECT COUNT(*) FROM `{table_name}`")
            return self.cursor.fetchone()[0]
        except Error:
            return 0
    
    def get_table_engine(self, table_name: str) -> str:
        """获取表的存储引擎"""
        try:
            self.cursor.execute("""
                SELECT engine 
                FROM information_schema.tables 
                WHERE table_schema = %s AND table_name = %s
            """, (self.config['database'], table_name))
            result = self.cursor.fetchone()
            return result[0] if result else 'Unknown'
        except Error:
            return 'Unknown'
    
    def get_table_charset(self, table_name: str) -> str:
        """获取表的字符集"""
        try:
            self.cursor.execute("""
                SELECT table_collation 
                FROM information_schema.tables 
                WHERE table_schema = %s AND table_name = %s
            """, (self.config['database'], table_name))
            result = self.cursor.fetchone()
            return result[0] if result else 'Unknown'
        except Error:
            return 'Unknown'
    
    def get_field_description(self, field_name: str) -> str:
        """获取字段的描述说明"""
        if field_name in FIELD_DESC_MAP:
            return FIELD_DESC_MAP[field_name]
        
        # 尝试模糊匹配（去掉前缀后缀）
        base_name = field_name.replace('_val', '').replace('_pattern', '')
        if base_name in FIELD_DESC_MAP:
            return FIELD_DESC_MAP[base_name]
        
        return "待补充说明"
    
    def generate_markdown_report(self, output_file: str = "database_schema_doc.md") -> bool:
        """生成 Markdown 格式的数据库文档"""
        
        log("正在生成数据库文档...")
        
        # 获取所有表和视图
        tables = self.get_all_tables()
        views = self.get_all_views()
        
        if not tables and not views:
            log("数据库中没有找到任何表", 'WARNING')
            return False
        
        # 生成报告内容
        content = []
        
        # 标题
        content.append(f"# IDS 数据库表结构文档\n")
        content.append(f"> 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        content.append(f"> 数据库：`{self.config['database']}`\n")
        content.append(f"> 主机：`{self.config['host']}:{self.config['port']}`\n")
        content.append("---\n")
        
        # 目录
        content.append("## 目录\n")
        for table in tables:
            content.append(f"- [{table}](#{table})")
        for view in views:
            content.append(f"- [{view}](#{view})（视图）")
        content.append("")
        
        # 统计概览
        content.append("## 统计概览\n")
        content.append("| 项目 | 数量 |")
        content.append("|------|------|")
        content.append(f"| 数据表 | {len(tables)} |")
        content.append(f"| 视图 | {len(views)} |")
        
        total_rows = 0
        for table in tables:
            total_rows += self.get_table_row_count(table)
        content.append(f"| 总记录数 | {total_rows:,} |")
        content.append("")
        
        # 表关系图
        content.append("### 表关系图\n")
        content.append("```")
        content.append("┌─────────────────────────────────────────────────────────────────┐")
        content.append("│                         snort_rules                             │")
        content.append("│  (规则主表 - 核心数据)                                          │")
        content.append("│      sid (PK)                                                   │")
        content.append("└─────────────────────────────────────────────────────────────────┘")
        content.append("                              │")
        content.append("                              │ FOREIGN KEY (sid)")
        content.append("                              ▼")
        content.append("┌─────────────────────────────────────────────────────────────────┐")
        content.append("│                        rule_contents                            │")
        content.append("│  (内容匹配表 - 扩展数据)                                        │")
        content.append("│      sid (FK → snort_rules.sid)                                 │")
        content.append("└─────────────────────────────────────────────────────────────────┘")
        content.append("")
        content.append("┌─────────────────────────────────────────────────────────────────┐")
        content.append("│                        snort_alerts                             │")
        content.append("│  (告警表 - 日志数据)                                            │")
        content.append("│      sid (FK → snort_rules.sid)                                 │")
        content.append("└─────────────────────────────────────────────────────────────────┘")
        content.append("```\n")
        
        # 生成每个表的文档
        for table_name in tables:
            content.extend(self._generate_table_doc(table_name))
        
        # 生成每个视图的文档
        for view_name in views:
            content.extend(self._generate_view_doc(view_name))
        
        # 写入文件
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
            log(f"文档已生成: {output_file}")
            return True
        except Exception as e:
            log(f"写入文件失败: {e}", 'ERROR')
            return False
    
    def _generate_table_doc(self, table_name: str) -> List[str]:
        """生成单个表的文档"""
        content = []
        
        # 表标题
        content.append(f"## `{table_name}`\n")
        
        # 表基本信息
        row_count = self.get_table_row_count(table_name)
        engine = self.get_table_engine(table_name)
        charset = self.get_table_charset(table_name)
        
        content.append("### 基本信息\n")
        content.append("| 属性 | 值 |")
        content.append("|------|-----|")
        content.append(f"| 说明 | {TABLE_DESC.get(table_name, f'{table_name} 数据表')} |")
        content.append(f"| 记录数 | {row_count:,} |")
        content.append(f"| 存储引擎 | {engine} |")
        content.append(f"| 字符集/排序规则 | {charset} |")
        content.append("")
        
        # 字段列表
        columns = self.get_table_columns(table_name)
        content.append("### 字段定义\n")
        content.append("| 字段名 | 类型 | 允许空 | 默认值 | 约束 | 说明 |")
        content.append("|--------|------|--------|--------|------|------|")
        
        for col in columns:
            # 构建类型字符串
            col_type = col['type']
            if col['max_length'] and col['data_type'] in ('varchar', 'char'):
                col_type = f"{col['data_type']}({col['max_length']})"
            
            # 约束
            constraints = []
            if col['key'] == 'PRI':
                constraints.append("PRIMARY KEY")
            elif col['key'] == 'UNI':
                constraints.append("UNIQUE")
            elif col['key'] == 'MUL':
                constraints.append("INDEX")
            
            if col['extra']:
                constraints.append(col['extra'].upper())
            
            constraint_str = ', '.join(constraints) if constraints else '-'
            
            # 默认值
            default_val = col['default']
            if default_val is not None:
                if default_val == 'CURRENT_TIMESTAMP':
                    default_str = 'CURRENT_TIMESTAMP'
                else:
                    default_str = f"'{default_val}'"
            else:
                default_str = 'NULL'
            
            # 允许空
            nullable = 'YES' if col['nullable'] == 'YES' else 'NO'
            
            # 获取字段说明
            description = self.get_field_description(col['name'])
            
            content.append(f"| `{col['name']}` | {col_type} | {nullable} | {default_str} | {constraint_str} | {description} |")
        
        content.append("")
        
        # 索引信息
        indexes = self.get_table_indexes(table_name)
        if indexes:
            content.append("### 索引\n")
            content.append("| 索引名 | 类型 | 字段 |")
            content.append("|--------|------|------|")
            
            for idx in indexes:
                # 跳过 PRIMARY 索引（已在字段中标注）
                if idx['name'] == 'PRIMARY':
                    continue
                idx_type = "UNIQUE" if idx['unique'] else "INDEX"
                columns_str = ", ".join([f"`{c}`" for c in idx['columns']])
                content.append(f"| `{idx['name']}` | {idx_type} | {columns_str} |")
            content.append("")
        
        # 外键信息
        fks = self.get_table_foreign_keys(table_name)
        if fks:
            content.append("### 外键约束\n")
            content.append("| 约束名 | 字段 | 引用表 | 引用字段 |")
            content.append("|--------|------|--------|----------|")
            
            for fk in fks:
                content.append(f"| `{fk['name']}` | `{fk['column']}` | `{fk['ref_table']}` | `{fk['ref_column']}` |")
            content.append("")
        
        content.append("---\n")
        
        return content
    
    def _generate_view_doc(self, view_name: str) -> List[str]:
        """生成视图的文档"""
        content = []
        
        # 视图标题
        content.append(f"## `{view_name}`（视图）\n")
        
        # 视图说明
        desc = TABLE_DESC.get(view_name, f"{view_name} 数据库视图")
        content.append(f"**说明**：{desc}\n")
        
        # 获取视图定义
        try:
            self.cursor.execute(f"SHOW CREATE VIEW {view_name}")
            result = self.cursor.fetchone()
            if result:
                content.append("### 视图定义\n")
                content.append("```sql")
                content.append(result[1])
                content.append("```\n")
        except Error:
            pass
        
        content.append("---\n")
        
        return content
    
    def print_console_summary(self):
        """在控制台打印简要摘要"""
        print("\n" + "=" * 60)
        print("数据库结构摘要")
        print("=" * 60)
        
        tables = self.get_all_tables()
        views = self.get_all_views()
        
        print(f"数据库: {self.config['database']}")
        print(f"主机: {self.config['host']}:{self.config['port']}")
        print(f"数据表数量: {len(tables)}")
        print(f"视图数量: {len(views)}")
        print()
        
        for table in tables:
            row_count = self.get_table_row_count(table)
            columns = self.get_table_columns(table)
            print(f"  📊 {table}: {row_count:,} 条记录, {len(columns)} 个字段")
        
        print()


def main():
    """主函数"""
    print(f"[INFO] 使用配置文件: config.py")
    print(f"[INFO] 目标数据库: {DB_CONFIG['database']} @ {DB_CONFIG['host']}")
    
    generator = DatabaseDocGenerator(DB_CONFIG)
    
    if not generator.connect():
        print("[ERROR] 无法连接到数据库")
        return 1
    
    # 打印控制台摘要
    generator.print_console_summary()
    
    # 生成 Markdown 文档
    output_file = "database_info.md"
    success = generator.generate_markdown_report(output_file)
    
    generator.close()
    
    if success:
        print(f"\n[SUCCESS] 文档已保存至: {os.path.abspath(output_file)}")
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())