#!/usr/bin/env python3
"""数据库操作模块 - 完整的 IDS 规则匹配数据库"""

import mysql.connector
from mysql.connector import Error
from typing import List, Tuple, Optional, Dict, Any
from config import DB_CONFIG, VERBOSE


def log(msg: str, level: str = 'INFO'):
    if VERBOSE:
        print(f"[{level}] {msg}")


class Database:
    """IDS 数据库管理类"""
    
    def __init__(self):
        self.conn = None
        self.cursor = None
    
    def connect(self) -> bool:
        try:
            self.conn = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.conn.cursor(buffered=True)
            log(f"数据库连接成功: {DB_CONFIG['host']}/{DB_CONFIG['database']}")
            return True
        except Error as e:
            log(f"数据库连接失败: {e}", 'ERROR')
            return False
    
    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
    
    def commit(self):
        if self.conn:
            self.conn.commit()
    
    def create_database(self) -> bool:
        """创建数据库（如果不存在）"""
        try:
            config = DB_CONFIG.copy()
            db_name = config.pop('database')
            conn = mysql.connector.connect(**config)
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name} "
                          f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            conn.commit()
            cursor.close()
            conn.close()
            log(f"数据库 {db_name} 已就绪")
            return True
        except Error as e:
            log(f"创建数据库失败: {e}", 'ERROR')
            return False
    
    def create_tables(self) -> bool:
        """创建 IDS 完整表结构"""
        log("创建数据库表...")
        
        # 1. 规则主表（增强版）
        rules_table = """
        CREATE TABLE IF NOT EXISTS snort_rules (
            sid INT UNSIGNED PRIMARY KEY COMMENT '规则唯一标识符',
            msg VARCHAR(500) NOT NULL COMMENT '威胁描述',
            classtype VARCHAR(100) COMMENT '攻击分类',
            rule_text TEXT NOT NULL COMMENT '完整规则文本',
            rule_hash CHAR(32) NOT NULL UNIQUE COMMENT '规则哈希值',
            protocol VARCHAR(20) COMMENT '协议: tcp/udp/icmp/ip',
            source_ip VARCHAR(255) COMMENT '源IP（支持变量和网段）',
            source_port VARCHAR(50) COMMENT '源端口',
            direction VARCHAR(100) COMMENT '方向: ->, <>, <-, 以及其他变体',
            dest_ip VARCHAR(255) COMMENT '目标IP',
            dest_port VARCHAR(50) COMMENT '目标端口',
            flow VARCHAR(100) COMMENT '流方向: to_client, to_server, etc',
            metadata TEXT COMMENT '元数据',
            reference TEXT COMMENT '参考链接',
            rev INT DEFAULT 1 COMMENT '规则版本',
            severity TINYINT DEFAULT 3 COMMENT '严重程度: 1-高, 2-中, 3-低',
            enabled TINYINT DEFAULT 1 COMMENT '启用状态: 1-启用, 0-禁用',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_classtype (classtype),
            INDEX idx_protocol (protocol),
            INDEX idx_severity (severity),
            INDEX idx_enabled (enabled),
            INDEX idx_hash (rule_hash),
            FULLTEXT INDEX ft_msg (msg)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
        
        # 2. 规则内容匹配表（用于快速匹配）
        content_table = """
        CREATE TABLE IF NOT EXISTS rule_contents (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sid INT UNSIGNED NOT NULL,
            content_pattern VARCHAR(512) NOT NULL COMMENT '匹配内容',
            content_type ENUM('content', 'nocase', 'regex') DEFAULT 'content' COMMENT '匹配类型',
            offset_val INT COMMENT '偏移量',
            depth_val INT COMMENT '深度',
            within_val INT COMMENT 'within范围',
            distance_val INT COMMENT 'distance距离',
            is_negated TINYINT DEFAULT 0 COMMENT '是否取反',
            position_order INT DEFAULT 0 COMMENT '匹配顺序',
            FOREIGN KEY (sid) REFERENCES snort_rules(sid) ON DELETE CASCADE,
            INDEX idx_content (content_pattern),
            INDEX idx_sid (sid),
            INDEX idx_order (position_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
        """
        
        # 3. 告警表
        alerts_table = """
        CREATE TABLE IF NOT EXISTS snort_alerts (
            alert_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sid INT UNSIGNED NOT NULL,
            timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            src_ip VARCHAR(45) NOT NULL COMMENT '源IP',
            src_port INT COMMENT '源端口',
            dst_ip VARCHAR(45) NOT NULL COMMENT '目标IP',
            dst_port INT COMMENT '目标端口',
            protocol VARCHAR(10) DEFAULT 'tcp',
            severity TINYINT DEFAULT 3,
            payload_preview TEXT COMMENT 'payload预览（前256字节）',
            matched_content VARCHAR(255) COMMENT '匹配到的content',
            processed TINYINT DEFAULT 0 COMMENT '是否已处理',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sid) REFERENCES snort_rules(sid) ON DELETE CASCADE,
            INDEX idx_timestamp (timestamp),
            INDEX idx_src_ip (src_ip),
            INDEX idx_dst_ip (dst_ip),
            INDEX idx_sid (sid),
            INDEX idx_severity (severity),
            INDEX idx_processed (processed)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
        
        # 4. 规则分类统计视图
        stats_view = """
        CREATE OR REPLACE VIEW rule_stats AS
        SELECT 
            classtype,
            COUNT(*) as rule_count,
            AVG(severity) as avg_severity
        FROM snort_rules 
        WHERE classtype IS NOT NULL AND enabled = 1
        GROUP BY classtype
        ORDER BY rule_count DESC
        """
        
        try:
            # 检查是否需要修复旧表结构
            self.cursor.execute("""
                SELECT COUNT(*) FROM information_schema.tables 
                WHERE table_schema = %s AND table_name = 'snort_rules'
            """, (DB_CONFIG['database'],))
            
            table_exists = self.cursor.fetchone()[0] > 0
            
            if table_exists:
                # 检查并修复现有表结构
                log("检测到现有表，检查并修复结构...")
                
                # 修改字段长度
                alter_commands = [
                    "ALTER TABLE snort_rules MODIFY direction VARCHAR(20)",
                    "ALTER TABLE snort_rules MODIFY flow VARCHAR(100)",
                    "ALTER TABLE snort_rules MODIFY protocol VARCHAR(20)"
                ]
                
                for cmd in alter_commands:
                    try:
                        self.cursor.execute(cmd)
                        log(f"执行: {cmd}")
                    except Error as e:
                        # 字段可能不存在或已经修改过
                        if "Unknown column" not in str(e):
                            log(f"跳过: {e}", 'WARNING')
                
                self.commit()
                log("表结构检查完成")
            else:
                # 创建新表
                self.cursor.execute(rules_table)
                self.cursor.execute(content_table)
                self.cursor.execute(alerts_table)
                self.cursor.execute(stats_view)
                self.commit()
                log("所有表创建成功")
            
            # 用于模型检测告警
            self.cursor.execute("SELECT 1 FROM snort_rules WHERE sid = 0")
            if not self.cursor.fetchone():
                # 计算一个固定的哈希值
                import hashlib
                fixed_hash = hashlib.md5(b'sid=0_model_alert_placeholder').hexdigest()
                
                self.cursor.execute("""
                    INSERT INTO snort_rules 
                    (sid, msg, classtype, rule_text, rule_hash, protocol, 
                     source_ip, source_port, direction, dest_ip, dest_port,
                     severity, enabled, rev)
                    VALUES (
                        0, 
                        'Model Detection Alert', 
                        'model-detection',
                        'alert model detection (auto-generated for ML alerts)', 
                        %s,
                        'any',
                        'any', 
                        'any', 
                        '->', 
                        'any', 
                        'any',
                        2,
                        1,
                        1
                    )
                """, (fixed_hash,))
                self.commit()
                log("已创建 sid=0 占位规则（用于模型检测告警）")
            else:
                log("sid=0 占位规则已存在，跳过创建")
            
            return True
        except Error as e:
            log(f"表创建失败: {e}", 'ERROR')
            return False
    
    def rule_exists(self, sid: int) -> bool:
        self.cursor.execute("SELECT 1 FROM snort_rules WHERE sid = %s", (sid,))
        return self.cursor.fetchone() is not None
    
    def insert_rule_full(self, rule) -> bool:
        """插入完整规则（包含content）"""
        sql = """
            INSERT INTO snort_rules 
            (sid, msg, classtype, rule_text, rule_hash, protocol, 
             source_ip, source_port, direction, dest_ip, dest_port,
             flow, metadata, reference, rev, severity, enabled)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                msg = VALUES(msg), classtype = VALUES(classtype),
                rule_text = VALUES(rule_text), rule_hash = VALUES(rule_hash),
                protocol = VALUES(protocol), source_ip = VALUES(source_ip),
                source_port = VALUES(source_port), direction = VALUES(direction),
                dest_ip = VALUES(dest_ip), dest_port = VALUES(dest_port),
                flow = VALUES(flow), metadata = VALUES(metadata),
                reference = VALUES(reference), rev = VALUES(rev),
                severity = VALUES(severity), updated_at = CURRENT_TIMESTAMP
        """
        try:
            self.cursor.execute(sql, (
                rule.sid, rule.msg, rule.classtype, rule.rule_text, rule.rule_hash,
                rule.protocol, rule.source_ip, rule.source_port, rule.direction,
                rule.dest_ip, rule.dest_port, rule.flow, rule.metadata,
                rule.reference, rule.rev, rule.severity
            ))
            return True
        except Error as e:
            log(f"插入规则失败 SID {rule.sid}: {e}", 'ERROR')
            return False
    
    def insert_contents_batch(self, sid: int, contents: List[Dict]) -> int:
        """批量插入content匹配条件"""
        if not contents:
            return 0
        
        sql = """
            INSERT INTO rule_contents 
            (sid, content_pattern, content_type, offset_val, depth_val, 
             within_val, distance_val, is_negated, position_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        try:
            data = []
            for idx, content in enumerate(contents):
                data.append((
                    sid,
                    content.get('pattern', ''),
                    content.get('type', 'content'),
                    content.get('offset'),
                    content.get('depth'),
                    content.get('within'),
                    content.get('distance'),
                    1 if content.get('negated') else 0,
                    idx
                ))
            self.cursor.executemany(sql, data)
            return len(data)
        except Error as e:
            log(f"插入content失败 SID {sid}: {e}", 'ERROR')
            return 0
    
    def insert_rules_batch(self, rules: List) -> Tuple[int, int]:
        """批量插入规则（返回成功数和失败数）"""
        success = 0
        failed = 0
        
        for rule in rules:
            if self.insert_rule_full(rule):
                if rule.contents:
                    self.insert_contents_batch(rule.sid, rule.contents)
                success += 1
            else:
                failed += 1
        
        return success, failed
    
    def insert_alert(self, sid: int, src_ip: str, dst_ip: str, 
                     src_port: int = None, dst_port: int = None,
                     protocol: str = 'tcp', payload: str = None,
                     matched_content: str = None) -> bool:
        """插入告警"""
        sql = """
            INSERT INTO snort_alerts 
            (sid, src_ip, src_port, dst_ip, dst_port, protocol, 
             severity, payload_preview, matched_content)
            VALUES (%s, %s, %s, %s, %s, %s, 
                (SELECT severity FROM snort_rules WHERE sid = %s),
                %s, %s)
        """
        try:
            payload_preview = payload[:256] if payload else None
            self.cursor.execute(sql, (sid, src_ip, src_port, dst_ip, dst_port, 
                                      protocol, sid, payload_preview, matched_content))
            self.commit()
            log(f"告警已记录: SID {sid} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return True
        except Error as e:
            log(f"告警插入失败: {e}", 'ERROR')
            return False
    
    def get_recent_alerts(self, limit: int = 50) -> List[Tuple]:
        """获取最近告警"""
        sql = """
            SELECT 
                a.alert_id, a.timestamp, a.src_ip, a.src_port,
                a.dst_ip, a.dst_port, a.protocol,
                r.msg AS threat, r.classtype, a.severity,
                a.matched_content
            FROM snort_alerts a
            JOIN snort_rules r ON a.sid = r.sid
            ORDER BY a.timestamp DESC
            LIMIT %s
        """
        self.cursor.execute(sql, (limit,))
        return self.cursor.fetchall()
    
    def get_rule_count(self) -> int:
        self.cursor.execute("SELECT COUNT(*) FROM snort_rules")
        return self.cursor.fetchone()[0]
    
    def get_classtype_stats(self) -> List[Tuple]:
        self.cursor.execute("""
            SELECT classtype, COUNT(*) as count 
            FROM snort_rules 
            WHERE classtype IS NOT NULL 
            GROUP BY classtype 
            ORDER BY count DESC 
            LIMIT 10
        """)
        return self.cursor.fetchall()
    
    def find_rule_by_hash(self, rule_hash: str) -> Optional[int]:
        """根据哈希查找规则"""
        self.cursor.execute("SELECT sid FROM snort_rules WHERE rule_hash = %s", (rule_hash,))
        result = self.cursor.fetchone()
        return result[0] if result else None
    
    def get_rules_for_matching(self, protocol: str = None) -> List[Dict]:
        """获取规则用于实时匹配"""
        sql = """
            SELECT r.sid, r.msg, r.protocol, r.source_ip, r.source_port,
                   r.dest_ip, r.dest_port, r.flow, r.severity,
                   GROUP_CONCAT(
                       CONCAT(c.content_pattern, '|', c.content_type, '|', 
                              c.offset_val, '|', c.depth_val)
                       SEPARATOR '||'
                   ) as contents
            FROM snort_rules r
            LEFT JOIN rule_contents c ON r.sid = c.sid
            WHERE r.enabled = 1
        """
        if protocol:
            sql += f" AND r.protocol = '{protocol}'"
        sql += " GROUP BY r.sid"
        
        self.cursor.execute(sql)
        results = self.cursor.fetchall()
        return [dict(zip(['sid', 'msg', 'protocol', 'src_ip', 'src_port',
                          'dst_ip', 'dst_port', 'flow', 'severity', 'contents'], row))
                for row in results]
    
    def drop_tables(self) -> bool:
        """删除所有表（用于重建）"""
        try:
            self.cursor.execute("DROP TABLE IF EXISTS rule_contents")
            self.cursor.execute("DROP TABLE IF EXISTS snort_alerts")
            self.cursor.execute("DROP TABLE IF EXISTS snort_rules")
            self.commit()
            log("所有表已删除")
            return True
        except Error as e:
            log(f"删除表失败: {e}", 'ERROR')
            return False


db = Database()