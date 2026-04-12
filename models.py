#!/usr/bin/env python3
"""数据模型定义"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class SnortRule:
    """Snort 规则数据模型"""
    sid: int
    msg: str
    classtype: Optional[str]
    rule_text: str
    rule_hash: str
    protocol: Optional[str]
    rev: int
    severity: int
    source_ip: Optional[str] = None
    source_port: Optional[str] = None
    direction: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[str] = None
    flow: Optional[str] = None
    contents: List[Dict[str, Any]] = None  # content 匹配条件
    metadata: Optional[str] = None
    reference: Optional[str] = None
    
    def __post_init__(self):
        if self.contents is None:
            self.contents = []


@dataclass
class SnortAlert:
    """告警数据模型"""
    sid: int
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = 'tcp'
    timestamp: Optional[str] = None