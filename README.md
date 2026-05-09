# Snort 规则导入系统

一个完整的 Snort 规则解析和导入系统，支持将 Snort 规则文件导入到 MySQL/MariaDB 数据库中，用于 IDS/IPS 系统的规则管理和实时匹配。
## 前端链接
- [Hybrid-IDS-Web](https://github.com/silivers/Hybrid-IDS-Web)



## 功能特性

- ✅ **完整规则解析**：支持 Snort 规则的标准语法
- ✅ **批量导入**：高性能批量插入，支持大规则集
- ✅ **内容匹配提取**：自动解析 content、depth、offset、within、distance 等修饰符
- ✅ **严重程度映射**：根据 classtype 自动计算严重程度（高/中/低）
- ✅ **去重机制**：基于 SID 和规则哈希避免重复导入
- ✅ **告警记录**：支持告警记录和查询
- ✅ **统计分析**：内置规则分类统计视图

## 系统架构

| 文件/目录              | 说明           |
| ---------------------- | -------------- |
| `Hybrid-IDS-Rules/`    | 项目根目录     |
| ├── `config.py`        | 配置文件       |
| ├── `database.py`      | 数据库操作模块 |
| ├── `parser.py`        | 规则解析模块   |
| ├── `models.py`        | 数据模型定义   |
| ├── `importer.py`      | 主导入程序     |
| └── `requirements.txt` | Python依赖     |
| ├── `dockerfile`       | Docker 镜像构建文件 |
| ├── `.dockerignore`    | Docker 构建忽略文件 
| └── `generate_db_report.py` | 生成数据库报告以供后续调用|
| └── `database_info.md` | 数据库报告(运行后生成) |
### 数据库表结构

| 表名            | 说明                              |
| --------------- | --------------------------------- |
| `snort_rules`   | 规则主表，存储规则基本属性        |
| `rule_contents` | 规则内容匹配表，存储 content 条件 |
| `snort_alerts`  | 告警记录表                        |
| `rule_stats`    | 规则统计视图                      |

## 安装部署

### 1. 环境要求

- Python 3.8+
- MySQL 5.7+ / MariaDB 10.3+
- pip 包管理器
- Docker (可选，用于容器化部署)


### 2. 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

直接运行程序，系统会自动从配置文件 `config.py` 中读取规则文件路径（可自行下载snort规则文件）并导入：

```bash
python importer.py
```
## 打包为docker镜像
```bash
docker build -t snort-rule .
```
