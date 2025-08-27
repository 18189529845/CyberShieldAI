#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
互联网违法网站批量检测脚本
基于多维度特征分析的自动化检测系统

功能特点：
1. 批量URL检测
2. 多维度特征提取
3. 机器学习模型集成
4. 实时结果输出
5. 详细报告生成
"""

import requests
import re
import socket
import ssl
import whois
import datetime
import json
import csv
import os
import time
import hashlib
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import dns.resolver
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import pymysql 
import signal
warnings.filterwarnings('ignore')
# 读取配置文件
def load_config(config_path='config.json'):
    """加载配置文件"""
    default_config = {
        'db_config': {
            'host': '192.168.2.41',  # 数据库主机地址
            'port': 3306,
            'user': 'root',       # 数据库用户名
            'password': 'df!2020?OK',  # 数据库密码
            'db': 'ntmv3',  # 数据库名称
            'charset': 'utf8mb4'
        },
        'max_workers': 10,
        'timeout': 10,
        'max_subpages': 50,
        'cache_ttl': 3600
    }
    
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            default_config.update(user_config)
    # 处理use_dict_cursor配置
    if 'db_config' in default_config and default_config['db_config'].pop('use_dict_cursor', False):
        default_config['db_config']['cursorclass'] = pymysql.cursors.DictCursor
    return default_config
# 数据库配置
CONFIG = load_config()
DB_CONFIG = CONFIG['db_config']
# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# IP地址正则表达式
IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

# 域名正则表达式（简化版）
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$')


def is_ip_address(text):
    """判断文本是否为IP地址"""
    return bool(IP_PATTERN.match(text))

def is_domain(text):
    """判断文本是否为域名"""
    return bool(DOMAIN_PATTERN.match(text))

def extract_domain_from_url(url):
    """从URL中提取域名"""
    # 如果URL以http://或https://开头，去掉协议部分
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]
    
    # 去掉路径部分，只保留域名
    domain = url.split('/')[0].split('?')[0].split(':')[0]
    return domain

def update_blacklist_from_db():
    """从数据库更新黑名单文件"""
    try:
        # 连接数据库
        connection = pymysql.connect(**DB_CONFIG)
        
        # 创建游标
        with connection.cursor() as cursor:
            # 执行SQL查询
            sql = "SELECT site_url, rel_url FROM gat_violat_chap;"
            cursor.execute(sql)
            results = cursor.fetchall()
            
            # 提取所有URL
            all_urls = []
            for row in results:
                if row['site_url']:
                    all_urls.append(row['site_url'])
                if row['rel_url']:
                    all_urls.append(row['rel_url'])
            
            # 去重
            unique_urls = list(set(all_urls))
            
            # 分别存储IP和域名
            ips = set()
            domains = set()
            
            for url in unique_urls:
                # 提取域名或IP
                if is_ip_address(url):
                    ips.add(url)
                elif is_domain(url):
                    domains.add(url)
                else:
                    # 尝试从URL中提取域名
                    extracted = extract_domain_from_url(url)
                    if is_ip_address(extracted):
                        ips.add(extracted)
                    elif is_domain(extracted):
                        domains.add(extracted)
            
            # 获取当前目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            
            # 写入blacklist_ips.txt
            ip_file = os.path.join(current_dir, 'blacklist_ips.txt')
            with open(ip_file, 'w', encoding='utf-8') as f:
                for ip in sorted(ips):
                    f.write(f"{ip}\n")
            
            # 写入blacklist_domains.txt
            domain_file = os.path.join(current_dir, 'blacklist_domains.txt')
            with open(domain_file, 'w', encoding='utf-8') as f:
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
            
            print(f"✅ 成功更新黑名单文件！")
            print(f"   - 新增 {len(ips)} 个IP地址到 {ip_file}")
            print(f"   - 新增 {len(domains)} 个域名到 {domain_file}")
            
    except Exception as e:
        print(f"❌ 从数据库更新黑名单失败: {e}")
    finally:
        if 'connection' in locals() and connection.open:
            connection.close()
# 彩色输出工具类
class ColorPrinter:
    """彩色输出工具类"""
    
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m'
    }
    
    @classmethod
    def print_header(cls, text):
        """打印标题"""
        print(f"{cls.COLORS['cyan']}{text}{cls.COLORS['reset']}")
    
    @classmethod
    def print_info(cls, text):
        """打印信息"""
        print(f"{cls.COLORS['blue']}ℹ️  {text}{cls.COLORS['reset']}")
    
    @classmethod
    def print_success(cls, text):
        """打印成功信息"""
        print(f"{cls.COLORS['green']}✅ {text}{cls.COLORS['reset']}")
    
    @classmethod
    def print_warning(cls, text):
        """打印警告信息"""
        print(f"{cls.COLORS['yellow']}⚠️  {text}{cls.COLORS['reset']}")
    
    @classmethod
    def print_error(cls, text):
        """打印错误信息"""
        print(f"{cls.COLORS['red']}❌ {text}{cls.COLORS['reset']}")
    
    @classmethod
    def print_risk(cls, text, level):
        """根据风险等级打印彩色信息"""
        if level == '高':
            print(f"{cls.COLORS['red']}🔴 {text}{cls.COLORS['reset']}")
        elif level == '中':
            print(f"{cls.COLORS['yellow']}🟡 {text}{cls.COLORS['reset']}")
        elif level == '低':
            print(f"{cls.COLORS['green']}🟢 {text}{cls.COLORS['reset']}")
    
    @classmethod
    def print_progress(cls, text):
        """打印进度信息"""
        print(f"{cls.COLORS['magenta']}⏳ {text}{cls.COLORS['reset']}")
    
    def __init__(self):
        self.enabled = True
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            self.enabled = False
    
    def print(self, text, color='white', bold=False, end='\n'):
        """彩色打印"""
        if not self.enabled:
            print(text, end=end)
            return
            
        colors = {
            'red': '\033[91m',
            'green': '\033[92m', 
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }
        
        color_code = colors.get(color, colors['white'])
        bold_code = '\033[1m' if bold else ''
        reset_code = colors['reset']
        
        print(f"{bold_code}{color_code}{text}{reset_code}", end=end)
    
    def print_header(self, text):
        """打印标题"""
        self.print("=" * 60, 'cyan', bold=True)
        self.print(text.center(60), 'cyan', bold=True)
        self.print("=" * 60, 'cyan', bold=True)
    
    def print_risk_level(self, risk_level, url, score):
        """打印风险等级"""
        risk_colors = {
            '高风险': 'red',
            '中风险': 'yellow', 
            '低风险': 'green',
            '检测失败': 'magenta'
        }
        
        color = risk_colors.get(risk_level, 'white')
        emoji = {
            '高风险': '🚨',
            '中风险': '⚠️',
            '低风险': '✅',
            '检测失败': '❌'
        }.get(risk_level, '•')
        
        self.print(f"{emoji} {url}", color, bold=True)
        self.print(f"   风险等级: {risk_level} ({score}%)", color)
    
    def print_progress(self, current, total, url, risk_level):
        """打印进度条"""
        progress = current / total
        bar_length = 30
        filled = int(bar_length * progress)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        colors = {
            '高风险': 'red',
            '中风险': 'yellow',
            '低风险': 'green',
            '检测失败': 'magenta'
        }
        color = colors.get(risk_level, 'white')
        
        self.print(f"\r[{bar}] {current}/{total} - {url[:50]}...", color, end='')
    
    def print_summary(self, results):
        """打印彩色统计摘要"""
        if not results:
            return
            
        total = len(results)
        risk_counts = {}
        for result in results:
            risk_level = result.get('风险等级', '未知')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        self.print("\n" + "=" * 60, 'cyan', bold=True)
        self.print("📊 检测统计汇总".center(60), 'cyan', bold=True)
        self.print("=" * 60, 'cyan', bold=True)
        
        risk_styles = {
            '高风险': ('red', '🚨'),
            '中风险': ('yellow', '⚠️'),
            '低风险': ('green', '✅'),
            '检测失败': ('magenta', '❌')
        }
        
        for risk_level, count in sorted(risk_counts.items()):
            color, emoji = risk_styles.get(risk_level, ('white', '•'))
            percentage = (count / total) * 100
            self.print(f"{emoji} {risk_level}: {count} 个 ({percentage:.1f}%)", color)
        
        self.print("-" * 60, 'cyan')
        
        # 安全建议
        high_risk = risk_counts.get('高风险', 0)
        medium_risk = risk_counts.get('中风险', 0)
        
        if high_risk > 0:
            self.print("🚨 立即处理: 发现高风险网站，请立即处理！", 'red', bold=True)
        if medium_risk > 0:
            self.print("⚠️ 谨慎访问: 发现中风险网站，建议进一步验证", 'yellow', bold=True)
        if high_risk == 0 and medium_risk == 0:
            self.print("✅ 安全良好: 本次检测未发现明显风险网站", 'green', bold=True)

# 创建全局彩色打印实例
color_printer = ColorPrinter()

# 修改原有的打印函数使用彩色输出
def print_colored_detection_result(result):
    """彩色打印检测结果"""
    url = result.get('网址', '未知')
    risk_level = result.get('风险等级', '未知')
    risk_score = result.get('风险评分', '0%')
    risk_desc = result.get('风险描述', '')
    
    color_printer.print_risk_level(risk_level, url, risk_score)
    
    if risk_desc:
        lines = risk_desc.split('\n')
        for line in lines:
            if line.startswith('🚨') or line.startswith('⚠️'):
                color_printer.print(f"   {line}", 'red' if '🚨' in line else 'yellow')
            elif line.startswith('✅'):
                color_printer.print(f"   {line}", 'green')
            elif line.startswith('💡'):
                color_printer.print(f"   {line}", 'blue')
            elif line.startswith('•'):
                color_printer.print(f"   {line}", 'white')
    
    print()  # 空行分隔

class WebsiteDetector:
    """违法网站检测器类"""
    # 添加类级缓存
    _keyword_cache = None
    _cache_timestamp = 0
    _cache_ttl = 3600  # 缓存有效期，单位秒
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.timeout = 10
        # 添加子页面检测相关参数
        self.max_subpages = 50  # 最多检测的子页面数量
        self.subpage_timeout = 8  # 子页面检测超时时间
        
        # 敏感关键词库 - 扩展分类
        self.sensitive_keywords = self._load_keywords_from_db()
        
        # 可疑域名后缀 - 扩展列表
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.wang', '.ren', 
            '.click', '.download', '.link', '.work', '.party', '.racing',
            '.date', '.accountant', '.science', '.trade', '.review'
        ]
        
        # 知名品牌的钓鱼域名变体检测
        self.brand_keywords = [
            'alipay', 'taobao', 'tmall', 'jd', 'qq', 'wechat', 'bank',
            'icbc', 'ccb', 'abc', 'boc', 'unionpay', 'paypal', 'amazon',
            'microsoft', 'google', 'apple', 'facebook', 'instagram'
        ]
        
        # 黑名单IP段和域名
        self.blacklisted_ips = set()
        self.blacklisted_domains = set()
        self._load_blacklists()
        
        # 加载模型（如果存在）
        self.model = self._load_model()
        
        # 可信CA列表
        self.trusted_cas = [
            "Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo", "GoDaddy",
            "Amazon", "Google Trust Services", "Cloudflare", "Entrust"
        ]
    def _load_keywords_from_db(self):
        """从数据库加载敏感关键词，带有缓存机制"""
        import time
        current_time = time.time()
        
        # 检查缓存是否有效
        if self._keyword_cache and (current_time - self._cache_timestamp < self._cache_ttl):
            return self._keyword_cache

        keywords_dict = {}
        try:
            # 连接数据库
            connection = pymysql.connect(**DB_CONFIG)
            try:
                with connection.cursor() as cursor:
                    # 执行SQL查询
                    sql = """select illegal, (select dict_label from sys_dict_data where dict_type = 'contraband_type' and dict_value = g.category ) as dict_type from gat_illegal_keyword g"""
                    cursor.execute(sql)
                    results = cursor.fetchall()
                    
                    # 构建关键词字典
                    for row in results:
                        keyword = row['illegal']
                        category = row['dict_type']
                        if category not in keywords_dict:
                            keywords_dict[category] = []
                        keywords_dict[category].append(keyword)
            finally:
                connection.close()
            # 更新缓存
            self._keyword_cache = keywords_dict
            self._cache_timestamp = current_time
        except Exception as e:
            logger.error(f"从数据库加载关键词失败: {e}")
            # 如果数据库连接失败，从keyword.txt文件中读取关键词
            try:
                import json
                import os
                # 获取当前文件所在目录
                current_dir = os.path.dirname(os.path.abspath(__file__))
                # 构建keyword.txt文件的完整路径
                keyword_file_path = os.path.join(current_dir, 'keyword.json')
                # 检查文件是否存在
                if os.path.exists(keyword_file_path):
                    with open(keyword_file_path, 'r', encoding='utf-8') as f:
                        # 读取文件内容并解析为字典
                        file_content = f.read()
                        # 处理文件内容，去除可能的BOM字符
                        file_content = file_content.lstrip('\ufeff')
                        keywords_dict = json.loads(file_content)
                        logger.info(f"成功从文件加载关键词，共加载 {len(keywords_dict)} 个类别")
                else:
                    logger.warning(f"关键词文件不存在: {keyword_file_path}")
            except Exception as file_error:
                logger.error(f"从文件加载关键词失败: {file_error}")
                keywords_dict = {}
        return keywords_dict
    def _extract_subpage_features(self, url):
        """提取子页面特征并进行检测"""
        features = {
            'subpage_count': 0,  # 检测的子页面数量
            'suspicious_subpages': 0,  # 可疑子页面数量
            'avg_subpage_risk': 0.0,  # 子页面平均风险分数
            'has_sensitive_subpage': 0,  # 是否包含高敏感子页面
            'subpage_keywords': {},  # 子页面中发现的关键词统计
            'subpage_details': []  # 子页面详细信息
        }
        
        try:
            # 获取主页面内容
            response = self.session.get(url, timeout=self.subpage_timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            
            # 提取所有内部链接作为子页面候选
            internal_links = set()
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                if href and not href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
                    # 转换相对链接为绝对链接
                    absolute_url = urljoin(url, href)
                    parsed_link = urlparse(absolute_url)
                    
                    # 检查是否为同一域名下的链接
                    if parsed_link.netloc == base_domain:
                        # 标准化URL（去除锚点等）
                        normalized_url = parsed_link.scheme + '://' + parsed_link.netloc + parsed_link.path
                        if normalized_url not in internal_links and normalized_url != url:
                            internal_links.add(normalized_url)
                            
                            # 限制子页面数量
                            if len(internal_links) >= self.max_subpages:
                                break
            
            # 对子页面进行检测
            features['subpage_count'] = len(internal_links)
            total_risk_score = 0
            
            for subpage_url in internal_links:
                try:
                    # 对子页面进行简单特征提取
                    subpage_features = {}
                    subpage_response = self.session.get(subpage_url, timeout=self.subpage_timeout)
                    subpage_soup = BeautifulSoup(subpage_response.content, 'html.parser')
                    
                    # 提取子页面内容特征
                    text_content = subpage_soup.get_text().lower()
                    
                    # 统计敏感关键词
                    subpage_keyword_count = 0
                    keyword_stats = {}
                    
                    for category, keywords in self.sensitive_keywords.items():
                        count = sum(1 for keyword in keywords if keyword.lower() in text_content)
                        keyword_stats[category] = count
                        subpage_keyword_count += count
                    
                    # 计算子页面风险分数
                    subpage_risk = 0
                    if subpage_keyword_count > 5:
                        subpage_risk = 80  # 高风险
                        features['has_sensitive_subpage'] = 1
                    elif subpage_keyword_count > 2:
                        subpage_risk = 50  # 中风险
                    
                    # 检查是否有可疑表单或脚本
                    has_login_form = 1 if subpage_soup.find('input', type='password') else 0
                    script_count = len(subpage_soup.find_all('script'))
                    
                    if has_login_form and not subpage_url.startswith('https://'):
                        subpage_risk += 30
                    if script_count > 5:
                        subpage_risk += 20
                    
                    # 限制风险分数范围
                    subpage_risk = min(100, max(0, subpage_risk))
                    
                    # 更新统计信息
                    total_risk_score += subpage_risk
                    if subpage_risk > 60:
                        features['suspicious_subpages'] += 1
                    
                    # 更新关键词统计
                    for category, count in keyword_stats.items():
                        if count > 0:
                            if category not in features['subpage_keywords']:
                                features['subpage_keywords'][category] = 0
                            features['subpage_keywords'][category] += count
                    
                    # 保存子页面详细信息
                    features['subpage_details'].append({
                        'url': subpage_url,
                        'risk_score': subpage_risk,
                        'keyword_count': subpage_keyword_count,
                        'has_login_form': has_login_form,
                        'script_count': script_count
                    })
                    
                except Exception as e:
                    logger.warning(f"子页面检测失败 {subpage_url}: {e}")
                    continue
            
            # 计算平均风险分数
            if features['subpage_count'] > 0:
                features['avg_subpage_risk'] = total_risk_score / features['subpage_count']
            
        except Exception as e:
            logger.error(f"子页面特征提取失败 {url}: {e}")
        
        return features

    def extract_all_features(self, url):
        """提取所有特征（包含子页面特征）"""
        features = {'url': url}
        
        # 提取各维度特征
        domain_features = self._extract_domain_features(url)
        content_features = self._extract_content_features(url)
        network_features = self._extract_network_features(url)
        subpage_features = self._extract_subpage_features(url)  # 添加子页面特征
        
        # 合并所有特征
        features.update(domain_features)
        features.update(content_features)
        features.update(network_features)
        features.update(subpage_features)  # 添加子页面特征
        
        return features
    def _load_model(self):
        """加载预训练的机器学习模型"""
        model_path = 'website_detection_model.pkl'
        if os.path.exists(model_path):
            try:
                return joblib.load(model_path)
            except Exception as e:
                logger.warning(f"模型加载失败: {e}")
        return None
    
    def _load_blacklists(self):
        """加载黑名单数据"""
        try:
            # 加载已知恶意IP列表
            if os.path.exists('blacklist_ips.txt'):
                with open('blacklist_ips.txt', 'r') as f:
                    self.blacklisted_ips = {line.strip() for line in f if line.strip()}
            
            # 加载已知恶意域名列表
            if os.path.exists('blacklist_domains.txt'):
                with open('blacklist_domains.txt', 'r') as f:
                    self.blacklisted_domains = {line.strip() for line in f if line.strip()}
                    
        except Exception as e:
            logger.warning(f"加载黑名单失败: {e}")
    
    def _detect_homograph_attacks(self, domain):
        """检测同形异义字符攻击"""
        homograph_chars = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T'
        }
        
        normalized = domain.lower()
        for unicode_char, ascii_char in homograph_chars.items():
            normalized = normalized.replace(unicode_char, ascii_char)
        
        return normalized != domain.lower()
    
    def _calculate_levenshtein_distance(self, s1, s2):
        """计算编辑距离"""
        if len(s1) < len(s2):
            return self._calculate_levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _extract_domain_features(self, url):
        """提取域名特征"""
        features = {}
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # 基础域名特征
            features['domain_length'] = len(domain)
            features['subdomain_count'] = domain.count('.')
            features['has_hyphen'] = 1 if '-' in domain else 0
            features['has_digits'] = 1 if any(c.isdigit() for c in domain) else 0
            
            # 顶级域名分析
            tld = '.' + domain.split('.')[-1] if '.' in domain else ''
            features['suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            
            # 字符分布特征
            features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain)
            features['special_char_ratio'] =round( sum(not c.isalnum() for c in domain) / len(domain), 2)
            features['consonant_ratio'] = round( sum(c.lower() in 'bcdfghjklmnpqrstvwxyz' for c in domain) / len(domain), 2)
            
            # 熵值计算（检测随机域名）
            import math
            char_counts = {}
            for char in domain.lower():
                char_counts[char] = char_counts.get(char, 0) + 1
            entropy = round( -sum((count/len(domain)) * math.log2(count/len(domain)) for count in char_counts.values()), 2)
            features['entropy'] = entropy
            
            # 黑名单检测
            features['in_blacklist'] = 1 if domain in self.blacklisted_domains else 0
            
            # 品牌钓鱼检测
            brand_similarity = 0
            domain_lower = domain.lower()
            for brand in self.brand_keywords:
                distance = self._calculate_levenshtein_distance(domain_lower, brand)
                similarity = max(0, 1 - distance / max(len(domain_lower), len(brand)))
                brand_similarity = max(brand_similarity, similarity)
            features['brand_similarity'] =round( brand_similarity , 2)
            features['potential_phishing'] = 1 if brand_similarity > 0.7 else 0
            
            # 同形异义字符攻击检测
            features['homograph_attack'] = 1 if self._detect_homograph_attacks(domain) else 0
            
            # 可疑关键词组合
            suspicious_combinations = [
                'login', 'signin', 'verify', 'secure', 'bank', 'update', 'confirm',
                'security', 'account', 'auth', 'password', 'credential'
            ]
            features['suspicious_combo'] = sum(1 for combo in suspicious_combinations if combo in domain.lower())
            
            # WHOIS信息
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    days_since_creation = (datetime.datetime.now() - creation_date).days
                    features['domain_age_days'] = days_since_creation
                    features['is_new_domain'] = 1 if days_since_creation < 30 else 0
                    features['is_very_new_domain'] = 1 if days_since_creation < 7 else 0
                else:
                    features['domain_age_days'] = -1
                    features['is_new_domain'] = 1
                    features['is_very_new_domain'] = 1
                    
                if domain_info.expiration_date:
                    expiration_date = domain_info.expiration_date
                    if isinstance(expiration_date, list):
                        expiration_date = expiration_date[0]
                    days_to_expire = (expiration_date - datetime.datetime.now()).days
                    features['days_to_expire'] = days_to_expire
                    features['short_registration'] = 1 if days_to_expire < 365 else 0
                else:
                    features['days_to_expire'] = -1
                    features['short_registration'] = 1
                    
                # 注册商信息
                registrar = str(domain_info.registrar).lower() if domain_info.registrar else ''
                suspicious_registrars = ['namecheap', 'godaddy', 'publicdomainregistry']
                features['suspicious_registrar'] = 1 if any(r in registrar for r in suspicious_registrars) else 0
                    
            except Exception as e:
                features['domain_age_days'] = -1
                features['is_new_domain'] = 0  # 修改为0，不默认为新域名
                features['is_very_new_domain'] = 0  # 修改为0，不默认为极新域名
                features['days_to_expire'] = -1
                features['short_registration'] = 0  # 修改为0，不默认为短期注册
                features['suspicious_registrar'] = 0
                
        except Exception as e:
            logger.error(f"域名特征提取失败 {url}: {e}")
            
        return features
    
    def _extract_content_features(self, url):
        """提取内容特征"""
        features = {}
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 基础内容特征
            features['content_length'] = len(response.content)
            features['text_length'] = len(soup.get_text())
            features['image_count'] = len(soup.find_all('img'))
            features['link_count'] = len(soup.find_all('a'))
            features['form_count'] = len(soup.find_all('form'))
            features['external_links'] = len([a for a in soup.find_all('a', href=True) 
                                            if a['href'].startswith('http') and urlparse(url).netloc not in a['href']])
            
            # 敏感关键词检测 - 分类统计
            text_content = soup.get_text().lower()
            total_sensitive = 0
            for category, keywords in self.sensitive_keywords.items():
                category_count = sum(1 for keyword in keywords if keyword.lower() in text_content)
                features[f'sensitive_{category}'] = category_count
                total_sensitive += category_count
            
            features['sensitive_keyword_count'] = total_sensitive
            features['sensitive_keyword_ratio'] = round(total_sensitive / max(len(text_content.split()), 1), 2)
            
            # 页面质量指标
            features['has_title'] = 1 if soup.title and soup.title.string else 0
            features['title_length'] = len(soup.title.string) if soup.title and soup.title.string else 0
            features['has_description'] = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
            features['has_keywords'] = 1 if soup.find('meta', attrs={'name': 'keywords'}) else 0
            features['has_robots'] = 1 if soup.find('meta', attrs={'name': 'robots'}) else 0
            
            # 页面结构分析
            features['has_login_form'] = 1 if soup.find('input', type='password') else 0
            features['has_contact_info'] = 1 if any(keyword in text_content for keyword in ['联系我们', 'contact', '电话', '邮箱']) else 0
            features['has_privacy_policy'] = 1 if any(keyword in text_content for keyword in ['隐私政策', 'privacy', '条款']) else 0
            
            # 图片质量分析
            suspicious_images = 0
            for img in soup.find_all('img'):
                src = img.get('src', '')
                if not src or src.startswith('data:'):
                    suspicious_images += 1
                elif 'logo' in src.lower() or 'banner' in src.lower():
                    continue
            features['suspicious_images'] = suspicious_images
            
            # 脚本分析
            scripts = soup.find_all('script')
            features['script_count'] = len(scripts)
            suspicious_scripts = 0
            for script in scripts:
                if script.string and any(keyword in script.string.lower() for keyword in ['eval', 'document.write', 'unescape']):
                    suspicious_scripts += 1
            features['suspicious_scripts'] = suspicious_scripts
            
            # 重定向检测
            if response.history:
                features['redirect_count'] = len(response.history)
                features['final_url'] = response.url
                features['domain_changed'] = 1 if urlparse(url).netloc != urlparse(response.url).netloc else 0
            else:
                features['redirect_count'] = 0
                features['final_url'] = url
                features['domain_changed'] = 0
            
            # SSL证书信息 - 增强版
            try:
                parsed = urlparse(url)
                context = ssl.create_default_context()
                with socket.create_connection((parsed.netloc, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                        cert = ssock.getpeercert()
                        features['has_ssl'] = 1
                        features['ssl_valid'] = 1 if cert else 0
                        
                        if cert:
                            # 检查证书颁发者
                            issuer = dict(x[0] for x in cert['issuer'])
                            ca_name = issuer.get('organizationName', '')
                            features['trusted_ca'] = 1 if any(ca in ca_name for ca in self.trusted_cas) else 0
                            
                            # 检查证书有效期
                            not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            features['cert_valid_days'] = (not_after - datetime.datetime.now()).days
                            features['cert_too_new'] = 1 if (datetime.datetime.now() - not_before).days < 7 else 0
                            
                            # 域名匹配检查
                            cn = None
                            for item in cert['subject']:
                                for key, value in item:
                                    if key == 'commonName':
                                        cn = value
                                        break
                            
                            features['ssl_domain_match'] = 1 if cn and parsed.netloc in cn else 0
                            features['wildcard_cert'] = 1 if cn and '*' in cn else 0
                            
            except Exception as e:
                features['has_ssl'] = 0
                features['ssl_valid'] = 0
                features['trusted_ca'] = 0
                features['cert_valid_days'] = -1
                features['cert_too_new'] = 0
                features['ssl_domain_match'] = 0
                features['wildcard_cert'] = 0
                
        except Exception as e:
            # logger.error(f"内容特征提取失败 {url}: {e}")
            color_printer.print(f"🚨 内容特征提取失败 {url}: {e}", 'red', bold=True)
            features.update({
                'content_length': 0, 'text_length': 0, 'image_count': 0,
                'link_count': 0, 'form_count': 0, 'external_links': 0,
                'sensitive_keyword_count': 0, 'sensitive_keyword_ratio': 0,
                'has_title': 0, 'title_length': 0, 'has_description': 0,
                'has_keywords': 0, 'has_robots': 0, 'has_login_form': 0,
                'has_contact_info': 0, 'has_privacy_policy': 0, 'suspicious_images': 0,
                'script_count': 0, 'suspicious_scripts': 0, 'redirect_count': 0,
                'domain_changed': 0, 'has_ssl': 0, 'ssl_valid': 0, 'trusted_ca': 0,
                'cert_valid_days': -1, 'cert_too_new': 0, 'ssl_domain_match': 0,
                'wildcard_cert': 0
            })
            for category in self.sensitive_keywords.keys():
                features[f'sensitive_{category}'] = 0
            
        return features
    
    def _extract_network_features(self, url):
        """提取网络特征"""
        features = {}
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # DNS解析 - 增强版
            try:
                # A记录
                answers = dns.resolver.resolve(domain, 'A')
                features['dns_resolved'] = 1
                features['ip_count'] = len(answers)
                features['first_ip'] = str(answers[0])
                
                # 黑名单IP检查
                features['blacklisted_ip'] = 1 if features['first_ip'] in self.blacklisted_ips else 0
                
                # MX记录
                try:
                    mx_answers = dns.resolver.resolve(domain, 'MX')
                    features['has_mx'] = 1
                    features['mx_count'] = len(mx_answers)
                except:
                    features['has_mx'] = 0
                    features['mx_count'] = 0
                
                # TXT记录（SPF检查）
                try:
                    txt_answers = dns.resolver.resolve(domain, 'TXT')
                    spf_records = [str(record) for record in txt_answers if 'spf' in str(record).lower()]
                    features['has_spf'] = 1 if spf_records else 0
                except:
                    features['has_spf'] = 0
                    
            except:
                features['dns_resolved'] = 0
                features['ip_count'] = 0
                features['first_ip'] = ''
                features['has_mx'] = 0
                features['mx_count'] = 0
                features['has_spf'] = 0
                features['blacklisted_ip'] = 0
            
            # 响应时间分析
            start_time = time.time()
            try:
                response = self.session.head(url, timeout=5)
                features['response_time'] =round(time.time() - start_time, 2)
                features['http_status'] = response.status_code
                features['web_accessible'] = 1
                
                # 服务器信息
                features['server_header'] = response.headers.get('Server', '')
                features['powered_by'] = response.headers.get('X-Powered-By', '')
                
                # 安全头检查
                security_headers = {
                    'strict-transport-security': 'hsts',
                    'x-frame-options': 'x_frame_options',
                    'x-content-type-options': 'x_content_type',
                    'x-xss-protection': 'x_xss_protection',
                    'content-security-policy': 'csp'
                }
                
                for header, feature_name in security_headers.items():
                    features[feature_name] = 1 if header in response.headers else 0
                
            except:
                features['response_time'] = -1
                features['http_status'] = 0
                features['web_accessible'] = 0
                features['server_header'] = ''
                features['powered_by'] = ''
                features['hsts'] = 0
                features['x_frame_options'] = 0
                features['x_content_type'] = 0
                features['x_xss_protection'] = 0
                features['csp'] = 0
                features['blacklisted_ip'] = 0
                
        except Exception as e:
            logger.error(f"网络特征提取失败 {url}: {e}")
            
        return features
    
    
    
    def predict_risk(self, features):
        """预测风险等级 - 增强版评分算法"""
        if not self.model:
            # 增强的基于规则风险评分
            risk_score = 0
            # 添加子页面风险因子
            if features.get('has_sensitive_subpage', 0) == 1:
                risk_score += 30  # 包含高敏感子页面
            if features.get('suspicious_subpages', 0) > 0:
                risk_score += features['suspicious_subpages'] * 10  # 每个可疑子页面增加风险
            if features.get('avg_subpage_risk', 0) > 50:
                risk_score += 15  # 子页面平均风险较高
            # 域名风险因子（权重增加）
            if features.get('in_blacklist', 0) == 1:
                risk_score += 50  # 黑名单直接高分
            if features.get('homograph_attack', 0) == 1:
                risk_score += 30  # 同形异义字符攻击
            if features.get('potential_phishing', 0) == 1:
                risk_score += 25  # 品牌钓鱼
            if features.get('brand_similarity', 0) > 0.8:
                risk_score += 20  # 高品牌相似度
            if features.get('entropy', 0) > 4.0:
                risk_score += 15  # 高熵值（随机域名）
            if features.get('is_very_new_domain', 0) == 1:
                risk_score += 5  # 非常新的域名
            if features.get('short_registration', 0) == 1:
                risk_score += 5  # 短期注册
            if features.get('suspicious_registrar', 0) == 1:
                risk_score += 10  # 可疑注册商
            if features.get('suspicious_combo', 0) > 2:
                risk_score += 15  # 可疑关键词组合
            
            # 内容风险因子（细化分类）
            gambling_content = features.get('sensitive_gambling', 0)
            fraud_content = features.get('sensitive_fraud', 0)
            porn_content = features.get('sensitive_pornography', 0)
            financial_fraud = features.get('sensitive_financial_fraud', 0)
            
            total_sensitive = gambling_content + fraud_content + porn_content + financial_fraud
            if total_sensitive > 10:
                risk_score += 30
            elif total_sensitive > 5:
                risk_score += 20
            elif total_sensitive > 0:
                risk_score += 10
                
            if features.get('sensitive_keyword_ratio', 0) > 0.1:
                risk_score += 15
            if features.get('has_login_form', 0) == 1 and features.get('has_ssl', 0) == 0:
                risk_score += 25  # 登录表单无SSL
            if features.get('suspicious_scripts', 0) > 3:
                risk_score += 15  # 可疑脚本
            if features.get('domain_changed', 0) == 1:
                risk_score += 20  # 域名跳转
                
            # SSL证书风险因子
            if features.get('has_ssl', 0) == 0:
                risk_score += 15
            if features.get('ssl_valid', 0) == 0:
                risk_score += 20
            if features.get('trusted_ca', 0) == 0:
                risk_score += 10  # 非可信CA
            if features.get('cert_too_new', 0) == 1:
                risk_score += 10  # 证书太新
            if features.get('cert_valid_days', 0) < 30:
                risk_score += 10  # 证书即将过期
                
            # 网络风险因子
            if features.get('blacklisted_ip', 0) == 1:
                risk_score += 40  # 黑名单IP
            if features.get('web_accessible', 0) == 0:
                risk_score += 30  # 无法访问
            if features.get('dns_resolved', 0) == 0:
                risk_score += 25
            if features.get('response_time', 0) > 5:
                risk_score += 10  # 响应时间过长
            if features.get('http_status', 0) >= 400:
                risk_score += 15  # HTTP错误状态
                
            # 安全头检查（负向风险）
            security_score = (features.get('hsts', 0) + features.get('x_frame_options', 0) + 
                            features.get('x_content_type', 0) + features.get('x_xss_protection', 0) + 
                            features.get('csp', 0))
            risk_score -= security_score * 2  # 安全头减少风险
            
            # 信任指标（负向风险）
            if features.get('has_contact_info', 0) == 1:
                risk_score -= 10
            if features.get('has_privacy_policy', 0) == 1:
                risk_score -= 10
            if features.get('has_mx', 0) == 1:
                risk_score -= 5  # 有MX记录
            if features.get('domain_age_days', 0) > 365:
                risk_score -= 15  # 老域名
                
            # 风险等级判定（调整阈值）
            risk_score = max(0, min(100, risk_score))  # 限制在0-100范围内
            
            if risk_score >= 70:
                return 'HIGH', risk_score
            elif risk_score >= 40:
                return 'MEDIUM', risk_score
            else:
                return 'LOW', risk_score
        else:
            # 使用机器学习模型预测
            feature_vector = self._prepare_features_for_model(features)
            prediction = self.model.predict([feature_vector])[0]
            probability = self.model.predict_proba([feature_vector])[0]
            risk_score = int(probability[1] * 100) if len(probability) > 1 else 50
            
            if prediction == 1:
                return 'HIGH' if risk_score > 70 else 'MEDIUM', risk_score
            else:
                return 'LOW', risk_score
    
    def _prepare_features_for_model(self, features):
        """准备机器学习模型需要的特征向量"""
        feature_order = [
            'domain_length', 'subdomain_count', 'has_hyphen', 'has_digits',
            'suspicious_tld', 'digit_ratio', 'special_char_ratio',
            'domain_age_days', 'is_new_domain', 'days_to_expire',
            'content_length', 'text_length', 'image_count', 'link_count',
            'form_count', 'sensitive_keyword_count', 'sensitive_keyword_ratio',
            'has_title', 'has_description', 'has_keywords', 'has_ssl',
            'ssl_valid', 'ssl_domain_match', 'dns_resolved', 'ip_count',
            'response_time', 'http_status'
        ]
        
        return [features.get(key, 0) for key in feature_order]

class BatchDetector:
    """批量检测器"""
    
    def __init__(self, max_workers=10):
        self.detector = WebsiteDetector()
        self.max_workers = max_workers
        self.results = []
    
    def detect_single(self, url):
        """检测单个URL"""
        try:
            # logger.info(f"开始检测: {url}")
            color_printer.print(f"🚀 开始检测 {url} ", 'cyan', bold=True)
            # 标准化URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # 提取特征
            features = self.detector.extract_all_features(url)
            
            # 预测风险
            risk_level, risk_score = self.detector.predict_risk(features)
            
            # 风险等级中文映射
            risk_level_cn = {
                'HIGH': '高风险',
                'MEDIUM': '中风险', 
                'LOW': '低风险',
                'ERROR': '检测失败'
            }.get(risk_level, risk_level)
            
            # 生成中文风险描述
            risk_description = self._generate_risk_description(features, risk_level, risk_score)
            
            result = {
                '网址': url,
                '风险等级': risk_level_cn,
                '风险评分': f"{risk_score}%",
                '风险描述': risk_description,
                '检测时间': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                '详细特征': self._translate_features(features),
                '英文原文': {
                    'url': url,
                    'risk_level': risk_level,
                    'risk_score': risk_score,
                    'features': features,
                    'timestamp': datetime.datetime.now().isoformat()
                }
            }
            
            # 根据风险等级设置不同颜色
            if risk_level_cn == "高风险":
                color = 'red'
            elif risk_level_cn == "中风险":
                color = 'yellow'
            else:  # 低风险
                color = 'blue'
                
            color_printer.print(f"检测完成: {url} - 风险等级: {risk_level_cn} ({risk_score}%) - 风险描述： {risk_description} \n", color, bold=True)
            return result
            
        except Exception as e:
            
            color_printer.print(f"🚨 检测失败 {url}: {e}", 'red', bold=True)
            return {
                '网址': url,
                '风险等级': '检测失败',
                '风险评分': '0%',
                '风险描述': f'检测过程中发生错误: {str(e)}',
                '检测时间': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                '详细特征': {},
                '错误信息': str(e)
            }
    
    def _generate_risk_description(self, features, risk_level, risk_score):
        """生成中文风险描述"""
        descriptions = []
        
        if risk_level == 'HIGH':
            descriptions.append("🚨 该网站存在严重安全风险")
        elif risk_level == 'MEDIUM':
            descriptions.append("⚠️ 该网站存在一定安全风险")
        elif risk_level == 'LOW':
            descriptions.append("✅ 该网站相对安全")
        
        # 域名相关风险
        if features.get('in_blacklist', 0) == 1:
            descriptions.append("• 域名在已知恶意域名黑名单中")
        if features.get('homograph_attack', 0) == 1:
            descriptions.append("• 检测到同形异义字符攻击（钓鱼域名）")
        if features.get('potential_phishing', 0) == 1:
            descriptions.append("• 疑似品牌钓鱼网站")
        if features.get('is_very_new_domain', 0) == 1:
            descriptions.append("• 域名注册时间极短（7天内）(whois请求可能存在网络异常)")
        if features.get('short_registration', 0) == 1:
            descriptions.append("• 域名注册期限过短（少于1年）(whois请求可能存在请求网络异常)")
            
        # 内容风险
        total_sensitive = (features.get('sensitive_gambling', 0) + 
                          features.get('sensitive_fraud', 0) + 
                          features.get('sensitive_pornography', 0) + 
                          features.get('sensitive_financial_fraud', 0))
        
        if total_sensitive > 0:
            if features.get('sensitive_gambling', 0) > 0:
                descriptions.append("• 包含赌博相关内容")
            if features.get('sensitive_fraud', 0) > 0:
                descriptions.append("• 包含诈骗相关内容")
            if features.get('sensitive_pornography', 0) > 0:
                descriptions.append("• 包含色情相关内容")
            if features.get('sensitive_financial_fraud', 0) > 0:
                descriptions.append("• 包含金融诈骗相关内容")
                
        # SSL证书风险
        if features.get('has_ssl', 0) == 0:
            descriptions.append("• 网站未启用HTTPS加密")
        elif features.get('ssl_valid', 0) == 0:
            descriptions.append("• SSL证书无效或已过期")
        elif features.get('trusted_ca', 0) == 0:
            descriptions.append("• SSL证书颁发机构不受信任")
            
        # 网络风险
        if features.get('blacklisted_ip', 0) == 1:
            descriptions.append("• 服务器IP地址在黑名单中")
        if features.get('web_accessible', 0) == 0:
            descriptions.append("• 网站无法访问")
        if features.get('response_time', 0) > 5:
            descriptions.append("• 网站响应速度过慢")

        # 添加子页面风险描述
        if features.get('has_sensitive_subpage', 0) == 1:
            descriptions.append("• 子页面中发现高敏感内容")
        if features.get('suspicious_subpages', 0) > 0:
            descriptions.append(f"• 发现 {features['suspicious_subpages']} 个可疑子页面")
        subpage_keywords = features.get('subpage_keywords', {})
        if isinstance(subpage_keywords, dict) and subpage_keywords:
            for category, count in features['subpage_keywords'].items():
                category_map = {
                    'gambling': '赌博',
                    'pornography': '色情', 
                    'fraud': '诈骗',
                    'illegal_trade': '非法交易',
                    'cybercrime': '网络犯罪',
                    'financial_fraud': '金融诈骗'
                }
                category_name = category_map.get(category, category)
                descriptions.append(f"• 子页面包含 {count} 个{category_name}相关关键词") 
            
        # 安全建议
        if risk_level in ['HIGH', 'MEDIUM']:
            descriptions.append("\n💡 建议：请勿在此网站输入个人信息或进行任何交易")
        else:
            descriptions.append("\n💡 建议：网站相对安全，但仍需保持警惕")
            
        return '\n'.join(descriptions)
    
    def _translate_features(self, features):
        """翻译特征名称为中文（包含子页面特征）"""
        if not isinstance(features, dict):
            return {}
            
        translate_map = {
            'domain_length': '域名长度',
            'subdomain_count': '子域名数量',
            'has_hyphen': '包含连字符',
            'has_digits': '包含数字',
            'suspicious_tld': '可疑顶级域名',
            'digit_ratio': '数字比例',
            'special_char_ratio': '特殊字符比例',
            'consonant_ratio': '辅音比例',
            'entropy': '熵值（随机性）',
            'in_blacklist': '黑名单匹配',
            'brand_similarity': '品牌相似度',
            'potential_phishing': '疑似钓鱼',
            'homograph_attack': '同形异义攻击',
            'suspicious_combo': '可疑关键词组合',
            'domain_age_days': '域名年龄（天）',
            'is_new_domain': '新域名（30天内）',
            'is_very_new_domain': '极新域名（7天内）',
            'days_to_expire': '到期剩余天数',
            'short_registration': '短期注册',
            'suspicious_registrar': '可疑注册商',
            'content_length': '内容长度',
            'text_length': '文本长度',
            'image_count': '图片数量',
            'link_count': '链接数量',
            'form_count': '表单数量',
            'external_links': '外部链接数',
            'sensitive_gambling': '赌博关键词',
            'sensitive_fraud': '诈骗关键词',
            'sensitive_pornography': '色情关键词',
            'sensitive_financial_fraud': '金融诈骗关键词',
            'sensitive_illegal_trade': '非法交易关键词',
            'sensitive_cybercrime': '网络犯罪关键词',
            'sensitive_违规书籍': '违规书籍关键词数量',
            'sensitive_网站违禁词': '网站违禁词数量',
            'sensitive_涉稳': '涉稳关键词数量',
            'sensitive_涉黄': '涉黄关键词数量',
            'sensitive_涉赌': '涉赌关键词数量',
            'sensitive_涉政': '涉政关键词数量',
            'sensitive_涉枪暴': '涉枪暴关键词数量',
            'sensitive_涉恐涉邪': '涉恐涉邪关键词数量',
            'sensitive_涉黑灰产': '涉黑灰产关键词数量',
            'sensitive_涉电诈': '涉电诈关键词数量',
            'sensitive_违规化学品': '违规化学品关键词数量',
            'sensitive_keyword_count': '敏感词总数',
            'sensitive_keyword_ratio': '敏感词占比',
            'sensitive_keyword_count': '敏感词总数',
            'sensitive_keyword_ratio': '敏感词占比',
            'has_title': '有标题',
            'title_length': '标题长度',
            'has_description': '有描述',
            'has_keywords': '有关键词',
            'has_robots': '有robots',
            'has_login_form': '有登录表单',
            'has_contact_info': '有联系信息',
            'has_privacy_policy': '有隐私政策',
            'suspicious_images': '可疑图片',
            'script_count': '脚本数量',
            'suspicious_scripts': '可疑脚本',
            'redirect_count': '重定向次数',
            'domain_changed': '域名变更',
            'has_ssl': '有SSL证书',
            'ssl_valid': 'SSL有效',
            'trusted_ca': '可信CA',
            'cert_valid_days': '证书有效天数',
            'cert_too_new': '证书太新',
            'ssl_domain_match': '域名匹配',
            'wildcard_cert': '通配符证书',
            'dns_resolved': 'DNS解析成功',
            'ip_count': 'IP数量',
            'first_ip': '首个IP',
            'blacklisted_ip': 'IP黑名单',
            'has_mx': '有MX记录',
            'mx_count': 'MX记录数',
            'has_spf': '有SPF记录',
            'web_accessible': '可访问',
            'response_time': '响应时间',
            'http_status': 'HTTP状态码',
            'server_header': '服务器信息',
            'powered_by': '技术栈',
            'hsts': 'HSTS安全头',
            'x_frame_options': 'X-Frame-Options',
            'x_content_type': 'X-Content-Type-Options',
            'x_xss_protection': 'X-XSS-Protection',
            'csp': 'Content-Security-Policy',
            'subpage_count': '检测子页面数量',
            'suspicious_subpages': '可疑子页面数',
            'avg_subpage_risk': '子页面平均风险',
            'has_sensitive_subpage': '包含敏感子页面',
            'subpage_keywords': '子页面中发现的关键词统计',
            'subpage_details': '子页面详细信息'
        }
        translated = {}
        for key, value in features.items():
            if key in translate_map:
                chinese_key = translate_map[key]
                if isinstance(value, (int, float)) and value != -1:
                    translated[chinese_key] = value
                elif value not in [None, '', -1]:
                    translated[chinese_key] = value
            elif key == 'url':
                translated['网址'] = value
            elif key == 'final_url':
                translated['最终网址'] = value
                
        return translated
    
    def detect_batch(self, urls):
        """批量检测"""
        self.results = []
        total = len(urls)
        
        logger.info(f"🚀 开始批量检测，共 {total} 个网站")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.detect_single, url): url for url in urls}
            
            for i, future in enumerate(as_completed(future_to_url), 1):
                result = future.result()
                self.results.append(result)
                
                # 获取中文风险等级用于进度显示
                risk_level = result.get('风险等级', '未知')
                url = result.get('网址', '未知网址')
                
                # 进度显示
                progress_bar = self._create_progress_bar(i, total)
                color_printer.print(f"{progress_bar} {i}/{total} - {url} - {risk_level}", 'cyan', bold=True)
        
        # 生成中文统计摘要
        stats = self._generate_chinese_summary(self.results)
        logger.info(stats)
        
        return self.results
    
    def _create_progress_bar(self, current, total, length=20):
        """创建进度条"""
        progress = current / total
        filled = int(length * progress)
        bar = '█' * filled + '░' * (length - filled)
        return f"[{bar}] {progress*100:.1f}%"
    
    def _generate_chinese_summary(self, results):
        """生成彩色中文统计摘要"""
        if not results:
            return "📊 无检测结果"
        
        total = len(results)
        
        # 统计各风险等级
        risk_counts = {}
        for result in results:
            risk_level = result.get('风险等级', '未知')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        summary_parts = []
        summary_parts.append("\n" + "=" * 60)
        summary_parts.append("📊 检测统计汇总".center(60))
        summary_parts.append("=" * 60)
        
        # 风险等级统计（带emoji和颜色）
        risk_emojis = {
            '高风险': ('🚨', 'red'),
            '中风险': ('⚠️', 'yellow'),
            '低风险': ('✅', 'green'),
            '检测失败': ('❌', 'magenta')
        }
        
        for risk_level, count in sorted(risk_counts.items()):
            emoji, color = risk_emojis.get(risk_level, ('•', 'white'))
            percentage = (count / total) * 100
            summary_parts.append(f"{emoji} {risk_level}: {count} 个 ({percentage:.1f}%)")
        
        summary_parts.append("-" * 60)
        
        # 安全建议和总结
        high_risk = risk_counts.get('高风险', 0)
        medium_risk = risk_counts.get('中风险', 0)
        
        if high_risk > 0:
            summary_parts.append("🚨 立即处理: 发现高风险网站，请立即处理！")
        if medium_risk > 0:
            summary_parts.append("⚠️ 谨慎访问: 发现中风险网站，建议进一步验证")
        if high_risk == 0 and medium_risk == 0:
            summary_parts.append("✅ 安全良好: 本次检测未发现明显风险网站")
            
        summary_parts.append("\n📋 建议操作:")
        summary_parts.append("1. 高风险网站：避免访问，立即加入黑名单")
        summary_parts.append("2. 中风险网站：谨慎访问，验证真实性")
        summary_parts.append("3. 低风险网站：可正常访问，但保持警惕")
        
        return '\n'.join(summary_parts)


    def save_results(self, output_prefix=None):
        """保存检测结果"""
        if not output_prefix:
            output_prefix = f"detection_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 保存JSON格式
        json_file = f"{output_prefix}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        # 保存CSV格式
        csv_file = f"{output_prefix}.csv"
        if self.results:
            import csv
            with open(csv_file, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                # 写入表头
                headers = ['网址', '风险等级', '风险评分', '检测时间']
                writer.writerow(headers)
                
                # 写入数据
                for result in self.results:
                    row = [
                        result.get('网址', ''),
                        result.get('风险等级', ''),
                        result.get('风险评分', ''),
                        result.get('检测时间', '')
                    ]
                    writer.writerow(row)
        # 新增：保存到数据库
        try:
            logger.info("正在保存结果到数据库...")
            save_results_to_database(self.results)
            logger.info("结果保存到数据库成功")
        except Exception as e:
            logger.error(f"保存结果到数据库时出错: {e}")
        
        return json_file, csv_file
    
    def generate_report(self):
        """生成中文检测报告"""
        if not self.results:
            return "无检测结果"
        
        report_lines = []
        
        # 报告标题
        report_lines.append("=" * 60)
        report_lines.append("🛡️ 违法网站检测报告".center(60))
        report_lines.append("=" * 60)
        report_lines.append(f"检测时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"检测网站总数: {len(self.results)} 个")
        report_lines.append("")
        
        # 风险等级统计
        risk_counts = {}
        for result in self.results:
            risk_level = result.get('风险等级', '未知')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        report_lines.append("📊 风险等级统计:")
        for risk_level, count in sorted(risk_counts.items()):
            percentage = (count / len(self.results)) * 100
            report_lines.append(f"  {risk_level}: {count} 个 ({percentage:.1f}%)")
        report_lines.append("")
        
        # 高风险网站详细分析
        high_risk_sites = [r for r in self.results if r.get('风险等级') == '高风险']
        if high_risk_sites:
            report_lines.append("🚨 高风险网站详情:")
            for site in high_risk_sites:
                report_lines.append(f"  • {site.get('网址', '')}")
                report_lines.append(f"    风险评分: {site.get('风险评分', '')}")
                report_lines.append(f"    风险描述: {site.get('风险描述', '').split(chr(10))[0]}")
                report_lines.append("")
        
        # 中风险网站列表
        medium_risk_sites = [r for r in self.results if r.get('风险等级') == '中风险']
        if medium_risk_sites:
            report_lines.append("⚠️ 中风险网站列表:")
            for site in medium_risk_sites:
                report_lines.append(f"  • {site.get('网址', '')}")
            report_lines.append("")
        
        # 检测失败网站
        failed_sites = [r for r in self.results if r.get('风险等级') == '检测失败']
        if failed_sites:
            report_lines.append("❌ 检测失败网站:")
            for site in failed_sites:
                report_lines.append(f"  • {site.get('网址', '')}")
                if '错误信息' in site:
                    report_lines.append(f"    错误: {site['错误信息']}")
            report_lines.append("")
        
        # 安全建议
        report_lines.append("💡 安全建议与处理方案:")
        if high_risk_sites:
            report_lines.append("  1. 高风险网站: 立即避免访问，加入黑名单")
            report_lines.append("  2. 通知相关人员: 将高风险网站信息分享给团队")
            report_lines.append("  3. 持续监控: 定期检查这些网站的状态")
        
        if medium_risk_sites:
            report_lines.append("  4. 中风险网站: 谨慎访问，建议人工验证")
            report_lines.append("  5. 二次检测: 24小时后重新检测中风险网站")
        
        report_lines.append("  6. 预防措施: 加强员工安全意识培训")
        report_lines.append("  7. 定期检测: 建议每周进行一次批量检测")
        report_lines.append("")
        
        # 后续行动计划
        report_lines.append("📅 后续行动计划:")
        report_lines.append("  • 立即: 处理所有高风险网站")
        report_lines.append("  • 24小时内: 人工验证中风险网站")
        report_lines.append("  • 本周内: 更新黑名单数据库")
        report_lines.append("  • 下周: 安排新一轮检测")
        
        return "\n".join(report_lines)

    def print_summary(self, results):
        """打印统计摘要"""
        if not results:
            return
            
        total = len(results)
        risk_counts = {}
        for result in results:
            risk_level = result.get('风险等级', '未知')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        print("\n" + "=" * 60)
        print("📊 检测统计汇总".center(60))
        print("=" * 60)
        
        risk_emojis = {
            '高风险': '🚨',
            '中风险': '⚠️',
            '低风险': '✅',
            '检测失败': '❌'
        }
        
        for risk_level, count in sorted(risk_counts.items()):
            emoji = risk_emojis.get(risk_level, '•')
            percentage = (count / total) * 100
            print(f"{emoji} {risk_level}: {count} 个 ({percentage:.1f}%)")
        
        print("-" * 60)
        
        high_risk = risk_counts.get('高风险', 0)
        medium_risk = risk_counts.get('中风险', 0)
        
        if high_risk > 0:
            print("🚨 立即处理: 发现高风险网站，请立即处理！")
        if medium_risk > 0:
            print("⚠️ 谨慎访问: 发现中风险网站，建议进一步验证")
        if high_risk == 0 and medium_risk == 0:
            print("✅ 安全良好: 本次检测未发现明显风险网站")

# 添加函数从MySQL数据库查询URL
def get_urls_from_mysql():
    """从MySQL数据库查询URL列表并进行去重，然后写入sample_urls.txt"""
    urls = []
    try:
        # 连接数据库
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            # 执行SQL查询
            sql = "select url from gat_illegal_result where  discovery_method not in (4,5)   and url not in (select url from gat_illegal_result_detector)   order by update_time desc   LIMIT 5"
            # sql = "select url from gat_illegal_result where  discovery_method not in (4,5)  LIMIT 5"
            cursor.execute(sql)
            # 获取所有查询结果
            results = cursor.fetchall()
            # 提取URLs
            urls = [row['url'] for row in results]
        
        # 对URL进行去重
        unique_urls = list(set(urls))
        
        # 将去重后的URL写入sample_urls.txt文件
        sample_urls_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_urls.txt')
        with open(sample_urls_path, 'w', encoding='utf-8') as f:
            for url in unique_urls:
                f.write(f"{url}\n")
        
        color_printer = ColorPrinter()
        color_printer.print_success(f"成功从数据库查询到 {len(urls)} 个URL，去重后剩余 {len(unique_urls)} 个")
        color_printer.print_success(f"已将去重后的URL写入 {sample_urls_path}")
        
        return unique_urls
    except Exception as e:
        color_printer = ColorPrinter()
        color_printer.print_error(f"从数据库查询URL或写入文件失败: {e}")
    finally:
        if 'connection' in locals() and connection.open:
            connection.close()
    return urls
# 创建检测结果表
def create_detector_result_table():
    """创建检测结果表"""
    try:
        # 连接数据库
        connection = pymysql.connect(**DB_CONFIG)
        try:
            with connection.cursor() as cursor:
                # 创建表的SQL语句，添加了表注释和字段注释
                create_table_sql = """
                CREATE TABLE IF NOT EXISTS gat_illegal_result_detector (
                    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '主键ID',
                    url VARCHAR(255) NOT NULL UNIQUE COMMENT '检测的网址',
                    risk_level VARCHAR(20) NOT NULL COMMENT '风险等级(低风险/中风险/高风险)',
                    risk_score INT NOT NULL COMMENT '风险评分(0-100)',
                    risk_description TEXT COMMENT '风险描述信息',
                    detection_time DATETIME NOT NULL COMMENT '检测时间',
                    domain_length INT COMMENT '域名长度',
                    subdomain_count INT COMMENT '子域名数量',
                    has_hyphen TINYINT(1) COMMENT '是否包含连字符',
                    has_digits TINYINT(1) COMMENT '是否包含数字',
                    suspicious_tld TINYINT(1) COMMENT '是否为可疑顶级域名',
                    digit_ratio FLOAT COMMENT '数字比例',
                    special_char_ratio FLOAT COMMENT '特殊字符比例',
                    consonant_ratio FLOAT COMMENT '辅音比例',
                    entropy FLOAT COMMENT '熵值(随机性)',
                    in_blacklist TINYINT(1) COMMENT '是否在黑名单中',
                    brand_similarity FLOAT COMMENT '品牌相似度',
                    potential_phishing TINYINT(1) COMMENT '是否疑似钓鱼',
                    homograph_attack TINYINT(1) COMMENT '是否存在同形异义攻击',
                    suspicious_combo INT COMMENT '可疑关键词组合数',
                    domain_age_days INT COMMENT '域名年龄(天)',
                    is_new_domain TINYINT(1) COMMENT '是否为新域名(30天内)',
                    is_very_new_domain TINYINT(1) COMMENT '是否为极新域名(7天内)',
                    days_to_expire INT COMMENT '到期剩余天数',
                    short_registration TINYINT(1) COMMENT '是否为短期注册(少于1年)',
                    suspicious_registrar TINYINT(1) COMMENT '是否为可疑注册商',
                    content_length INT COMMENT '内容长度',
                    text_length INT COMMENT '文本长度',
                    image_count INT COMMENT '图片数量',
                    link_count INT COMMENT '链接数量',
                    form_count INT COMMENT '表单数量',
                    external_links INT COMMENT '外部链接数',
                    sensitive_keyword_count INT COMMENT '敏感词总数',
                    sensitive_keyword_ratio FLOAT COMMENT '敏感词占比',
                    has_title TINYINT(1) COMMENT '是否有标题',
                    title_length INT COMMENT '标题长度',
                    has_description TINYINT(1) COMMENT '是否有描述',
                    has_keywords TINYINT(1) COMMENT '是否有关键词',
                    has_robots TINYINT(1) COMMENT '是否有robots.txt',
                    has_login_form TINYINT(1) COMMENT '是否有登录表单',
                    has_contact_info TINYINT(1) COMMENT '是否有联系信息',
                    has_privacy_policy TINYINT(1) COMMENT '是否有隐私政策',
                    suspicious_images TINYINT(1) COMMENT '是否有可疑图片',
                    script_count INT COMMENT '脚本数量',
                    suspicious_scripts TINYINT(1) COMMENT '是否有可疑脚本',
                    redirect_count INT COMMENT '重定向次数',
                    final_url VARCHAR(255) COMMENT '最终重定向后的网址',
                    domain_changed TINYINT(1) COMMENT '是否发生域名变更',
                    has_ssl TINYINT(1) COMMENT '是否有SSL证书',
                    ssl_valid TINYINT(1) COMMENT 'SSL证书是否有效',
                    trusted_ca TINYINT(1) COMMENT '是否为可信CA颁发',
                    cert_valid_days INT COMMENT '证书有效天数',
                    cert_too_new TINYINT(1) COMMENT '证书是否太新',
                    ssl_domain_match TINYINT(1) COMMENT '域名是否匹配',
                    wildcard_cert TINYINT(1) COMMENT '是否为通配符证书',
                    dns_resolved TINYINT(1) COMMENT 'DNS是否解析成功',
                    ip_count INT COMMENT 'IP数量',
                    first_ip VARCHAR(50) COMMENT '首个IP地址',
                    blacklisted_ip TINYINT(1) COMMENT 'IP是否在黑名单中',
                    has_mx TINYINT(1) COMMENT '是否有MX记录',
                    mx_count INT COMMENT 'MX记录数量',
                    has_spf TINYINT(1) COMMENT '是否有SPF记录',
                    response_time FLOAT COMMENT '响应时间(秒)',
                    http_status INT COMMENT 'HTTP状态码',
                    web_accessible TINYINT(1) COMMENT '网站是否可访问',
                    server_header VARCHAR(100) COMMENT '服务器信息',
                    hsts TINYINT(1) COMMENT '是否启用HSTS安全头',
                    x_frame_options TINYINT(1) COMMENT '是否设置X-Frame-Options',
                    x_content_type TINYINT(1) COMMENT '是否设置X-Content-Type-Options',
                    x_xss_protection TINYINT(1) COMMENT '是否设置X-XSS-Protection',
                    csp TINYINT(1) COMMENT '是否设置Content-Security-Policy',
                    sensitive_违规书籍 INT COMMENT '违规书籍关键词数量',
                    sensitive_网站违禁词 INT COMMENT '网站违禁词数量',
                    sensitive_涉稳 INT COMMENT '涉稳关键词数量',
                    sensitive_涉黄 INT COMMENT '涉黄关键词数量',
                    sensitive_涉赌 INT COMMENT '涉赌关键词数量',
                    sensitive_涉政 INT COMMENT '涉政关键词数量',
                    sensitive_涉枪暴 INT COMMENT '涉枪暴关键词数量',
                    sensitive_涉恐涉邪 INT COMMENT '涉恐涉邪关键词数量',
                    sensitive_涉黑灰产 INT COMMENT '涉黑灰产关键词数量',
                    sensitive_涉电诈 INT COMMENT '涉电诈关键词数量',
                    sensitive_违规化学品 INT COMMENT '违规化学品关键词数量',
                    subpage_count INT COMMENT '检测子页面数量',
                    suspicious_subpages INT COMMENT '可疑子页面数',
                    avg_subpage_risk FLOAT COMMENT '子页面平均风险',
                    has_sensitive_subpage TINYINT(1) COMMENT '是否包含敏感子页面',
                    subpage_keywords TEXT COMMENT '子页面关键词统计(JSON格式)',
                    subpage_details TEXT COMMENT '子页面详细信息(JSON格式)',
                    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
                ) COMMENT='违法网站检测结果表' 
                """
                cursor.execute(create_table_sql)
                connection.commit()
                logger.info("检测结果表创建成功")
        finally:
            connection.close()
    except Exception as e:
        logger.error(f"创建检测结果表失败: {e}")


def save_result_to_database(result):
    """保存检测结果到数据库，如果存在则更新，不存在则新增"""
    try:
        # 连接数据库
        connection = pymysql.connect(**DB_CONFIG)
        try:
            with connection.cursor() as cursor:
                # 检查记录是否存在
                check_sql = "SELECT id FROM gat_illegal_result_detector WHERE url = %s"
                cursor.execute(check_sql, (result['网址'],))
                exists = cursor.fetchone() is not None
                
                # 获取详细特征
                features = result['详细特征']
                en_features = result['英文原文']['features']
                # 将子页面特征转换为JSON字符串
            #     'subpage_keywords': '子页面中发现的关键词统计',
            # 'subpage_details': '子页面详细信息'
                subpage_keywords = json.dumps(features.get('子页面中发现的关键词统计', {}), ensure_ascii=False) if '子页面中发现的关键词统计' in features else None
                subpage_details = json.dumps(features.get('子页面详细信息', []), ensure_ascii=False) if '子页面详细信息' in features else None
                if exists:
                    # 更新记录
                    update_sql = """
                    UPDATE gat_illegal_result_detector
                    SET 
                        risk_level = %s,
                        risk_score = %s,
                        risk_description = %s,
                        detection_time = %s,
                        domain_length = %s,
                        subdomain_count = %s,
                        has_hyphen = %s,
                        has_digits = %s,
                        suspicious_tld = %s,
                        digit_ratio = %s,
                        special_char_ratio = %s,
                        consonant_ratio = %s,
                        entropy = %s,
                        in_blacklist = %s,
                        brand_similarity = %s,
                        potential_phishing = %s,
                        homograph_attack = %s,
                        suspicious_combo = %s,
                        domain_age_days = %s,
                        is_new_domain = %s,
                        is_very_new_domain = %s,
                        days_to_expire = %s,
                        short_registration = %s,
                        suspicious_registrar = %s,
                        content_length = %s,
                        text_length = %s,
                        image_count = %s,
                        link_count = %s,
                        form_count = %s,
                        external_links = %s,
                        sensitive_keyword_count = %s,
                        sensitive_keyword_ratio = %s,
                        has_title = %s,
                        title_length = %s,
                        has_description = %s,
                        has_keywords = %s,
                        has_robots = %s,
                        has_login_form = %s,
                        has_contact_info = %s,
                        has_privacy_policy = %s,
                        suspicious_images = %s,
                        script_count = %s,
                        suspicious_scripts = %s,
                        redirect_count = %s,
                        final_url = %s,
                        domain_changed = %s,
                        has_ssl = %s,
                        ssl_valid = %s,
                        trusted_ca = %s,
                        cert_valid_days = %s,
                        cert_too_new = %s,
                        ssl_domain_match = %s,
                        wildcard_cert = %s,
                        dns_resolved = %s,
                        ip_count = %s,
                        first_ip = %s,
                        blacklisted_ip = %s,
                        has_mx = %s,
                        mx_count = %s,
                        has_spf = %s,
                        response_time = %s,
                        http_status = %s,
                        web_accessible = %s,
                        server_header = %s,
                        hsts = %s,
                        x_frame_options = %s,
                        x_content_type = %s,
                        x_xss_protection = %s,
                        csp = %s,
                        sensitive_违规书籍 = %s,
                        sensitive_网站违禁词 = %s,
                        sensitive_涉稳 = %s,
                        sensitive_涉黄 = %s,
                        sensitive_涉赌 = %s,
                        sensitive_涉政 = %s,
                        sensitive_涉枪暴 = %s,
                        sensitive_涉恐涉邪 = %s,
                        sensitive_涉黑灰产 = %s,
                        sensitive_涉电诈 = %s,
                        sensitive_违规化学品 = %s,
                        subpage_count = %s,
                        suspicious_subpages = %s,
                        avg_subpage_risk = %s,
                        has_sensitive_subpage = %s,
                        subpage_keywords = %s,
                        subpage_details = %s

                    WHERE url = %s
                    """
                    
                    # 准备参数
                    params = (
                        result['风险等级'],
                        int(result['风险评分'].replace('%', '')),
                        result['风险描述'],
                        result['检测时间'],
                        features.get('域名长度'),
                        features.get('子域名数量'),
                        features.get('包含连字符'),
                        features.get('包含数字'),
                        features.get('可疑顶级域名'),
                        features.get('数字比例'),
                        features.get('特殊字符比例'),
                        features.get('辅音比例'),
                        features.get('熵值（随机性）'),
                        features.get('黑名单匹配'),
                        features.get('品牌相似度'),
                        features.get('疑似钓鱼'),
                        features.get('同形异义攻击'),
                        features.get('可疑关键词组合'),
                        features.get('域名年龄（天）'),
                        features.get('新域名（30天内）'),
                        features.get('极新域名（7天内）'),
                        features.get('到期剩余天数'),
                        features.get('短期注册'),
                        features.get('可疑注册商'),
                        features.get('内容长度'),
                        features.get('文本长度'),
                        features.get('图片数量'),
                        features.get('链接数量'),
                        features.get('表单数量'),
                        features.get('外部链接数'),
                        features.get('敏感词总数'),
                        features.get('敏感词占比'),
                        features.get('有标题'),
                        features.get('标题长度'),
                        features.get('有描述'),
                        features.get('有关键词'),
                        features.get('有robots'),
                        features.get('有登录表单'),
                        features.get('有联系信息'),
                        features.get('有隐私政策'),
                        features.get('可疑图片'),
                        features.get('脚本数量'),
                        features.get('可疑脚本'),
                        features.get('重定向次数'),
                        features.get('最终网址'),
                        features.get('域名变更'),
                        features.get('有SSL证书'),
                        features.get('SSL有效'),
                        features.get('可信CA'),
                        features.get('证书有效天数'),
                        features.get('证书太新'),
                        features.get('域名匹配'),
                        features.get('通配符证书'),
                        features.get('DNS解析成功'),
                        features.get('IP数量'),
                        features.get('首个IP'),
                        features.get('IP黑名单'),
                        features.get('有MX记录'),
                        features.get('MX记录数'),
                        features.get('有SPF记录'),
                        features.get('响应时间'),
                        features.get('HTTP状态码'),
                        features.get('可访问'),
                        features.get('服务器信息'),
                        features.get('HSTS安全头'),
                        features.get('X-Frame-Options'),
                        features.get('X-Content-Type-Options'),
                        features.get('X-XSS-Protection'),
                        features.get('Content-Security-Policy'),
                        en_features.get('sensitive_违规书籍'),
                        en_features.get('sensitive_网站违禁词'),
                        en_features.get('sensitive_涉稳'),
                        en_features.get('sensitive_涉黄'),
                        en_features.get('sensitive_涉赌'),
                        en_features.get('sensitive_涉政'),
                        en_features.get('sensitive_涉枪暴'),
                        en_features.get('sensitive_涉恐涉邪'),
                        en_features.get('sensitive_涉黑灰产'),
                        en_features.get('sensitive_涉电诈'),
                        en_features.get('sensitive_违规化学品'),
                        features.get('检测子页面数量'),
                        features.get('可疑子页面数'),
                        features.get('子页面平均风险'),
                        features.get('包含敏感子页面'),
                        subpage_keywords,
                        subpage_details,
                        result['网址']
                    )
                    
                    cursor.execute(update_sql, params)
                    logger.info(f"更新检测结果成功: {result['网址']}")
                else:
                    # 插入新记录
                    insert_sql = """
                    INSERT INTO gat_illegal_result_detector (
                        url,
                        risk_level,
                        risk_score,
                        risk_description,
                        detection_time,
                        domain_length,
                        subdomain_count,
                        has_hyphen,
                        has_digits,
                        suspicious_tld,
                        digit_ratio,
                        special_char_ratio,
                        consonant_ratio,
                        entropy,
                        in_blacklist,
                        brand_similarity,
                        potential_phishing,
                        homograph_attack,
                        suspicious_combo,
                        domain_age_days,
                        is_new_domain,
                        is_very_new_domain,
                        days_to_expire,
                        short_registration,
                        suspicious_registrar,
                        content_length,
                        text_length,
                        image_count,
                        link_count,
                        form_count,
                        external_links,
                        sensitive_keyword_count,
                        sensitive_keyword_ratio,
                        has_title,
                        title_length,
                        has_description,
                        has_keywords,
                        has_robots,
                        has_login_form,
                        has_contact_info,
                        has_privacy_policy,
                        suspicious_images,
                        script_count,
                        suspicious_scripts,
                        redirect_count,
                        final_url,
                        domain_changed,
                        has_ssl,
                        ssl_valid,
                        trusted_ca,
                        cert_valid_days,
                        cert_too_new,
                        ssl_domain_match,
                        wildcard_cert,
                        dns_resolved,
                        ip_count,
                        first_ip,
                        blacklisted_ip,
                        has_mx,
                        mx_count,
                        has_spf,
                        response_time,
                        http_status,
                        web_accessible,
                        server_header,
                        hsts,
                        x_frame_options,
                        x_content_type,
                        x_xss_protection,
                        csp,
                        sensitive_违规书籍,
                        sensitive_网站违禁词,
                        sensitive_涉稳,
                        sensitive_涉黄,
                        sensitive_涉赌,
                        sensitive_涉政,
                        sensitive_涉枪暴,
                        sensitive_涉恐涉邪,
                        sensitive_涉黑灰产,
                        sensitive_涉电诈,
                        sensitive_违规化学品,
                        subpage_count,
                        suspicious_subpages,
                        avg_subpage_risk,
                        has_sensitive_subpage,
                        subpage_keywords,
                        subpage_details
                    )VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    
                    # 准备参数（与更新时相同）
                    params = (
                        result['网址'],
                        result['风险等级'],
                        int(result['风险评分'].replace('%', '')),
                        result['风险描述'],
                        result['检测时间'],
                        features.get('域名长度'),
                        features.get('子域名数量'),
                        features.get('包含连字符'),
                        features.get('包含数字'),
                        features.get('可疑顶级域名'),
                        features.get('数字比例'),
                        features.get('特殊字符比例'),
                        features.get('辅音比例'),
                        features.get('熵值（随机性）'),
                        features.get('黑名单匹配'),
                        features.get('品牌相似度'),
                        features.get('疑似钓鱼'),
                        features.get('同形异义攻击'),
                        features.get('可疑关键词组合'),
                        features.get('域名年龄（天）'),
                        features.get('新域名（30天内）'),
                        features.get('极新域名（7天内）'),
                        features.get('到期剩余天数'),
                        features.get('短期注册'),
                        features.get('可疑注册商'),
                        features.get('内容长度'),
                        features.get('文本长度'),
                        features.get('图片数量'),
                        features.get('链接数量'),
                        features.get('表单数量'),
                        features.get('外部链接数'),
                        features.get('敏感词总数'),
                        features.get('敏感词占比'),
                        features.get('有标题'),
                        features.get('标题长度'),
                        features.get('有描述'),
                        features.get('有关键词'),
                        features.get('有robots'),
                        features.get('有登录表单'),
                        features.get('有联系信息'),
                        features.get('有隐私政策'),
                        features.get('可疑图片'),
                        features.get('脚本数量'),
                        features.get('可疑脚本'),
                        features.get('重定向次数'),
                        features.get('最终网址'),
                        features.get('域名变更'),
                        features.get('有SSL证书'),
                        features.get('SSL有效'),
                        features.get('可信CA'),
                        features.get('证书有效天数'),
                        features.get('证书太新'),
                        features.get('域名匹配'),
                        features.get('通配符证书'),
                        features.get('DNS解析成功'),
                        features.get('IP数量'),
                        features.get('首个IP'),
                        features.get('IP黑名单'),
                        features.get('有MX记录'),
                        features.get('MX记录数'),
                        features.get('有SPF记录'),
                        features.get('响应时间'),
                        features.get('HTTP状态码'),
                        features.get('可访问'),
                        features.get('服务器信息'),
                        features.get('HSTS安全头'),
                        features.get('X-Frame-Options'),
                        features.get('X-Content-Type-Options'),
                        features.get('X-XSS-Protection'),
                        features.get('Content-Security-Policy'),
                        en_features.get('sensitive_违规书籍'),
                        en_features.get('sensitive_网站违禁词'),
                        en_features.get('sensitive_涉稳'),
                        en_features.get('sensitive_涉黄'),
                        en_features.get('sensitive_涉赌'),
                        en_features.get('sensitive_涉政'),
                        en_features.get('sensitive_涉枪暴'),
                        en_features.get('sensitive_涉恐涉邪'),
                        en_features.get('sensitive_涉黑灰产'),
                        en_features.get('sensitive_涉电诈'),
                        en_features.get('sensitive_违规化学品'),
                        features.get('检测子页面数量'),
                        features.get('可疑子页面数'),
                        features.get('子页面平均风险'),
                        features.get('包含敏感子页面'),
                        subpage_keywords,
                        subpage_details
                    )
                    
                    cursor.execute(insert_sql, params)
                    logger.info(f"插入检测结果成功: {result['网址']}")
                
                connection.commit()
        finally:
            connection.close()
    except Exception as e:
        logger.error(f"保存检测结果到数据库失败: {e}")


def save_results_to_database(results):
    """批量保存检测结果到数据库"""
    try:
        # 确保表存在
        create_detector_result_table()
        
        # 批量保存结果
        for result in results:
            save_result_to_database(result)
    except pymysql.MySQLError as db_err:
        # 数据库特定错误处理
        logger.error(f"数据库错误: {db_err.args[0]}, {db_err.args[1]}")
        # 根据错误代码采取不同的恢复策略
        if db_err.args[0] == 1045:  # 访问被拒绝
            logger.error("数据库认证失败，请检查用户名和密码")
        elif db_err.args[0] == 1049:  # 数据库不存在
            logger.error("数据库不存在，请检查配置")
        # ... 其他数据库错误类型 ...
        raise
    except Exception as e:
        logger.error(f"保存检测结果失败: {str(e)}")
        raise



def main():
    """主函数 - 彩色输出版"""
    import argparse
    
    parser = argparse.ArgumentParser(description='违法网站批量检测工具 - 彩色输出版')
    parser.add_argument('-f', '--file', help='包含URL列表的文件')
    parser.add_argument('-u', '--urls', nargs='+', help='直接指定URL列表')
    parser.add_argument('-o', '--output', help='输出文件名前缀')
    parser.add_argument('-w', '--workers', type=int, default=10, help='并发工作线程数')
    
    args = parser.parse_args()
    
    # 彩色欢迎信息
    color_printer.print_header("🛡️ 违法网站批量检测系统 v2.0")
    color_printer.print("📋 功能特性:", 'cyan', bold=True)
    color_printer.print("• 多维度特征分析", 'white')
    color_printer.print("• 机器学习风险预测", 'white') 
    color_printer.print("• 实时彩色输出", 'white')
    color_printer.print("• 详细中文报告", 'white')
    print()
    # 从数据库更新恶意域名及恶意IP文件
    update_blacklist_from_db()
    # 获取URL列表
    urls = []
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            color_printer.print_success(f"成功读取 {len(urls)} 个URL")
        except Exception as e:
            color_printer.print_error(f"读取文件失败: {e}")
            return
    elif args.urls:
        urls = args.urls
        color_printer.print_success(f"检测到 {len(urls)} 个URL参数")
    else:
        # 使用示例URL进行测试
        urls = get_urls_from_mysql()
        # if not urls:
        #     # 如果从数据库获取失败，使用备用的示例URL
        #     color_printer.print_warning("从数据库获取URL失败，使用示例URL进行测试")
        #     urls = [
        #         "http://36guanxiang.com",
        #         "http://51dxjy.com", 
        #         "http://etdd.cn",
        #         "http://fast024.com",
        #         "http://gsmoyy.com",
        #         "http://hry.lmtc.work"
        #     ]
        #     color_printer.print_info("使用示例URL进行测试")
        # else:
        #     color_printer.print_info("从数据库获取URL成功")
    
    if not urls:
        color_printer.print_error("没有提供待检测的URL")
        return
    
    # 执行检测
    detector = BatchDetector(max_workers=args.workers)
    color_printer.print(f"🚀 开始检测 {len(urls)} 个网站...", 'cyan', bold=True)
    
    results = detector.detect_batch(urls)
    
    # 保存结果
    color_printer.print_info("正在保存检测结果...")
    json_file, csv_file = detector.save_results(args.output)
    
    # 生成并保存报告
    color_printer.print_info("正在生成检测报告...")
    report = detector.generate_report()
    
    # 保存报告
    report_file = f"{args.output or 'report'}_summary.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    # 彩色完成信息
    color_printer.print_header("🎉 检测完成！")
    color_printer.print(f"📁 结果文件:", 'cyan')
    color_printer.print(f"• JSON详细数据: {json_file}", 'white')
    color_printer.print(f"• CSV简要结果: {csv_file}", 'white')  
    color_printer.print(f"• 中文检测报告: {report_file}", 'white')
    
    # 显示最终统计
    detector.print_summary(results)

if __name__ == '__main__':
    # 设置信号处理，允许优雅退出
    def signal_handler(sig, frame):
        print('\n🛑 程序已停止')
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🚀 违法网站批量检测系统已启动")
    print("📅 定时任务：每隔10秒运行一次检测")
    print("⌨️  按 Ctrl+C 可以随时停止程序\n")
    
    # 定时任务主循环
    iteration = 1
    try:
        while True:
            print(f"\n🔄 第{iteration}轮检测开始")
            start_time = time.time()
            
            # 执行主检测逻辑
            main()
            
            # 计算本次执行耗时
            elapsed_time = time.time() - start_time
            print(f"✅ 第{iteration}轮检测完成，耗时: {elapsed_time:.2f}秒")
            
            # 增加轮次计数
            iteration += 1
            
            # 等待10秒后再次执行
            wait_time = 10
            print(f"⏳ 等待{wait_time}秒后进行下一轮检测...")
            time.sleep(wait_time)
            
    except Exception as e:
        print(f"❌ 程序运行出错: {e}")
        

    
