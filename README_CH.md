# 网盾智检

"网盾智检 · 守护每一次点击" "CyberShield AI - Guarding Every Click"

基于多维度特征分析的自动化违法网站检测系统，整合了域名特征、内容分析、网络行为、证书验证等多个检测维度，能够高效识别各类违法违规网站。

## 📚 项目简介

网盾智检是一个全面的网站安全检测解决方案，通过采集和分析网站的多维度特征，实现对违法违规网站的快速识别和风险评估。系统采用了基于规则和机器学习相结合的检测方法，具有高度的准确性和扩展性。

适用于网络安全监管、企业安全防护、网站安全审计等多种场景，能够有效帮助用户识别潜在的网络安全风险。

## 🚀 功能特性

- **多维度检测**：基于7大维度特征的综合分析
- **批量处理**：支持大规模URL并行检测
- **实时评分**：动态风险评分和等级划分
- **机器学习**：集成随机森林等算法提高准确性
- **详细报告**：生成JSON、CSV、文本三种格式报告
- **并发优化**：支持多线程并发检测
- **定时任务**：支持定时自动执行检测任务
- **数据库集成**：可从数据库获取URL和敏感关键词
- **黑名单管理**：自动更新和管理恶意域名/IP黑名单
- **子页面分析**：深度检测网站子页面内容特征

## 📊 检测维度（增强版）

| 维度类别 | 检测指标 |
|---------|----------|
| **域名特征** | 域名年龄、拼写异常、可疑后缀、WHOIS信息、黑名单匹配、品牌钓鱼检测、同形异义字符攻击、域名熵值、注册商信誉 |
| **内容分析** | 分类关键词检测、页面质量、SSL证书增强检测、安全头检测、页面结构分析、重定向分析、恶意代码 |
| **网络特征** | DNS解析、响应时间、IP地址、HTTP状态、IP黑名单检查、邮件服务器检测、服务器指纹识别、可访问性测试 |
| **行为模式** | 访问异常、重定向链、资源加载、登录表单检测、联系信息完整性、隐私政策存在性、可疑图片检测、恶意脚本检测 |
| **子页面特征** | 子页面数量、敏感子页面检测、平均风险评分、关键词分布 |

## 🏗️ 系统架构

系统采用模块化设计，主要包含以下核心组件：

1. **数据采集模块**：负责获取网站内容、域名信息、网络特征等数据
2. **特征提取模块**：从采集的原始数据中提取有价值的特征
3. **风险评估模块**：基于规则和机器学习模型进行风险评分
4. **报告生成模块**：生成多格式的检测报告
5. **数据存储模块**：连接数据库进行数据读写和黑名单更新
6. **任务调度模块**：实现定时检测功能

## 🛠️ 快速开始

### 1. 环境准备

```bash
# 安装依赖
pip install -r requirements.txt

# 或使用conda
conda install --file requirements.txt
```

### 2. 配置黑名单（可选）
系统已预置黑名单文件：
- `blacklist_domains.txt` - 已知恶意域名列表
- `blacklist_ips.txt` - 已知恶意IP地址列表

您可以根据需要添加更多条目。系统也支持从数据库自动更新黑名单。

### 3. 数据库配置
系统支持从MySQL数据库获取URL和关键词信息，配置位于代码文件中的`DB_CONFIG`变量：

```python
# 数据库配置示例
DB_CONFIG = {
    'host': '192.168.2.41',  # 数据库主机地址
    'port': 3306,
    'user': 'root',       # 数据库用户名
    'password': 'your_password',  # 数据库密码
    'db': 'ntmv3',  # 数据库名称
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}
```

### 4. 基本使用

#### 方式一：检测单个URL
```python
from batch_website_detector import WebsiteDetector

detector = WebsiteDetector()
features = detector.extract_all_features("https://example.com")
risk_level, risk_score = detector.predict_risk(features)
print(f"风险等级: {risk_level}, 评分: {risk_score}%")
```

#### 方式二：批量检测文件
```bash
# 检测文件中的URL列表
python batch_website_detector.py -f sample_urls.txt -o results

# 直接指定URL检测
python batch_website_detector.py -u https://site1.com https://site2.com

# 指定并发线程数
python batch_website_detector.py -f urls.txt -w 20
```

#### 方式三：定时任务检测
系统支持定时自动执行检测任务，默认每10秒执行一次：

```bash
# 启动定时检测任务
python batch_website_detector.py

# 自定义检测间隔（秒）
python batch_website_detector.py --interval 30

# 仅执行一次检测（不启用定时）
python batch_website_detector.py --once
```

### 5. 使用测试脚本
```bash
# 运行完整测试
python test_detector.py

# 测试单个网站
python test_detector.py --single https://example.com

# 测试批量检测
python test_detector.py --batch sample_urls.txt
```

## 📋 输入输出格式

### 输入格式

#### URL列表文件格式
```
# 支持注释
https://www.google.com
https://www.baidu.com
https://example123.tk
```

#### 命令行参数
```bash
usage: batch_website_detector.py [-h] [-f FILE] [-u URLS [URLS ...]] 
                                [-o OUTPUT] [-w WORKERS] [--interval INTERVAL] [--once]

options:
  -h, --help            显示帮助信息
  -f FILE, --file FILE  包含URL列表的文件
  -u URLS [URLS ...], --urls URLS [URLS ...]
                        直接指定URL列表
  -o OUTPUT, --output OUTPUT
                        输出文件名前缀
  -w WORKERS, --workers WORKERS
                        并发工作线程数，默认10
  --interval INTERVAL   定时检测间隔（秒），默认10秒
  --once                仅执行一次检测，不启用定时
```

### 输出结果

#### 结果文件

检测完成后会生成三个文件：
- `{prefix}.json` - 完整检测结果（包含所有特征）
- `{prefix}.csv` - 简要结果（URL、风险等级、评分）
- `{prefix}_summary.txt` - 检测报告摘要

#### 风险等级

| 等级 | 分数范围 | 说明 |
|------|----------|------|
| **高风险** | 70-100% | 高风险，疑似违法网站 |
| **中风险** | 40-69% | 中风险，需进一步核实 |
| **低风险** | 0-39% | 低风险，相对安全 |

#### 示例输出

```json
{
  "网址": "https://example123.tk",
  "风险等级": "高风险",
  "风险评分": "75%",
  "风险描述": "🚨 该网站存在严重安全风险\n• 域名注册时间极短（7天内）\n• 包含敏感内容",
  "检测时间": "2024-01-15 10:30:00",
  "详细特征": {
    "域名长度": 15,
    "域名年龄（天）": 5,
    "可疑顶级域名": 1,
    "敏感词占比": 0.08,
    "有SSL证书": 0,
    ...
  }
}
```

## 🔧 高级配置

### 1. 自定义敏感关键词

系统支持从数据库加载关键词，也可以在`WebsiteDetector`类中修改关键词配置。

### 2. 调整风险评分权重

在`predict_risk`方法中调整各项因子的权重：

```python
# 域名风险因子
if features.get('is_new_domain', 0) == 1:
    risk_score += 25  # 调整权重
```

### 3. 训练机器学习模型

```python
# 准备训练数据
from sklearn.ensemble import RandomForestClassifier

# 特征和标签
X = [...]  # 特征矩阵
y = [...]  # 标签

# 训练模型
model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# 保存模型
joblib.dump(model, 'website_detection_model.pkl')
```

### 4. 定时任务配置

系统支持通过命令行参数配置定时检测间隔，也可以直接修改代码中的默认值：

```python
# 设置默认检测间隔（秒）
DEFAULT_INTERVAL = 10
```

## ⚡ 性能优化

### 1. 并发配置

- **低并发**（5-10线程）：适用于网络环境较差
- **中并发**（10-20线程）：平衡性能和稳定性
- **高并发**（20-50线程）：适用于大量检测任务

### 2. 缓存优化

```python
# 启用DNS缓存
import dns.resolver
dns.resolver.default_resolver.cache = dns.resolver.Cache()

# 启用请求缓存
import requests_cache
requests_cache.install_cache('website_cache', expire_after=3600)
```

### 3. 检测超时配置

可以调整各模块的超时时间以适应不同网络环境：

```python
# 设置默认超时时间
session_timeout = 10  # 秒
subpage_timeout = 8   # 秒
```


## 🤖 机器学习功能详解

CyberShield_AI 集成了机器学习算法以提高检测准确性，采用随机森林
等算法构建风险评估模型。

### 模型使用机制

系统采用双模式智能切换机制：
- **自动检测模型**：初始化时自动检查 
`website_detection_model.pkl` 文件
- **智能切换**：存在有效模型时使用机器学习预测，否则自动切换到增
强版规则算法
- **无缝运行**：两种模式之间的切换对用户完全透明，确保系统始终可
靠运行

### 获取和使用机器学习模型

#### 方式一：自行训练模型

1. **准备训练数据**
   - 收集已知风险等级的网站样本
   - 为每个样本标注风险标签（0=低风险, 1=高风险）

2. **训练模型代码示例**
   ```python
   # 准备训练数据
   from sklearn.ensemble import RandomForestClassifier
   import joblib
   
   # 特征和标签（需自行收集和标注）
   X = [...]  # 特征矩阵，与_prepare_features_for_model方
   法输出格式一致
   y = [...]  # 风险标签
   
   # 训练随机森林模型
   model = RandomForestClassifier(n_estimators=100, 
   random_state=42)
   model.fit(X, y)
   
   # 保存模型到项目根目录
   joblib.dump(model, 'website_detection_model.pkl')
```
3. 
方式一：放置模型文件 将训练好的 website_detection_model.pkl 文件放入项目根目录，系统会自动加载使用 
方式二：使用预训练模型（未来版本支持）
目前系统暂不提供官方预训练模型下载，用户需自行训练或使用规则引擎。未来版本计划提供模型下载功能。

### 特征向量说明
模型使用的特征向量由 _prepare_features_for_model() 方法生成，包含以下核心特征：

- 域名特征（长度、子域名数、特殊字符比例等）
- 内容特征（文本长度、图片数量、敏感关键词比例等）
- 网络特征（响应时间、HTTP状态码、SSL证书状态等）
- 安全特征（安全头配置、可访问性等）
### 模型性能优化建议
1. 样本数量 ：建议训练样本数量不少于1000个，以保证模型稳定性
2. 特征工程 ：根据实际检测场景调整 _prepare_features_for_model() 中的特征列表
3. 模型调优 ：调整随机森林的 n_estimators 等参数以获得最佳性能
4. 定期更新 ：建议每3-6个月更新一次模型，以适应新的攻击模式

## 🚨 注意事项

1. **网络权限**：确保有访问外网的权限
2. **DNS配置**：检查本地DNS配置是否正确
3. **防火墙**：可能需要配置防火墙允许相关端口
4. **频率限制**：避免过快的检测频率触发目标网站防护
5. **法律合规**：仅用于合法的安全检测目的
6. **资源占用**：大规模检测时注意系统资源占用情况

## 📞 技术支持

### 常见问题

**Q: 检测速度很慢怎么办？**
A: 调整`-w`参数减少并发线程，或检查网络连接

**Q: 出现SSL证书验证错误？**
A: 更新系统的CA证书包或临时禁用SSL验证

**Q: 如何添加新的检测维度？**
A: 在`WebsiteDetector`类中添加新的特征提取方法

**Q: 检测结果不准确？**
A: 收集更多训练数据重新训练机器学习模型

**Q: 定时任务如何停止？**
A: 使用Ctrl+C组合键优雅退出定时任务

### 更新日志

- v1.0.0 - 初始版本，包含基础检测功能
- v1.1.0 - 增加机器学习模型支持
- v1.2.0 - 优化并发性能和报告生成
- v1.3.0 - 新增子页面深度检测功能
- v1.4.0 - 增加数据库集成和定时任务功能

## 📄 许可证

本项目采用 GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007 许可证。

详细许可证信息请参阅项目根目录下的 LICENSE 文件。

本项目仅供学习和研究使用，请确保在合法范围内使用。
        