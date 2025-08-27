#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
违法网站检测器API接口
提供RESTful API，支持传入网址进行检测并返回结果
"""

import json
import logging
from flask import Flask, request, jsonify
from batch_website_detector import WebsiteDetector, BatchDetector, save_result_to_database, save_results_to_database
import time
import datetime

# 初始化Flask应用
app = Flask(__name__)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 初始化检测器
website_detector = WebsiteDetector()
batch_detector = BatchDetector()

@app.route('/api/detect', methods=['POST'])
def detect_website():
    """
    检测单个网站
    请求示例:
    {
        "url": "https://example.com",
        "save_to_db": true  # 可选参数，默认为true
    }
    
    返回示例:
    {
        "code": 200,
        "message": "success",
        "data": {
            "url": "https://example.com",
            "risk_level": "低风险",
            "risk_score": "25%",
            "risk_description": "...",
            "detection_time": "2023-07-01 12:00:00",
            "features": {},
            "saved_to_db": true
        }
    }
    """
    try:
        # 获取请求数据
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'code': 400,
                'message': '缺少必要参数: url'
            })
        
        url = data['url']
        save_to_db = data.get('save_to_db', True)  # 默认保存到数据库
        logger.info(f"接收到网站检测请求: {url}, 保存到数据库: {save_to_db}")
        
        # 标准化URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 提取特征
        features = website_detector.extract_all_features(url)
        
        # 预测风险
        risk_level, risk_score = website_detector.predict_risk(features)
        
        # 风险等级中文映射
        risk_level_cn = {
            'HIGH': '高风险',
            'MEDIUM': '中风险', 
            'LOW': '低风险',
            'ERROR': '检测失败'
        }.get(risk_level, risk_level)
        
        # 生成中文风险描述
        risk_description = batch_detector._generate_risk_description(features, risk_level, risk_score)
        
        # 构建完整的结果对象，用于数据库存储
        full_result = {
            '网址': url,
            '风险等级': risk_level_cn,
            '风险评分': f"{risk_score}%",
            '风险描述': risk_description,
            '检测时间': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            '详细特征': batch_detector._translate_features(features),
            '英文原文': {
                'url': url,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'features': features,
                'timestamp': datetime.datetime.now().isoformat()
            }
        }
        
        # 保存结果到数据库
        saved_to_db = False
        if save_to_db:
            try:
                save_result_to_database(full_result)
                saved_to_db = True
                logger.info(f"检测结果已保存到数据库: {url}")
            except Exception as db_err:
                logger.error(f"保存检测结果到数据库失败: {str(db_err)}")
                # 数据库保存失败不应影响API响应
        
        # 构建响应数据
        result = {
            'code': 200,
            'message': 'success',
            'data': {
                'url': url,
                'risk_level': risk_level_cn,
                'risk_score': f"{risk_score}%",
                'risk_description': risk_description,
                'detection_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'features': batch_detector._translate_features(features),
                'saved_to_db': saved_to_db
            }
        }
        
        logger.info(f"网站检测完成: {url}, 风险等级: {risk_level_cn}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"网站检测失败: {str(e)}")
        return jsonify({
            'code': 500,
            'message': f'检测失败: {str(e)}'
        })

@app.route('/api/batch_detect', methods=['POST'])
def batch_detect_websites():
    """
    批量检测网站
    请求示例:
    {
        "urls": ["https://example1.com", "https://example2.com"],
        "save_to_db": true  # 可选参数，默认为true
    }
    
    返回示例:
    {
        "code": 200,
        "message": "success",
        "data": [
            {
                "url": "https://example1.com",
                "risk_level": "低风险",
                "risk_score": "25%",
                "risk_description": "...",
                "detection_time": "2023-07-01 12:00:00",
                "saved_to_db": true
            },
            ...
        ]
    }
    """
    try:
        # 获取请求数据
        data = request.get_json()
        if not data or 'urls' not in data or not isinstance(data['urls'], list):
            return jsonify({
                'code': 400,
                'message': '缺少必要参数: urls (列表格式)'
            })
        
        urls = data['urls']
        save_to_db = data.get('save_to_db', True)  # 默认保存到数据库
        logger.info(f"接收到批量检测请求，共{len(urls)}个网站，保存到数据库: {save_to_db}")
        
        # 批量检测
        results = []
        full_results_for_db = []  # 用于数据库存储的完整结果列表
        
        for url in urls:
            try:
                # 使用detect_single方法检测单个网站
                result = batch_detector.detect_single(url)
                full_results_for_db.append(result)  # 保存完整结果用于数据库
                
                # 简化返回结果
                simplified_result = {
                    'url': result['网址'],
                    'risk_level': result['风险等级'],
                    'risk_score': result['风险评分'],
                    'risk_description': result['风险描述'],
                    'detection_time': result['检测时间'],
                    'saved_to_db': save_to_db  # 默认标记为已保存
                }
                results.append(simplified_result)
            except Exception as e:
                logger.error(f"网站检测失败: {url}, 错误: {str(e)}")
                results.append({
                    'url': url,
                    'risk_level': '检测失败',
                    'risk_score': '0%',
                    'risk_description': f'检测失败: {str(e)}',
                    'detection_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'saved_to_db': False  # 检测失败的网站不会保存到数据库
                })
        
        # 批量保存结果到数据库
        if save_to_db and full_results_for_db:
            try:
                save_results_to_database(full_results_for_db)
                logger.info(f"批量检测结果已保存到数据库，共{len(full_results_for_db)}条记录")
            except Exception as db_err:
                logger.error(f"批量保存检测结果到数据库失败: {str(db_err)}")
                # 更新返回结果中的保存状态
                for result in results:
                    result['saved_to_db'] = False
        
        return jsonify({
            'code': 200,
            'message': 'success',
            'data': results
        })
        
    except Exception as e:
        logger.error(f"批量检测失败: {str(e)}")
        return jsonify({
            'code': 500,
            'message': f'批量检测失败: {str(e)}'
        })

@app.route('/api/health', methods=['GET'])
def health_check():
    """\API健康检查接口"""
    return jsonify({
        'code': 200,
        'message': 'API服务运行正常',
        'timestamp': time.time()
    })

if __name__ == '__main__':
    # 从配置文件加载配置（如果有）
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            api_port = config.get('api_port', 11006)
    except:
        api_port = 11006
    
    # 启动API服务
    # 注意：生产环境应使用WSGI服务器如Gunicorn，此处仅用于开发测试
    print(f"\n🚀 违法网站检测器API服务启动成功！")
    print(f"📡 API服务运行在: http://localhost:{api_port}")
    print(f"🔍 检测单个网站: POST http://localhost:{api_port}/api/detect")
    print(f"📋 批量检测网站: POST http://localhost:{api_port}/api/batch_detect")
    print(f"❤️ 健康检查: GET http://localhost:{api_port}/api/health")
    
    # 注意：在生产环境中，应该将debug设置为False，并使用WSGI服务器
    app.run(host='0.0.0.0', port=api_port, debug=False)