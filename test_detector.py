#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
违法网站检测器测试脚本
"""

import sys
import os
from batch_website_detector import BatchDetector, WebsiteDetector

def test_single_detection():
    """测试单个网站检测"""
    print("=== 测试单个网站检测 ===")
    
    detector = WebsiteDetector()
    test_urls = [
        "http://36guanxiang.com",
        "http://51dxjy.com",
        "http://etdd.cn", 
        "http://fast024.com",  
        "http://gsmoyy.com", 
        "http://hry.lmtc.work"
    ]
    
    for url in test_urls:
        print(f"\n检测网站: {url}")
        try:
            features = detector.extract_all_features(url)
            risk_level, risk_score = detector.predict_risk(features)
            
            print(f"风险等级: {risk_level}")
            print(f"风险评分: {risk_score}%")
            print(f"域名年龄: {features.get('domain_age_days', '未知')} 天")
            print(f"SSL证书: {'有' if features.get('has_ssl') else '无'}")
            print(f"敏感词比例: {features.get('sensitive_keyword_ratio', 0):.3f}")
            
        except Exception as e:
            print(f"检测失败: {e}")

def test_batch_detection():
    """测试批量检测"""
    print("\n=== 测试批量检测 ===")

    # 使用示例URL
    test_urls = [
        "http://36guanxiang.com",
        "http://51dxjy.com",
        "http://etdd.cn", 
        "http://fast024.com",  
        "http://gsmoyy.com", 
        "http://hry.lmtc.work"
    ]
    
    detector = BatchDetector(max_workers=5)
    results = detector.detect_batch(test_urls)
    
    print(f"\n检测完成，共检测 {len(results)} 个网站")
    
    # 统计结果
    risk_stats = {}
    for result in results:
        level = result['risk_level']
        risk_stats[level] = risk_stats.get(level, 0) + 1
        print(f"{result['url']} -> {level} ({result['risk_score']}%)")
    
    print(f"\n风险统计:")
    for level, count in risk_stats.items():
        print(f"  {level}: {count} 个")

def test_from_file():
    """测试从文件读取URL"""
    print("\n=== 测试从文件检测 ===")
    
    if os.path.exists("sample_urls.txt"):
        detector = BatchDetector(max_workers=3)
        
        # 读取URL
        with open("sample_urls.txt", 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"从文件读取到 {len(urls)} 个URL")
        
        # 执行检测
        results = detector.detect_batch(urls[:5])  # 只检测前5个
        
        # 保存结果
        json_file, csv_file = detector.save_results("test_results")
        
        print(f"结果已保存到: {json_file}, {csv_file}")
    else:
        print("sample_urls.txt 文件不存在")

if __name__ == '__main__':
    print("违法网站检测器测试")
    print("=" * 50)
    
    try:
        test_single_detection()
        test_batch_detection()
        test_from_file()
        
        print("\n" + "=" * 50)
        print("测试完成！")
        
    except KeyboardInterrupt:
        print("\n用户中断测试")
    except Exception as e:
        print(f"测试出错: {e}")