#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
阿里云SSL证书自动同步到 EMQX Cloud 托管部署
通过 EMQX Cloud API 更新指定部署的 TLS 证书
API文档: https://docs.emqx.com/zh/cloud/latest/api/tls_certificate.html
"""

import os
import logging
import hashlib
from datetime import datetime

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# EMQX Cloud 配置
EMQX_API_BASE = os.environ.get("EMQX_API_BASE", "https://cloud.emqx.com")
EMQX_API_KEY = os.environ.get("EMQX_API_KEY", "")
EMQX_API_SECRET = os.environ.get("EMQX_API_SECRET", "")
# 多个 deployment_id 用逗号分隔
EMQX_DEPLOYMENT_IDS = [d.strip() for d in os.environ.get("EMQX_DEPLOYMENT_IDS", "").split(",") if d.strip()]


def get_current_cert(deployment_id):
    """获取指定部署当前的 TLS 证书信息"""
    url = f"{EMQX_API_BASE}/deployments/{deployment_id}/tls"
    resp = requests.get(url, auth=(EMQX_API_KEY, EMQX_API_SECRET), timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_cert_fingerprint(cert_pem):
    """计算证书 SHA256 指纹"""
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def update_tls_cert(deployment_id, cert_pem, key_pem):
    """为指定部署更新 TLS 证书"""
    url = f"{EMQX_API_BASE}/deployments/{deployment_id}/tls"
    payload = {
        "tlsType": "one-way",
        "cert": cert_pem,
        "key": key_pem
    }
    resp = requests.put(
        url,
        json=payload,
        auth=(EMQX_API_KEY, EMQX_API_SECRET),
        timeout=60
    )
    resp.raise_for_status()
    return resp.json()


def sync_emqx_cloud(certs_map):
    """同步 EMQX Cloud 部署的 TLS 证书"""
    if not EMQX_API_KEY or not EMQX_API_SECRET:
        logger.warning("[EMQX] 未配置 EMQX_API_KEY/EMQX_API_SECRET，跳过")
        return 0, 0, 0

    if not EMQX_DEPLOYMENT_IDS:
        logger.warning("[EMQX] 未配置 EMQX_DEPLOYMENT_IDS，跳过")
        return 0, 0, 0

    # 使用第一个域名的证书（EMQX Cloud 通常绑定一个自定义域名）
    cert_domain = os.environ.get("EMQX_CERT_DOMAIN", "").strip()
    if not cert_domain:
        # 默认取 certs_map 的第一个
        cert_domain = list(certs_map.keys())[0]

    cert_info = certs_map.get(cert_domain)
    if not cert_info:
        logger.error(f"[EMQX] 未找到域名 {cert_domain} 的证书")
        return 0, 0, 0

    aliyun_expire_raw = cert_info.get("end_time", "")
    if isinstance(aliyun_expire_raw, (int, float)):
        aliyun_expire_log = datetime.fromtimestamp(aliyun_expire_raw / 1000).strftime("%Y-%m-%d %H:%M:%S")
    else:
        aliyun_expire_log = str(aliyun_expire_raw)
    logger.info(f"[EMQX] 阿里云证书过期时间: {aliyun_expire_log}")

    updated = 0
    skipped = 0
    failed = 0

    for deployment_id in EMQX_DEPLOYMENT_IDS:
        logger.info(f"[EMQX] 检查部署: {deployment_id}")
        try:
            # 获取当前证书信息（API 只返回 cn, expire, status, tlsType，不返回证书内容）
            current = get_current_cert(deployment_id)
            current_expire = current.get("expire", "")
            current_cn = current.get("cn", "")

            # 阿里云 end_time 是毫秒时间戳，转为格式化字符串比较
            aliyun_expire_raw = cert_info.get("end_time", "")
            if isinstance(aliyun_expire_raw, (int, float)):
                aliyun_expire = datetime.fromtimestamp(aliyun_expire_raw / 1000).strftime("%Y-%m-%d %H:%M:%S")
            else:
                aliyun_expire = str(aliyun_expire_raw)[:19]

            logger.info(f"  当前证书: cn={current_cn}, expire={current_expire}")
            logger.info(f"  阿里云证书: expire={aliyun_expire}")

            if current_expire and aliyun_expire:
                if current_expire[:19] == aliyun_expire[:19]:
                    logger.info(f"  ⏭️  部署 {deployment_id} 证书过期时间一致，跳过")
                    skipped += 1
                    continue

            # 更新证书
            logger.info(f"  🔄 部署 {deployment_id} 证书不一致，开始更新...")
            update_tls_cert(deployment_id, cert_info["cert"], cert_info["key"])
            logger.info(f"  ✅ 部署 {deployment_id} TLS 证书更新成功")
            updated += 1

        except requests.HTTPError as e:
            logger.error(f"  ❌ 部署 {deployment_id} 更新失败: {e.response.status_code} {e.response.text}")
            failed += 1
        except Exception as e:
            logger.error(f"  ❌ 部署 {deployment_id} 更新异常: {e}")
            failed += 1

    return updated, skipped, failed
