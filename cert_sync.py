#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
阿里云SSL证书自动同步到K8s各namespace的Secret
每天0点执行，自动发现所有包含 *.sisensing.com 证书的 TLS Secret，比对指纹，不一致则更新
"""

import os
import sys
import base64
import hashlib
import logging
import time
from datetime import datetime

# 强制 stdout 使用 UTF-8
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from alibabacloud_cas20200407.client import Client as CasClient
from alibabacloud_cas20200407 import models as cas_models
from alibabacloud_tea_openapi import models as open_api_models
from kubernetes import client, config
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# 环境变量配置
ALIBABA_AK = os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"]
ALIBABA_SK = os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"]
ALIBABA_REGION = os.environ.get("ALIBABA_CLOUD_REGION", "cn-hangzhou")

CERT_DOMAINS = [d.strip() for d in os.environ.get("CERT_DOMAIN", "*.sisensing.com").split(",")]
# 排除的命名空间
EXCLUDE_NAMESPACES = os.environ.get("EXCLUDE_NAMESPACES", "kube-system,kube-public,kube-node-lease").split(",")


def create_cas_client():
    """创建阿里云SSL证书客户端"""
    cfg = open_api_models.Config(
        access_key_id=ALIBABA_AK,
        access_key_secret=ALIBABA_SK,
        region_id=ALIBABA_REGION,
        endpoint="cas.aliyuncs.com"
    )
    return CasClient(cfg)


def get_latest_cert_from_aliyun():
    """从阿里云获取所有目标域名的最新证书"""
    cas_client = create_cas_client()
    results = {}

    for cert_domain in CERT_DOMAINS:
        request = cas_models.ListUserCertificateOrderRequest(
            status="ISSUED",
            keyword=cert_domain.replace("*.", ""),
            order_type="CERT",
            current_page=1,
            show_size=50
        )
        response = cas_client.list_user_certificate_order(request)
        cert_list = response.body.certificate_order_list

        if not cert_list:
            logger.error(f"未找到域名 {cert_domain} 的有效证书")
            continue

        latest_cert = None
        for cert in cert_list:
            if cert_domain in (cert.domain or "") or cert_domain.replace("*.", "") in (cert.sans or ""):
                if latest_cert is None or cert.cert_end_time > latest_cert.cert_end_time:
                    latest_cert = cert

        if not latest_cert:
            logger.error(f"未找到匹配 {cert_domain} 的证书")
            continue

        logger.info(f"找到证书: ID={latest_cert.certificate_id}, 域名={latest_cert.domain}, "
                    f"过期时间={latest_cert.cert_end_time}")

        detail_request = cas_models.GetUserCertificateDetailRequest(
            cert_id=latest_cert.certificate_id
        )
        detail_response = cas_client.get_user_certificate_detail(detail_request)

        results[cert_domain] = {
            "cert": detail_response.body.cert,
            "key": detail_response.body.key,
            "cert_id": latest_cert.certificate_id,
            "domain": latest_cert.domain,
            "end_time": latest_cert.cert_end_time
        }

    return results if results else None


def get_cert_fingerprint(cert_pem):
    """计算证书 SHA256 指纹"""
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def get_cert_domains(cert_pem):
    """解析证书中的域名（CN + SAN）"""
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        domains = set()

        # 获取 CN
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                domains.add(attr.value)

        # 获取 SAN
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for dns in san.value.get_values_for_type(x509.DNSName):
                domains.add(dns)
        except x509.ExtensionNotFound:
            pass

        return domains
    except Exception:
        return set()


def is_target_cert(cert_pem):
    """判断证书是否是目标域名的证书，返回匹配的域名或 None"""
    domains = get_cert_domains(cert_pem)
    logger.info(f"解析证书获取到域名: {domains}")
    for cert_domain in CERT_DOMAINS:
        target_base = cert_domain.replace("*.", "")
        for domain in domains:
            if domain == cert_domain or domain.endswith(target_base):
                return cert_domain
    return None


def get_k8s_client():
    """获取 K8s 客户端"""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def discover_target_secrets(v1):
    """自动发现所有命名空间中包含目标域名证书的 TLS Secret"""
    targets = []

    all_secrets = v1.list_secret_for_all_namespaces(field_selector="type=kubernetes.io/tls")

    for secret in all_secrets.items:
        ns = secret.metadata.namespace
        name = secret.metadata.name
        logger.info(f"当前namespace: {ns} 下secret: {name}")

        if ns in EXCLUDE_NAMESPACES:
            continue

        cert_data = secret.data.get("tls.crt")
        if not cert_data:
            continue

        try:
            cert_pem = base64.b64decode(cert_data)
            matched_domain = is_target_cert(cert_pem)
            if matched_domain:
                fingerprint = get_cert_fingerprint(cert_pem)
                targets.append({
                    "namespace": ns,
                    "secret_name": name,
                    "fingerprint": fingerprint,
                    "matched_domain": matched_domain
                })
        except Exception as e:
            logger.warning(f"解析 {ns}/{name} 证书失败: {e}")
            continue

    return targets


def update_secret(v1, namespace, secret_name, cert_pem, key_pem, domain):
    """更新 K8s TLS Secret"""
    secret_data = {
        "tls.crt": base64.b64encode(cert_pem.encode()).decode(),
        "tls.key": base64.b64encode(key_pem.encode()).decode(),
    }

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            annotations={
                "cert-sync/last-updated": datetime.utcnow().isoformat(),
                "cert-sync/domain": domain,
                "cert-sync/source": "alibaba-cloud-cas",
            }
        ),
        type="kubernetes.io/tls",
        data=secret_data
    )

    v1.replace_namespaced_secret(secret_name, namespace, secret)
    logger.info(f"✅ 已更新 {namespace}/{secret_name}")


# 运行模式: k8s / docker / emqx / all，支持逗号分隔多选，如 k8s,emqx
SYNC_MODES = [m.strip() for m in os.environ.get("SYNC_MODE", "all").split(",")]


def sync_k8s(certs_map):
    """同步 K8s Secret"""
    logger.info("[K8s] 开始同步...")
    v1 = get_k8s_client()
    targets = discover_target_secrets(v1)
    logger.info(f"[K8s] 发现 {len(targets)} 个目标 Secret:")
    for t in targets:
        logger.info(f"  - {t['namespace']}/{t['secret_name']} ({t['matched_domain']})")

    if not targets:
        logger.warning("[K8s] 未发现任何使用目标域名证书的 Secret")
        return 0, 0, 0

    updated = 0
    skipped = 0
    failed = 0

    for t in targets:
        ns = t["namespace"]
        name = t["secret_name"]
        domain = t["matched_domain"]

        cert_info = certs_map.get(domain)
        if not cert_info:
            logger.warning(f"⚠️  {ns}/{name} 匹配域名 {domain} 但未获取到阿里云证书，跳过")
            skipped += 1
            continue

        aliyun_fingerprint = get_cert_fingerprint(cert_info["cert"])
        if t["fingerprint"] == aliyun_fingerprint:
            logger.info(f"⏭️  {ns}/{name} 证书一致，跳过")
            skipped += 1
            continue

        logger.info(f"🔄 {ns}/{name} 证书不一致，开始更新...")
        try:
            update_secret(v1, ns, name, cert_info["cert"], cert_info["key"], domain)
            updated += 1
        except Exception as e:
            logger.error(f"❌ {ns}/{name} 更新失败: {e}")
            failed += 1

    return updated, skipped, failed


def sync_docker(certs_map):
    """同步 Docker Nginx 容器"""
    logger.info("[Docker] 开始同步...")
    try:
        from docker_nginx_sync import sync_docker_nginx
        return sync_docker_nginx(certs_map)
    except ImportError:
        logger.error("[Docker] docker_nginx_sync 模块未找到")
        return 0, 0, 0
    except Exception as e:
        logger.error(f"[Docker] 同步失败: {e}")
        return 0, 0, 0


def sync_emqx(certs_map):
    """同步 EMQX Cloud TLS 证书"""
    logger.info("[EMQX] 开始同步...")
    try:
        from emqx_cloud_sync import sync_emqx_cloud
        return sync_emqx_cloud(certs_map)
    except ImportError:
        logger.error("[EMQX] emqx_cloud_sync 模块未找到")
        return 0, 0, 0
    except Exception as e:
        logger.error(f"[EMQX] 同步失败: {e}")
        return 0, 0, 0


def sync_intl(certs_map):
    """同步阿里云国际站证书"""
    logger.info("[INTL] 开始同步...")
    try:
        from aliyun_intl_sync import sync_aliyun_intl
        return sync_aliyun_intl(certs_map)
    except ImportError:
        logger.error("[INTL] aliyun_intl_sync 模块未找到")
        return 0, 0, 0
    except Exception as e:
        logger.error(f"[INTL] 同步失败: {e}")
        return 0, 0, 0


def sync_certs():
    """主同步逻辑"""
    logger.info("=" * 50)
    logger.info(f"开始证书同步任务，目标域名: {CERT_DOMAINS}，模式: {SYNC_MODES}")

    # 1. 从阿里云获取所有目标域名的最新证书
    certs_map = get_latest_cert_from_aliyun()
    if not certs_map:
        logger.error("获取阿里云证书失败，退出")
        return

    for domain, info in certs_map.items():
        fingerprint = get_cert_fingerprint(info["cert"])
        logger.info(f"阿里云证书 [{domain}] 指纹: {fingerprint[:16]}...")

    total_updated = 0
    total_skipped = 0
    total_failed = 0

    run_all = "all" in SYNC_MODES

    # 2. K8s 同步
    if run_all or "k8s" in SYNC_MODES:
        try:
            u, s, f = sync_k8s(certs_map)
            total_updated += u
            total_skipped += s
            total_failed += f
        except Exception as e:
            logger.error(f"[K8s] 同步异常: {e}")

    # 3. Docker Nginx 同步
    if run_all or "docker" in SYNC_MODES:
        try:
            u, s, f = sync_docker(certs_map)
            total_updated += u
            total_skipped += s
            total_failed += f
        except Exception as e:
            logger.error(f"[Docker] 同步异常: {e}")

    # 4. EMQX Cloud 同步
    if run_all or "emqx" in SYNC_MODES:
        try:
            u, s, f = sync_emqx(certs_map)
            total_updated += u
            total_skipped += s
            total_failed += f
        except Exception as e:
            logger.error(f"[EMQX] 同步异常: {e}")

    # 5. 阿里云国际站同步
    if run_all or "intl" in SYNC_MODES:
        try:
            u, s, f = sync_intl(certs_map)
            total_updated += u
            total_skipped += s
            total_failed += f
        except Exception as e:
            logger.error(f"[INTL] 同步异常: {e}")

    logger.info(f"全部同步完成: 更新={total_updated}, 跳过={total_skipped}, 失败={total_failed}")


if __name__ == "__main__":
    sync_certs()

