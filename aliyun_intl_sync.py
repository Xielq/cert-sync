#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
阿里云国际站 SSL 证书同步
校验国际站上传的证书是否和国内阿里云的证书一致，不一致则原地更新（保持证书ID不变，ALB引用不受影响）
"""

import os
import hashlib
import logging

from alibabacloud_cas20200407.client import Client as CasClient
from alibabacloud_cas20200407 import models as cas_models
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_tea_util import models as util_models
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# 国际站配置（可使用独立的 AK/SK，也可复用国内站的）
INTL_AK = os.environ.get("ALIBABA_CLOUD_INTL_ACCESS_KEY_ID", os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID", ""))
INTL_SK = os.environ.get("ALIBABA_CLOUD_INTL_ACCESS_KEY_SECRET", os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", ""))
INTL_REGION = os.environ.get("ALIBABA_CLOUD_INTL_REGION", "ap-southeast-1")
INTL_CERT_NAME_PREFIX = os.environ.get("INTL_CERT_NAME_PREFIX", "cert-sync")


def create_intl_cas_client():
    """创建阿里云国际站 SSL 证书客户端"""
    cfg = open_api_models.Config(
        access_key_id=INTL_AK,
        access_key_secret=INTL_SK,
        region_id=INTL_REGION,
        endpoint="cas.ap-southeast-1.aliyuncs.com"
    )
    return CasClient(cfg)


def get_cert_fingerprint(cert_pem):
    """计算证书 SHA256 指纹"""
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def list_intl_certs(cas_client, keyword):
    """列出国际站已上传的证书"""
    request = cas_models.ListUserCertificateOrderRequest(
        status="ISSUED",
        keyword=keyword,
        order_type="UPLOAD",
        current_page=1,
        show_size=50
    )
    response = cas_client.list_user_certificate_order(request)
    return response.body.certificate_order_list or []


def get_intl_cert_detail(cas_client, cert_id):
    """获取国际站证书详情"""
    request = cas_models.GetUserCertificateDetailRequest(cert_id=cert_id)
    response = cas_client.get_user_certificate_detail(request)
    return response.body


def update_intl_cert(cas_client, cert_id, name, cert_pem, key_pem):
    """原地更新国际站证书（保持证书ID不变，ALB引用不受影响）"""
    # 使用通用 OpenAPI 调用 UpdateUserCertificate
    from alibabacloud_tea_openapi.client import Client as OpenApiClient
    from alibabacloud_openapi_util.client import Client as OpenApiUtilClient
    import alibabacloud_tea_openapi.models as open_models

    cfg = open_api_models.Config(
        access_key_id=INTL_AK,
        access_key_secret=INTL_SK,
        region_id=INTL_REGION,
        endpoint="cas.ap-southeast-1.aliyuncs.com"
    )
    client = OpenApiClient(cfg)

    params = open_models.Params(
        action="UploadUserCertificate",
        version="2020-04-07",
        protocol="HTTPS",
        method="POST",
        auth_type="AK",
        style="RPC",
        pathname="/",
        req_body_type="formData",
        body_type="json"
    )

    body = {
        "CertId": cert_id,
        "Name": name,
        "Cert": cert_pem,
        "Key": key_pem
    }

    request = open_models.OpenApiRequest(body=OpenApiUtilClient.parse_to_map(body))
    runtime = util_models.RuntimeOptions()
    response = client.call_api(params, request, runtime)
    return response.get("body", {})


def upload_intl_cert(cas_client, name, cert_pem, key_pem):
    """上传新证书到国际站"""
    request = cas_models.UploadUserCertificateRequest(
        name=name,
        cert=cert_pem,
        key=key_pem
    )
    response = cas_client.upload_user_certificate(request)
    return response.body.cert_id


def sync_aliyun_intl(certs_map):
    """同步阿里云国际站证书"""
    if not INTL_AK or not INTL_SK:
        logger.warning("[INTL] 未配置国际站 AK/SK，跳过")
        return 0, 0, 0

    cas_client = create_intl_cas_client()

    updated = 0
    skipped = 0
    failed = 0

    for cert_domain, cert_info in certs_map.items():
        logger.info(f"[INTL] 检查域名: {cert_domain}")

        aliyun_fingerprint = get_cert_fingerprint(cert_info["cert"])
        logger.info(f"  国内站证书指纹: {aliyun_fingerprint[:16]}...")

        # 搜索国际站中该域名的证书
        keyword = cert_domain.replace("*.", "")
        intl_certs = list_intl_certs(cas_client, keyword)

        # 查找匹配的证书并比对指纹
        matched_cert = None
        matched_fingerprint = None

        for cert in intl_certs:
            if cert_domain in (cert.domain or "") or keyword in (cert.sans or ""):
                try:
                    detail = get_intl_cert_detail(cas_client, cert.certificate_id)
                    if detail.cert:
                        matched_cert = cert
                        matched_fingerprint = get_cert_fingerprint(detail.cert)
                        break
                except Exception as e:
                    logger.warning(f"  获取国际站证书 {cert.certificate_id} 详情失败: {e}")
                    continue

        if matched_cert and matched_fingerprint == aliyun_fingerprint:
            logger.info(f"  ⏭️  国际站证书指纹一致，跳过")
            skipped += 1
            continue

        try:
            if matched_cert:
                # 原地更新：保持证书ID不变，ALB引用不受影响
                cert_name = matched_cert.name or f"{INTL_CERT_NAME_PREFIX}-{keyword}"
                logger.info(f"  🔄 国际站证书不一致，原地更新 ID={matched_cert.certificate_id}")
                update_intl_cert(cas_client, matched_cert.certificate_id, cert_name, cert_info["cert"], cert_info["key"])
                logger.info(f"  ✅ 国际站证书原地更新成功，ID不变: {matched_cert.certificate_id}")
            else:
                # 不存在则新上传
                cert_name = f"{INTL_CERT_NAME_PREFIX}-{keyword}"
                logger.info(f"  📤 国际站无该域名证书，上传新证书: {cert_name}")
                new_cert_id = upload_intl_cert(cas_client, cert_name, cert_info["cert"], cert_info["key"])
                logger.info(f"  ✅ 国际站证书上传成功，新证书 ID={new_cert_id}")

            updated += 1

        except Exception as e:
            logger.error(f"  ❌ 国际站证书更新失败: {e}")
            failed += 1

    return updated, skipped, failed
