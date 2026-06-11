#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
阿里云SSL证书自动同步到 Docker Nginx 容器
自动发现所有运行中的 nginx 容器，检查其 TLS 证书是否为目标域名，
若与阿里云最新证书不一致则更新并 reload nginx
"""

import os
import sys
import hashlib
import logging
import re

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

import docker
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

CERT_DOMAINS = [d.strip() for d in os.environ.get("CERT_DOMAIN", "*.sisensing.com").split(",")]


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
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                domains.add(attr.value)
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
    for cert_domain in CERT_DOMAINS:
        target_base = cert_domain.replace("*.", "")
        for domain in domains:
            if domain == cert_domain or domain.endswith(target_base):
                return cert_domain
    return None


def find_nginx_containers(docker_client):
    """查找所有运行中的 nginx 容器"""
    containers = docker_client.containers.list(filters={"status": "running"})
    nginx_containers = []
    for container in containers:
        image_name = container.image.tags[0] if container.image.tags else ""
        # 通过镜像名或容器内进程判断是否是 nginx
        if "nginx" in image_name.lower() or "nginx" in container.name.lower():
            nginx_containers.append(container)
            continue
        # 额外检查：容器内是否有 nginx 进程
        try:
            exit_code, _ = container.exec_run("which nginx", demux=True)
            if exit_code == 0:
                nginx_containers.append(container)
        except Exception:
            pass
    return nginx_containers


def find_cert_files_in_container(container):
    """从 nginx 配置中提取 ssl_certificate 路径"""
    cert_paths = []
    # 常见 nginx 配置路径
    config_paths = [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/conf.d/",
        "/etc/nginx/sites-enabled/",
    ]

    for conf_path in config_paths:
        try:
            exit_code, output = container.exec_run(
                f"find {conf_path} -name '*.conf' -exec cat {{}} ;",
                demux=True
            )
            if exit_code != 0:
                # 尝试直接 cat 单文件
                exit_code, output = container.exec_run(f"cat {conf_path}", demux=True)
                if exit_code != 0:
                    continue

            stdout = output[0] if output[0] else b""
            content = stdout.decode("utf-8", errors="ignore")

            # 提取 ssl_certificate 和 ssl_certificate_key 路径
            cert_matches = re.findall(r'ssl_certificate\s+([^;]+);', content)
            key_matches = re.findall(r'ssl_certificate_key\s+([^;]+);', content)

            for cert_path in cert_matches:
                cert_path = cert_path.strip()
                # 找到对应的 key 路径
                key_path = None
                for k in key_matches:
                    key_path = k.strip()
                    break

                if cert_path and key_path:
                    cert_paths.append({
                        "cert_path": cert_path,
                        "key_path": key_path
                    })
        except Exception as e:
            logger.warning(f"读取容器 {container.name} 配置失败: {e}")

    # 去重
    seen = set()
    unique_paths = []
    for p in cert_paths:
        key = (p["cert_path"], p["key_path"])
        if key not in seen:
            seen.add(key)
            unique_paths.append(p)

    return unique_paths


def read_cert_from_container(container, cert_path):
    """从容器中读取证书文件内容"""
    try:
        exit_code, output = container.exec_run(f"cat {cert_path}", demux=True)
        if exit_code == 0 and output[0]:
            return output[0]
    except Exception as e:
        logger.warning(f"读取 {container.name}:{cert_path} 失败: {e}")
    return None


def write_cert_to_container(container, file_path, content):
    """将证书内容写入容器"""
    import tarfile
    import io

    # 通过 tar 方式写入文件到容器
    if isinstance(content, str):
        content = content.encode()

    tar_stream = io.BytesIO()
    file_name = os.path.basename(file_path)
    dir_path = os.path.dirname(file_path)

    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
        file_info = tarfile.TarInfo(name=file_name)
        file_info.size = len(content)
        tar.addfile(file_info, io.BytesIO(content))

    tar_stream.seek(0)
    container.put_archive(dir_path, tar_stream)


def reload_nginx(container):
    """重载 nginx 配置"""
    # 先测试配置
    exit_code, output = container.exec_run("nginx -t", demux=True)
    if exit_code != 0:
        stderr = output[1].decode("utf-8", errors="ignore") if output[1] else ""
        logger.error(f"容器 {container.name} nginx 配置测试失败: {stderr}")
        return False

    # reload
    exit_code, output = container.exec_run("nginx -s reload", demux=True)
    if exit_code == 0:
        logger.info(f"✅ 容器 {container.name} nginx reload 成功")
        return True
    else:
        stderr = output[1].decode("utf-8", errors="ignore") if output[1] else ""
        logger.error(f"容器 {container.name} nginx reload 失败: {stderr}")
        return False


def sync_docker_nginx(certs_map):
    """同步 Docker Nginx 容器中的证书"""
    try:
        docker_client = docker.from_env()
    except Exception as e:
        logger.error(f"连接 Docker 失败: {e}")
        return 0, 0, 0

    # 1. 查找所有 nginx 容器
    nginx_containers = find_nginx_containers(docker_client)
    logger.info(f"发现 {len(nginx_containers)} 个 nginx 容器:")
    for c in nginx_containers:
        logger.info(f"  - {c.name} ({c.image.tags})")

    if not nginx_containers:
        logger.info("未发现运行中的 nginx 容器")
        return 0, 0, 0

    updated = 0
    skipped = 0
    failed = 0

    # 2. 遍历每个 nginx 容器
    for container in nginx_containers:
        logger.info(f"检查容器: {container.name}")

        # 3. 从 nginx 配置中提取证书路径
        cert_configs = find_cert_files_in_container(container)
        if not cert_configs:
            logger.info(f"  容器 {container.name} 未找到 SSL 证书配置，跳过")
            continue

        container_need_reload = False

        for cfg in cert_configs:
            cert_path = cfg["cert_path"]
            key_path = cfg["key_path"]
            logger.info(f"  检查证书: {cert_path}")

            # 4. 读取容器中的证书
            cert_content = read_cert_from_container(container, cert_path)
            if not cert_content:
                logger.warning(f"  无法读取 {cert_path}，跳过")
                continue

            # 5. 判断是否是目标域名证书
            matched_domain = is_target_cert(cert_content)
            if not matched_domain:
                logger.info(f"  {cert_path} 不是目标域名证书，跳过")
                continue

            # 6. 获取对应域名的阿里云证书
            cert_info = certs_map.get(matched_domain)
            if not cert_info:
                logger.warning(f"  {cert_path} 匹配 {matched_domain} 但未获取到阿里云证书，跳过")
                continue

            # 7. 比对指纹
            aliyun_fingerprint = get_cert_fingerprint(cert_info["cert"].encode() if isinstance(cert_info["cert"], str) else cert_info["cert"])
            current_fingerprint = get_cert_fingerprint(cert_content)
            if current_fingerprint == aliyun_fingerprint:
                logger.info(f"  ⏭️  {cert_path} 证书一致，跳过")
                skipped += 1
                continue

            # 8. 更新证书和私钥
            logger.info(f"  🔄 {cert_path} 证书不一致，开始更新...")
            try:
                write_cert_to_container(container, cert_path, cert_info["cert"])
                write_cert_to_container(container, key_path, cert_info["key"])
                container_need_reload = True
                updated += 1
                logger.info(f"  ✅ 已更新 {cert_path} 和 {key_path}")
            except Exception as e:
                logger.error(f"  ❌ 更新 {cert_path} 失败: {e}")
                failed += 1

        # 8. 如果有证书更新，reload nginx
        if container_need_reload:
            reload_nginx(container)

    return updated, skipped, failed
