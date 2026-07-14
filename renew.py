import os
import re
import sys
import json
import time
import base64
import platform
import subprocess
import tarfile
from urllib.parse import urlparse, parse_qs, unquote

import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

SING_BOX_FALLBACK_VERSION = "1.13.14"
SOCKS_PORT = 1080
HTTP_PORT = 1081
SING_BOX_BIN = "./sing-box"
SING_BOX_CONFIG = "sing-box-config.json"
SING_BOX_LOG = "sing-box.log"


def log(msg):
    print(f"[INFO] {msg}")


def parse_expires_minutes(text):
    hours = re.search(r'(\d+)\s*h', text)
    mins = re.search(r'(\d+)\s*min', text)
    total = 0
    if hours:
        total += int(hours.group(1)) * 60
    if mins:
        total += int(mins.group(1))
    return total


# ============================================================
#   节点链接解析 -> sing-box outbound 配置
# ============================================================

def _bool_from_qs(qs, key, default=False):
    val = qs.get(key, [None])[0]
    if val is None:
        return default
    return val.lower() in ("1", "true")


def _parse_vless(link):
    u = urlparse(link)
    qs = parse_qs(u.query)
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "uuid": u.username,
    }
    flow = qs.get("flow", [None])[0]
    if flow:
        outbound["flow"] = flow

    net_type = qs.get("type", ["tcp"])[0]
    if net_type != "tcp":
        outbound["transport"] = {
            "type": net_type,
            "path": unquote(qs.get("path", ["/"])[0]),
            "headers": {"Host": qs.get("host", [u.hostname])[0]},
        }

    security = qs.get("security", ["none"])[0]
    sni = qs.get("sni", [u.hostname])[0]
    fp = qs.get("fp", ["chrome"])[0]
    insecure = _bool_from_qs(qs, "insecure") or _bool_from_qs(qs, "allowInsecure")

    if security in ("tls", "reality"):
        tls = {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure,
            "utls": {"enabled": True, "fingerprint": fp},
        }
        if security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": qs.get("pbk", [""])[0],
                "short_id": qs.get("sid", [""])[0],
            }
        outbound["tls"] = tls
    return outbound


def _parse_vmess(link):
    b64 = link[len("vmess://"):]
    b64 += "=" * (-len(b64) % 4)
    try:
        decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
    except Exception as e:
        raise ValueError(f"VMess 链接解码失败: {e}")

    net_type = decoded.get("net", "tcp")
    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": decoded.get("add"),
        "server_port": int(decoded.get("port", 443)),
        "uuid": decoded.get("id"),
        "security": "auto",
        "transport": {
            "type": net_type,
            "path": unquote(decoded.get("path", "/")),
            "headers": {"Host": decoded.get("host") or decoded.get("add")},
        },
    }
    if decoded.get("tls") == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": decoded.get("sni") or decoded.get("add"),
            "insecure": False,
            "utls": {"enabled": True, "fingerprint": decoded.get("fp", "chrome")},
        }
    return outbound


def _parse_trojan(link):
    u = urlparse(link)
    qs = parse_qs(u.query)
    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": u.username,
        "transport": {
            "type": qs.get("type", ["tcp"])[0],
            "path": unquote(qs.get("path", ["/"])[0]),
            "headers": {"Host": qs.get("host", [u.hostname])[0]},
        },
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni", [u.hostname])[0],
            "insecure": _bool_from_qs(qs, "insecure") or _bool_from_qs(qs, "allowInsecure"),
            "utls": {"enabled": True, "fingerprint": qs.get("fp", ["chrome"])[0]},
        },
    }
    return outbound


def _parse_hysteria2(link):
    link = link.replace("hy2://", "hysteria2://", 1)
    u = urlparse(link)
    qs = parse_qs(u.query)
    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": u.username or qs.get("auth", [""])[0],
        "up_mbps": 100,
        "down_mbps": 100,
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni", [u.hostname])[0],
            "insecure": _bool_from_qs(qs, "insecure") or _bool_from_qs(qs, "allowInsecure"),
        },
    }
    obfs = qs.get("obfs", [None])[0]
    if obfs:
        outbound["obfs"] = {"type": "salamander", "password": qs.get("obfs-password", [""])[0] or obfs}
    return outbound


def _parse_tuic(link):
    u = urlparse(link)
    qs = parse_qs(u.query)
    outbound = {
        "type": "tuic",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "uuid": u.username,
        "password": u.password or "",
        "congestion_control": qs.get("congestion_control", ["bbr"])[0],
        "udp_over_stream": True,
        "zero_rtt_handshake": False,
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni", [u.hostname])[0],
            "insecure": _bool_from_qs(qs, "insecure") or _bool_from_qs(qs, "allowInsecure"),
        },
    }
    alpn = qs.get("alpn", [None])[0]
    if alpn:
        outbound["tls"]["alpn"] = [alpn]
    return outbound


def _parse_anytls(link):
    u = urlparse(link)
    qs = parse_qs(u.query)
    outbound = {
        "type": "anytls",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": u.username,
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni", [u.hostname])[0],
            "insecure": _bool_from_qs(qs, "insecure") or _bool_from_qs(qs, "allowInsecure"),
            "utls": {"enabled": True, "fingerprint": qs.get("fp", ["chrome"])[0]},
        },
    }
    return outbound


def _parse_socks5(link):
    u = urlparse(link)
    outbound = {
        "type": "socks",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "version": "5",
    }
    if u.username:
        username, password = u.username, (u.password or "")
        if not u.password:
            try:
                decoded = base64.b64decode(u.username + "=" * (-len(u.username) % 4)).decode()
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
            except Exception:
                pass
        outbound["username"] = username
        outbound["password"] = password
    return outbound


_PARSERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "trojan": _parse_trojan,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
    "anytls": _parse_anytls,
    "socks5": _parse_socks5,
    "socks": _parse_socks5,
}


def parse_node_link(link):
    scheme = link.split("://", 1)[0].lower()
    parser = _PARSERS.get(scheme)
    if not parser:
        raise ValueError(f"不支持的协议: {scheme}")
    return parser(link)


# ============================================================
#   sing-box 下载 / 启动 / 连通性测试
# ============================================================

def _arch_tag():
    m = platform.machine().lower()
    return {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv7",
        "i686": "386", "i386": "386",
        "s390x": "s390x",
    }.get(m, None)


def ensure_sing_box_binary():
    if os.path.exists(SING_BOX_BIN):
        log("sing-box 已存在，跳过下载")
        return

    arch = _arch_tag()
    if not arch:
        raise RuntimeError(f"不支持的架构: {platform.machine()}")

    version = SING_BOX_FALLBACK_VERSION
    try:
        resp = requests.get(
            "https://api.github.com/repos/SagerNet/sing-box/releases",
            timeout=15,
        )
        resp.raise_for_status()
        releases = [r for r in resp.json() if not r.get("prerelease")]
        if releases:
            version = releases[0]["tag_name"].lstrip("v")
    except Exception as e:
        log(f"获取最新版本失败，使用兜底版本 v{version}: {e}")

    filename = f"sing-box-{version}-linux-{arch}.tar.gz"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{filename}"

    log(f"下载 sing-box v{version} ({arch})...")
    resp = requests.get(url, timeout=60, allow_redirects=True)
    resp.raise_for_status()
    with open(filename, "wb") as f:
        f.write(resp.content)

    if not tarfile.is_tarfile(filename):
        raise RuntimeError(f"下载的文件不是有效的 tar 包，可能版本/架构不对: {url}")

    with tarfile.open(filename) as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("/sing-box"))
        member.name = os.path.basename(member.name)
        tf.extract(member, path=".", filter="data")

    os.remove(filename)
    os.chmod(SING_BOX_BIN, 0o755)
    log("sing-box 就绪")


def write_config(outbound):
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT},
        ],
        "outbounds": [outbound],
    }
    with open(SING_BOX_CONFIG, "w") as f:
        json.dump(config, f)


def start_sing_box():
    log_file = open(SING_BOX_LOG, "w")
    proc = subprocess.Popen(
        [SING_BOX_BIN, "run", "-c", SING_BOX_CONFIG],
        stdout=log_file, stderr=subprocess.STDOUT,
    )
    time.sleep(5)
    if proc.poll() is not None:
        with open(SING_BOX_LOG) as f:
            raise RuntimeError(f"sing-box 启动后立即退出，日志:\n{f.read()}")
    return proc


def test_proxy_connectivity():
    proxies = {
        "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{SOCKS_PORT}",
    }
    for attempt in range(1, 4):
        try:
            r = requests.get("https://api.ipify.org", proxies=proxies, timeout=15)
            r.raise_for_status()
            log(f"代理连接成功，出口 IP: {r.text.strip()}")
            return True
        except Exception as e:
            log(f"代理测试第 {attempt}/3 次失败: {e}")
            time.sleep(3)
    return False


def setup_proxy_from_node_link(node_link):
    try:
        outbound = parse_node_link(node_link)
    except Exception as e:
        log(f"❌ 节点链接解析失败: {e}")
        return None

    try:
        ensure_sing_box_binary()
    except Exception as e:
        log(f"❌ sing-box 准备失败: {e}")
        return None

    write_config(outbound)

    try:
        proc = start_sing_box()
    except Exception as e:
        log(f"❌ {e}")
        return None

    if not test_proxy_connectivity():
        log("❌ 代理连通性测试失败")
        proc.terminate()
        return None

    return {"server": f"socks5://127.0.0.1:{SOCKS_PORT}"}


def build_proxy_config():
    node_link = os.environ.get("NODE_LINK", "").strip()
    if node_link:
        log("检测到 NODE_LINK，解析节点链接并启动本地代理...")
        proxy_config = setup_proxy_from_node_link(node_link)
        if proxy_config:
            return proxy_config
        log("⚠️ 基于 NODE_LINK 启动代理失败，回退为直连")
        return None

    is_proxy = os.environ.get("IS_PROXY", "false").strip().lower() == "true"
    if not is_proxy:
        log("未启用代理，直连模式")
        return None

    proxy_server = os.environ.get("PROXY_SERVER", "").strip()
    if not proxy_server:
        log("⚠️ IS_PROXY=true 但未设置 PROXY_SERVER，回退为直连")
        return None

    proxy_config = {"server": proxy_server}
    username = os.environ.get("PROXY_USERNAME", "").strip()
    if username:
        proxy_config["username"] = username
        proxy_config["password"] = os.environ.get("PROXY_PASSWORD", "").strip()
    log(f"使用外部已启动的代理: {proxy_server}")
    return proxy_config


def dump_debug(page, tag):
    """失败时留证据：存一张截图，并把页面正文前 500 字打到日志里，方便对照实际文案/选择器"""
    try:
        os.makedirs("screenshots", exist_ok=True)
        shot_path = f"screenshots/{tag}.png"
        page.screenshot(path=shot_path, full_page=True)
        log(f"📸 已保存诊断截图: {shot_path}")
    except Exception as e:
        log(f"⚠️ 截图失败: {e}")

    try:
        body_text = page.locator("body").inner_text(timeout=3000)
        snippet = " ".join(body_text.split())[:500]
        log(f"📄 页面正文片段: {snippet!r}")
    except Exception as e:
        log(f"⚠️ 读取页面正文失败: {e}")


def run(playwright):
    proxy_config = build_proxy_config()

    launch_kwargs = {"headless": True}
    if proxy_config:
        launch_kwargs["proxy"] = proxy_config

    try:
        browser = playwright.chromium.launch(**launch_kwargs)
    except Exception as e:
        log(f"❌ 浏览器启动失败: {e}")
        return

    context = browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    raw_cookies = os.environ.get('ACL_COOKIES', '')
    if not raw_cookies:
        log("错误: 未找到 ACL_COOKIES 环境变量")
        browser.close()
        return

    cookies = []
    for item in raw_cookies.split(';'):
        if '=' in item:
            name, value = item.split('=', 1)
            cookies.append({
                "name": name.strip(),
                "value": value.strip(),
                "domain": "dash.aclclouds.com",
                "path": "/"
            })
    context.add_cookies(cookies)
    page = context.new_page()

    try:
        log("正在访问项目面板...")
        page.goto("https://dash.aclclouds.com/projects", timeout=60000)
        page.wait_for_timeout(5000)

        current_url = page.url
        current_title = page.title()
        log(f"当前 URL: {current_url}")
        log(f"当前标题: {current_title}")

        try:
            reactiver_btns = page.locator('button:has-text("Réactiver")')
            count = reactiver_btns.count()
            if count > 0:
                log(f"检测到 {count} 个暂停的服务器，点击重新激活...")
                for i in range(count):
                    reactiver_btns.nth(i).click()
                    page.wait_for_timeout(3000)
                    log(f"第 {i+1} 个服务器已激活")
                page.wait_for_timeout(3000)
            else:
                log("无暂停服务器")
        except PlaywrightTimeout:
            log("激活操作超时")

        try:
            page.wait_for_selector('a[href*="/server/"]', timeout=10000)
        except PlaywrightTimeout:
            log("等待服务器链接超时，尝试继续...")

        server_links = page.locator('a[href*="/server/"]').all()
        hrefs = []
        for link in server_links:
            href = link.get_attribute("href")
            if href and href not in hrefs:
                hrefs.append(href)
        log(f"找到 {len(hrefs)} 个服务器")

        if len(hrefs) == 0:
            os.makedirs("screenshots", exist_ok=True)
            shot_path = "screenshots/no_servers_found.png"
            page.screenshot(path=shot_path, full_page=True)

            # 用 URL / 标题辅助判断具体原因，而不是笼统地都归为 "Cookie 过期"
            url_lower = current_url.lower()
            title_lower = (current_title or "").lower()
            if "login" in url_lower or "signin" in url_lower or "login" in title_lower:
                log("❌ 当前停留在登录页，说明 Cookie 无效/已过期（不是代理或反爬问题），请更新 ACL_COOKIES")
            elif any(kw in title_lower for kw in ("just a moment", "attention required", "access denied", "blocked")):
                log("❌ 页面标题显示疑似被反爬/风控拦截（很可能是代理出口 IP 被目标站点识别为数据中心/VPS IP），"
                    "建议更换代理节点，或临时不设 NODE_LINK 走直连对比测试")
            else:
                log("❌ 既不在登录页也无明显拦截特征，但页面上没有服务器链接，"
                    "请查看下方截图 Artifact 确认页面实际内容（可能是页面结构变了，选择器需要更新）")
            log(f"截图已保存: {shot_path}")
            browser.close()
            return

        for idx, href in enumerate(hrefs):
            url = href if href.startswith("http") else f"https://dash.aclclouds.com{href}"
            log(f"--- 处理第 {idx+1} 个服务器 ---")

            page.goto(url, timeout=60000)
            page.wait_for_timeout(5000)

            try:
                suspended_btn = page.locator('button:has-text("Renouveler maintenant")')
                if suspended_btn.is_visible(timeout=3000):
                    log("服务器被暂停，点击立即续期...")
                    suspended_btn.click()
                    page.wait_for_timeout(5000)
                    log("暂停续期完成")
                    page.goto(url, timeout=60000)
                    page.wait_for_timeout(5000)
            except PlaywrightTimeout:
                pass

            remaining = None
            try:
                temps_el = page.locator('text=/Temps restant/').first
                full_text = temps_el.inner_text(timeout=5000)
                remaining = parse_expires_minutes(full_text)
                log(f"剩余时间: {full_text.strip()} ({remaining} 分钟)")
            except Exception as e:
                log(f"无法读取剩余时间: {e}")
                dump_debug(page, f"server_{idx+1}_no_remaining_time")

            RENEW_THRESHOLD_MINUTES = 2 * 24 * 60 - 30  # 到期前2天可续期，留30分钟余量 = 2850分钟
            if remaining is not None and remaining <= RENEW_THRESHOLD_MINUTES:
                log(f"剩余时间不足 2 天（阈值 {RENEW_THRESHOLD_MINUTES} 分钟），尝试续期...")
                try:
                    renew_btn = page.locator('button:has-text("Renouveler")').first
                    if renew_btn.is_visible(timeout=3000):
                        renew_btn.click()
                        page.wait_for_timeout(2000)
                        confirm = page.locator('button:has-text("Confirmer")')
                        if confirm.is_visible(timeout=3000):
                            confirm.click()
                            page.wait_for_timeout(2000)
                        log("续期成功")
                    else:
                        log("续期按钮不可见，未到续期窗口期")
                except PlaywrightTimeout:
                    log("续期操作超时")
            elif remaining is None:
                log("无法读取剩余时间，跳过续期")
            else:
                log(f"剩余时间充足（{remaining}min），无需续期")

            try:
                start_btn = page.locator('button:has-text("Start")').first
                if start_btn.is_visible(timeout=5000):
                    start_btn.scroll_into_view_if_needed()
                    page.wait_for_timeout(1000)
                    start_btn.click()
                    log("开机成功")
                    page.wait_for_timeout(3000)
                else:
                    log("服务器已在运行")
            except PlaywrightTimeout:
                log("开机操作超时")
                dump_debug(page, f"server_{idx+1}_start_timeout")

        log("全部服务器处理完成")

    except Exception as e:
        log(f"执行过程中发生错误: {e}")
    finally:
        browser.close()


with sync_playwright() as playwright:
    run(playwright)
