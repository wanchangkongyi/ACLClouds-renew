import os
import re
import time
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

def log(msg):
    print(f"[INFO] {msg}")

def parse_expires_minutes(text):
    hours = re.search(r'(\d+)\s*h', text)
    mins  = re.search(r'(\d+)\s*min', text)
    total = 0
    if hours:
        total += int(hours.group(1)) * 60
    if mins:
        total += int(mins.group(1))
    return total

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # ============ 1. 注入 Cookie ============
    raw_cookies = os.environ.get('ACL_COOKIES', '')
    if not raw_cookies:
        log("错误: 未找到 ACL_COOKIES 环境变量")
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
        # ============ 2. 进入项目列表页 ============
        log("正在访问项目面板...")
        page.goto("https://dash.aclclouds.com/projects", timeout=60000)
        page.wait_for_timeout(5000)  # 等待前端渲染完成
        page.screenshot(path="01_projects.png", full_page=True)

        # 等待服务器链接出现
        try:
            page.wait_for_selector('a[href*="/server/"]', timeout=10000)
        except PlaywrightTimeout:
            log("等待服务器链接超时，尝试继续...")

        # 收集所有 /server/ 链接
        server_links = page.locator('a[href*="/server/"]').all()
        hrefs = []
        for link in server_links:
            href = link.get_attribute("href")
            if href and href not in hrefs:
                hrefs.append(href)
        log(f"找到 {len(hrefs)} 个服务器")

        if len(hrefs) == 0:
            log("未找到任何服务器，Cookie 可能已过期，请更新")
            page.screenshot(path="error_no_server.png", full_page=True)
            return

        # ============ 3. 逐个处理服务器 ============
        for idx, href in enumerate(hrefs):
            url = href if href.startswith("http") else f"https://dash.aclclouds.com{href}"
            log(f"--- 处理第 {idx+1} 个服务器: {url} ---")

            page.goto(url, timeout=60000)
            page.wait_for_timeout(3000)
            page.screenshot(path=f"server_{idx+1}_01_enter.png", full_page=True)

            # --- 读取剩余时间（法语：Temps restant） ---
            remaining = None
            try:
                temps_el = page.locator('text=/Temps restant/').first
                full_text = temps_el.inner_text(timeout=5000)
                remaining = parse_expires_minutes(full_text)
                log(f"剩余时间: {full_text.strip()} ({remaining} 分钟)")
            except Exception as e:
                log(f"无法读取剩余时间: {e}")

            # --- 续期判断 ---
            # 剩余 ≤120 分钟，或无法读取时间时尝试续期
            should_renew = (remaining is not None and remaining <= 120) or (remaining is None)

            if should_renew:
                log("尝试续期...")
                try:
                    renew_btn = page.locator("text='Renouveler'").first
                    if renew_btn.is_visible(timeout=3000):
                        renew_btn.click()
                        page.wait_for_timeout(2000)
                        confirm = page.locator("text='Confirmer'").first
                        if confirm.is_visible(timeout=3000):
                            confirm.click()
                            page.wait_for_timeout(2000)
                        log("续期成功")
                    else:
                        log("续期按钮不可见，未到续期窗口期（到期前2h才出现）")
                except PlaywrightTimeout:
                    log("续期操作超时")
                page.screenshot(path=f"server_{idx+1}_02_after_renew.png", full_page=True)
            else:
                log(f"剩余时间充足（{remaining}min），无需续期")

            # --- 开机（每次都检查） ---
            log("检查开机状态...")
            try:
                start_btn = page.locator("text='Start'").first
                if start_btn.is_visible(timeout=3000):
                    start_btn.click()
                    page.wait_for_timeout(2000)
                    confirm = page.locator("text='Confirmer'").first
                    if confirm.is_visible(timeout=3000):
                        confirm.click()
                        page.wait_for_timeout(3000)
                    log("开机成功")
                else:
                    log("服务器已在运行，无需开机")
            except PlaywrightTimeout:
                log("开机操作超时")

            page.screenshot(path=f"server_{idx+1}_03_final.png", full_page=True)
            page.wait_for_timeout(2000)

        log("全部服务器处理完成")

    except Exception as e:
        log(f"执行过程中发生错误: {e}")
        page.screenshot(path="error_page.png", full_page=True)
    finally:
        browser.close()

with sync_playwright() as playwright:
    run(playwright)
