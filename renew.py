import os
import time
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

username = os.environ.get("ACL_USERNAME", "")
password = os.environ.get("ACL_PASSWORD", "")

def log(msg):
    print(f"[INFO] {msg}")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    # ============ 1. 登录 ============
    log("正在打开登录页...")
    page.goto("https://dash.aclclouds.com/login", wait_until="networkidle")
    page.screenshot(path="00_before_login.png")

    page.fill('input[type="email"]', username)
    page.fill('input[type="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    page.screenshot(path="01_after_login.png")
    log("登录完成")

    # ============ 2. 进入项目页面 ============
    log("正在进入项目页面...")
    page.goto("https://dash.aclclouds.com/projects", wait_until="networkidle")
    page.screenshot(path="02_projects.png")

    # ============ 3. 收集所有项目链接 ============
    # 先收集所有项目的详情页链接，避免点击后页面跳转导致定位失效
    project_links = page.locator('a[href*="/projects/"]').all()
    hrefs = []
    for link in project_links:
        href = link.get_attribute("href")
        if href and href not in hrefs:
            hrefs.append(href)
    log(f"找到 {len(hrefs)} 个项目")

    # ============ 4. 逐个项目：续期 + 开机 ============
    for idx, href in enumerate(hrefs):
        url = href if href.startswith("http") else f"https://dash.aclclouds.com{href}"
        log(f"--- 处理第 {idx+1} 个项目: {url} ---")

        page.goto(url, wait_until="networkidle")
        page.screenshot(path=f"project_{idx+1}_01_enter.png")

        # --- 续期 ---
        try:
            renew_btn = page.locator('button:has-text("Renew")')
            if renew_btn.is_visible():
                renew_btn.click()
                time.sleep(2)
                # 确认弹窗
                confirm = page.locator('button:has-text("Confirm")')
                if confirm.is_visible():
                    confirm.click()
                    time.sleep(2)
                log(f"第 {idx+1} 个项目续期成功")
            else:
                log(f"第 {idx+1} 个项目未找到续期按钮，跳过")
        except PlaywrightTimeout:
            log(f"第 {idx+1} 个项目续期超时")

        page.screenshot(path=f"project_{idx+1}_02_after_renew.png")

        # --- 开机 ---
        try:
            # 常见开机按钮文字：Start / Power On / 开机，按实际修改
            start_btn = page.locator('button:has-text("Start")')
            if start_btn.is_visible():
                start_btn.click()
                time.sleep(2)
                # 确认弹窗
                confirm = page.locator('button:has-text("Confirm")')
                if confirm.is_visible():
                    confirm.click()
                    time.sleep(3)
                log(f"第 {idx+1} 个服务器开机成功")
            else:
                log(f"第 {idx+1} 个服务器未找到开机按钮（可能已在运行）")
        except PlaywrightTimeout:
            log(f"第 {idx+1} 个服务器开机超时")

        page.screenshot(path=f"project_{idx+1}_03_final.png")
        time.sleep(2)

    log("全部项目处理完成")
    browser.close()
