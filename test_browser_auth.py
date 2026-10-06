import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={'width': 1440, 'height': 900})
        page = await context.new_page()

        print("[Test 1] Testing unauthenticated redirect...")
        await page.goto("http://localhost:3000/")
        await page.wait_for_timeout(1000)
        current_url = page.url
        print(f"Current URL after visiting /: {current_url}")
        assert "/login" in current_url, f"Expected redirect to /login, got {current_url}"

        # Screenshot login page
        await page.screenshot(path="phase2_login_page.png")
        print("Captured phase2_login_page.png")

        print("[Test 2] Navigating to register page...")
        await page.click("text=Create Account")
        await page.wait_for_timeout(1000)
        print(f"Current URL: {page.url}")
        assert "/register" in page.url, f"Expected /register, got {page.url}"

        # Screenshot register page
        await page.screenshot(path="phase2_register_page.png")
        print("Captured phase2_register_page.png")

        print("[Test 3] Submitting registration form...")
        await page.fill('input[placeholder="Jane Doe"]', "Elena Rostova")
        await page.fill('input[placeholder="operator@aegis.internal"]', "elena.rostova@aegis.internal")
        await page.fill('input[placeholder="••••••••••••"]', "PasswordSecOps2026!")
        await page.click('button:has-text("Complete Registration")')

        # Wait for auto-login and navigation to dashboard
        await page.wait_for_url("http://localhost:3000/", timeout=10000)
        await page.wait_for_timeout(2000)
        print(f"Current URL after register & auto-login: {page.url}")

        # Check user name in topbar
        content = await page.content()
        assert "Elena Rostova" in content, "Elena Rostova not found in topbar!"
        assert "analyst" in content, "Role 'analyst' not found in topbar!"
        print("Verified Elena Rostova and role analyst in topbar!")

        # Screenshot dashboard after login
        await page.screenshot(path="phase2_dashboard_after_login.png")
        print("Captured phase2_dashboard_after_login.png")

        print("[Test 4] Testing logout...")
        await page.click('button[title="Terminate Session"]')
        await page.wait_for_url("http://localhost:3000/login", timeout=5000)
        await page.wait_for_timeout(1000)
        print(f"Current URL after logout: {page.url}")
        assert "/login" in page.url, "Logout did not redirect to /login!"

        # Verify token cleared
        token = await page.evaluate("() => localStorage.getItem('aegis_token')")
        print(f"Token after logout in localStorage: {token}")
        assert token is None, "Token was not cleared on logout!"

        print("[SUCCESS] All browser authentication tests passed flawlessly!")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
