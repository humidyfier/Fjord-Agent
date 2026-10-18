from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    page = b.new_page()
    page.goto("http://127.0.0.1:8000/")
    page.wait_for_timeout(1000)
    page.evaluate("() => switchView('copilot')")
    page.wait_for_timeout(500)
    
    xss = "<b id='xss-injection-marker'><img src=x onerror=alert('xss')></b>"
    page.fill("#chat-input", xss)
    page.click("#btn-chat-send")
    page.wait_for_timeout(1000)
    
    marker = page.query_selector("#xss-injection-marker")
    chat_box = page.query_selector("#chat-messages")
    print("Marker found:", marker is not None)
    print("XSS text in chat box:", "xss-injection-marker" in (chat_box.inner_text() if chat_box else ""))
    b.close()
