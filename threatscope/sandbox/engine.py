import time
import asyncio
from typing import Dict, Any
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

class BehavioralSandbox:
    def __init__(self, timeout_ms: int = 15000):
        self.timeout_ms = timeout_ms

    async def analyze_url(self, target_url: str) -> Dict[str, Any]:
        """Runs URL dynamic behavioral scan inside isolated Playwright session."""
        results = {
            "url": target_url,
            "status": "completed",
            "redirect_chain": [],
            "http_status_codes": [],
            "crypto_mining_detected": False,
            "suspicious_scripts": [],
            "outbound_requests_count": 0,
            "forms_detected": 0,
            "has_password_input": False,
            "has_credit_card_input": False,
            "verdict": "BENIGN",
            "threat_score": 0.0,
            "elapsed_seconds": 0.0
        }

        start_time = time.time()
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = "http://" + target_url

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-blink-features=AutomationControlled"
                ]
            )
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True
            )
            page = await context.new_page()

            await page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                window.chrome = { runtime: {} };
            """)

            page.on("request", lambda req: self._handle_request(req, results))
            page.on("response", lambda res: results["http_status_codes"].append(res.status))

            try:
                response = await page.goto(target_url, timeout=self.timeout_ms, wait_until="networkidle")
                results["final_url"] = page.url
                results["redirect_chain"].append(page.url)

                inputs = await page.query_selector_all("input")
                forms = await page.query_selector_all("form")
                results["forms_detected"] = len(forms)

                for inp in inputs:
                    inp_type = (await inp.get_attribute("type") or "").lower()
                    inp_name = (await inp.get_attribute("name") or "").lower()
                    inp_placeholder = (await inp.get_attribute("placeholder") or "").lower()

                    if inp_type == "password" or "pass" in inp_name:
                        results["has_password_input"] = True
                    if any(kw in inp_name or kw in inp_placeholder for kw in ["cc", "card", "cvv", "credit"]):
                        results["has_credit_card_input"] = True

                miner_signatures = await page.evaluate("""() => {
                    const scripts = Array.from(document.querySelectorAll('script')).map(s => s.src || s.innerText);
                    const keywords = ['coinhive', 'cryptonight', 'cryptoloot', 'coin-hive', 'minr', 'webminer'];
                    return {
                        hasMiner: scripts.some(src => keywords.some(k => src.toLowerCase().includes(k))),
                        scriptCount: scripts.length
                    };
                }""")

                if miner_signatures.get("hasMiner"):
                    results["crypto_mining_detected"] = True
                    results["suspicious_scripts"].append("Known crypto-mining signature detected")

                if len(results["redirect_chain"]) > 2:
                    results["suspicious_scripts"].append("Multi-hop redirection chain detected")

            except PlaywrightTimeoutError:
                results["status"] = "timeout_reached"
            except Exception as e:
                results["status"] = f"error: {str(e)}"
            finally:
                await context.close()
                await browser.close()

        score = 0.0
        if results["has_password_input"]: score += 0.35
        if results["has_credit_card_input"]: score += 0.45
        if results["crypto_mining_detected"]: score += 0.50
        if len(results["redirect_chain"]) > 2: score += 0.20

        results["threat_score"] = min(round(score, 3), 1.0)
        results["verdict"] = "MALICIOUS" if results["threat_score"] >= 0.5 else "BENIGN"
        results["elapsed_seconds"] = round(time.time() - start_time, 2)
        return results

    def _handle_request(self, req, results):
        results["outbound_requests_count"] += 1
        url = req.url.lower()
        if any(w in url for w in ["coinhive", "xmrig", "cryptonight", "webminer"]):
            results["crypto_mining_detected"] = True
