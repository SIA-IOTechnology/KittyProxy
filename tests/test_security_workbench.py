import base64
import json
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from kittyproxy.security_workbench import SecurityWorkbench  # noqa: E402


def encoded(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.b64encode(value).decode("ascii")


def flow(
    flow_id="flow-1",
    method="GET",
    url="https://example.test/",
    request_headers=None,
    request_body="",
    response_headers=None,
    response_body="",
    status=200,
    **extra,
):
    return {
        "id": flow_id,
        "method": method,
        "url": url,
        "status_code": status,
        "request": {
            "headers": request_headers or {},
            "content_bs64": encoded(request_body),
        },
        "response": {
            "headers": response_headers or {},
            "content_bs64": encoded(response_body),
        },
        **extra,
    }


class SecurityWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.workbench = SecurityWorkbench()

    def rules(self, report):
        return {item["rule_id"] for item in report["findings"]}

    def test_dom_csp_headers_and_cookie_findings(self):
        sample = flow(
            response_headers={"Content-Type": "text/html"},
            response_body="""
                <html><script>
                const value = window.location.hash;
                document.querySelector('#out').innerHTML = value;
                window.addEventListener('message', event => render(event.data));
                localStorage.setItem('access_token', value);
                </script></html>
            """,
        )
        sample["response"]["set_cookie_headers"] = ["sessionid=abc; Path=/"]

        report = self.workbench.analyze([sample])
        rules = self.rules(report)

        self.assertIn("DOM_TAINTED_SINK", rules)
        self.assertIn("POSTMESSAGE_ORIGIN_UNCHECKED", rules)
        self.assertIn("TOKEN_IN_WEB_STORAGE", rules)
        self.assertIn("CSP_MISSING", rules)
        self.assertIn("HSTS_MISSING", rules)
        self.assertIn("COOKIE_SECURE_MISSING", rules)
        self.assertIn("COOKIE_HTTPONLY_MISSING", rules)
        self.assertIn("COOKIE_SAMESITE_MISSING", rules)
        self.assertEqual(report["asvs"]["version"], "5.0.0")

    def test_auth_transport_url_oauth_and_jwt_none(self):
        jwt_none = "{}.{}.x".format(
            base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("="),
            base64.urlsafe_b64encode(b'{"sub":"123456"}').decode().rstrip("="),
        )
        sample = flow(
            method="GET",
            url="http://auth.example.test/oauth/authorize?response_type=code&access_token=secret",
            request_headers={"Authorization": f"Bearer {jwt_none}"},
            response_headers={"Content-Type": "application/json"},
            response_body=json.dumps({"access_token": jwt_none}),
        )

        report = self.workbench.analyze([sample])
        rules = self.rules(report)

        self.assertIn("SENSITIVE_DATA_IN_URL", rules)
        self.assertIn("AUTH_OVER_HTTP", rules)
        self.assertIn("AUTH_RESPONSE_CACHEABLE", rules)
        self.assertIn("JWT_NONE_ALGORITHM", rules)
        self.assertIn("OAUTH_STATE_MISSING", rules)
        self.assertIn("OAUTH_PKCE_MISSING", rules)
        serialized = json.dumps(report)
        self.assertNotIn("access_token=secret", serialized)

    def test_websocket_analysis(self):
        sample = flow(
            url="http://socket.example.test/ws?token=supersecret",
            request_headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Cookie": "session=abc",
            },
            response_headers={"Upgrade": "websocket"},
            status=101,
            is_websocket=True,
            ws_messages=[
                {
                    "direction": "server",
                    "content": '{"access_token":"a-very-secret-value"}',
                    "type": "text",
                }
            ],
        )

        report = self.workbench.analyze([sample])
        rules = self.rules(report)

        self.assertIn("WEBSOCKET_CLEAR_TEXT", rules)
        self.assertIn("WEBSOCKET_ORIGIN_MISSING", rules)
        self.assertIn("WEBSOCKET_TOKEN_IN_URL", rules)
        self.assertIn("WEBSOCKET_SECRET_EXPOSURE", rules)
        self.assertNotIn("a-very-secret-value", json.dumps(report))

    def test_graphql_introspection_debug_and_complexity(self):
        nested = "query Deep {" + " a {" * 10 + " value " + "}" * 10 + "}"
        sample = flow(
            method="POST",
            url="https://api.example.test/graphql",
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps({"query": nested + " __schema { queryType { name } }"}),
            response_headers={"Content-Type": "application/json"},
            response_body=json.dumps(
                {
                    "data": {"__schema": {"queryType": {"name": "Query"}, "types": []}},
                    "errors": [{"message": "boom", "extensions": {"stacktrace": ["line 1"]}}],
                }
            ),
        )

        report = self.workbench.analyze([sample])
        rules = self.rules(report)

        self.assertIn("GRAPHQL_INTROSPECTION_ENABLED", rules)
        self.assertIn("GRAPHQL_DEBUG_ERROR", rules)
        self.assertIn("GRAPHQL_COMPLEX_QUERY", rules)
        self.assertEqual(report["observations"]["graphql_flows"][0]["operation"], "query")

    def test_regression_suite_redacts_secrets_and_compiles(self):
        sample = flow(
            method="POST",
            url="https://example.test/login?access_token=url-secret",
            request_headers={
                "Authorization": "Bearer secret-token",
                "Content-Type": "application/json",
            },
            request_body=json.dumps({"username": "alice", "password": "hunter2"}),
            response_headers={"Content-Type": "text/html"},
            response_body="<html>ok</html>",
        )
        report = self.workbench.analyze([sample])

        suite = self.workbench.build_regression_suite(
            [sample],
            report=report,
            include_sensitive=False,
        )

        self.assertEqual(len(suite["cases"]), 1)
        request = suite["cases"][0]["request"]
        self.assertEqual(request["headers"]["authorization"], "${KITTYPROXY_AUTHORIZATION}")
        self.assertIn("${KITTYPROXY_QUERY_ACCESS_TOKEN}", request["url"])
        decoded_body = base64.b64decode(request["body_b64"]).decode()
        self.assertIn("${KITTYPROXY_PASSWORD}", decoded_body)
        self.assertIn("KITTYPROXY_AUTHORIZATION", suite["required_environment"])
        self.assertIn("KITTYPROXY_PASSWORD", suite["required_environment"])
        self.assertIn("KITTYPROXY_QUERY_ACCESS_TOKEN", suite["required_environment"])
        self.assertNotIn("hunter2", json.dumps(suite))
        self.assertNotIn("url-secret", json.dumps(suite))
        self.assertIn("expand(request_body.decode", suite["python"])
        compile(suite["python"], "generated_security_regression.py", "exec")

    def test_response_assertion_evaluation(self):
        checks = [
            {"type": "status_not_5xx"},
            {"type": "header_equals", "header": "x-content-type-options", "value": "nosniff"},
            {"type": "header_contains", "header": "content-security-policy", "value": "frame-ancestors"},
        ]
        result = self.workbench.evaluate_response(
            checks,
            {
                "status_code": 200,
                "headers": {
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                },
                "body": "ok",
            },
        )
        self.assertTrue(result["passed"])


if __name__ == "__main__":
    unittest.main()
