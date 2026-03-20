// ---------------------------------------------------------------------------
// Kill-AI-Leak — VS Code Local Proxy
//
// Starts an HTTP proxy on localhost that intercepts outbound requests to
// known AI API endpoints. The proxy:
//   1. Inspects request bodies for PII/secrets before forwarding
//   2. Inspects response bodies for vulnerabilities/leakage
//   3. Forwards events to the Kill-AI-Leak gateway for full analysis
//   4. Sets HTTPS_PROXY env so child processes (AI assistants) route through it
// ---------------------------------------------------------------------------

import * as http from "http";
import * as https from "https";
import * as net from "net";
import { URL } from "url";

// ---------------------------------------------------------------------------
// AI API domains that the proxy intercepts for scanning
// ---------------------------------------------------------------------------

const INTERCEPTED_HOSTS = new Set([
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.cohere.ai",
  "api.mistral.ai",
  "api.groq.com",
  "api.together.xyz",
  "api.fireworks.ai",
  "api.deepseek.com",
  "api.replicate.com",
  "api-inference.huggingface.co",
  "api.stability.ai",
  "api.openrouter.ai",
]);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProxyConfig {
  port: number;
  serverUrl: string;
  authToken: string;
  onEvent: (event: ProxyEvent) => void;
}

export interface ProxyEvent {
  severity: "info" | "warning" | "error";
  message: string;
  host?: string;
  method?: string;
  path?: string;
  findings?: ProxyFinding[];
}

export interface ProxyFinding {
  type: string;
  label: string;
  severity: string;
  value: string;
}

// ---------------------------------------------------------------------------
// Lightweight secret / PII regex patterns (subset for fast inline scanning)
// ---------------------------------------------------------------------------

interface QuickPattern {
  label: string;
  severity: string;
  regex: RegExp;
}

const QUICK_PATTERNS: QuickPattern[] = [
  { label: "ssn", severity: "critical", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: "credit_card", severity: "critical", regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g },
  { label: "aws_access_key", severity: "critical", regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
  { label: "github_token", severity: "critical", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g },
  { label: "private_key", severity: "critical", regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { label: "openai_key", severity: "critical", regex: /\bsk-proj-[A-Za-z0-9_-]{40,200}\b/g },
  { label: "anthropic_key", severity: "critical", regex: /\bsk-ant-[A-Za-z0-9_-]{40,200}\b/g },
  { label: "password", severity: "high", regex: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']/gi },
  { label: "connection_string", severity: "critical", regex: /(?:mongodb|postgres(?:ql)?|mysql|redis):\/\/[^\s]+:[^\s]+@[^\s]+/gi },
];

function quickScan(text: string): ProxyFinding[] {
  const findings: ProxyFinding[] = [];
  for (const pattern of QUICK_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      findings.push({
        type: "secret",
        label: pattern.label,
        severity: pattern.severity,
        value: redact(match[0]),
      });
    }
  }
  return findings;
}

function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 4) + "*".repeat(Math.max(value.length - 6, 0)) + value.slice(-2);
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

export class ProxyServer {
  private config: ProxyConfig;
  private server: http.Server | null = null;
  private previousHttpsProxy: string | undefined;

  constructor(config: ProxyConfig) {
    this.config = config;
  }

  // -----------------------------------------------------------------------
  // Start / Stop
  // -----------------------------------------------------------------------

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.on("connect", (req, clientSocket, head) => {
        this.handleConnect(req, clientSocket, head);
      });

      this.server.on("error", (err) => {
        this.config.onEvent({
          severity: "error",
          message: `Proxy server error: ${err.message}`,
        });
        reject(err);
      });

      this.server.listen(this.config.port, "127.0.0.1", () => {
        this.config.onEvent({
          severity: "info",
          message: `Proxy listening on 127.0.0.1:${this.config.port}`,
        });

        // Set HTTPS_PROXY for child processes.
        this.previousHttpsProxy = process.env.HTTPS_PROXY;
        process.env.HTTPS_PROXY = `http://127.0.0.1:${this.config.port}`;
        process.env.HTTP_PROXY = `http://127.0.0.1:${this.config.port}`;

        resolve();
      });
    });
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }

    // Restore previous proxy settings.
    if (this.previousHttpsProxy !== undefined) {
      process.env.HTTPS_PROXY = this.previousHttpsProxy;
    } else {
      delete process.env.HTTPS_PROXY;
    }
    delete process.env.HTTP_PROXY;

    this.config.onEvent({
      severity: "info",
      message: "Proxy server stopped",
    });
  }

  // -----------------------------------------------------------------------
  // HTTP request handler (plain HTTP proxy)
  // -----------------------------------------------------------------------

  private handleRequest(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse,
  ): void {
    const url = clientReq.url ?? "";
    let parsedUrl: URL;

    try {
      parsedUrl = new URL(url);
    } catch {
      clientRes.writeHead(400, { "Content-Type": "text/plain" });
      clientRes.end("Bad Request");
      return;
    }

    const hostname = parsedUrl.hostname;
    const isIntercepted = INTERCEPTED_HOSTS.has(hostname);

    // Collect request body if this is a POST to an AI endpoint.
    if (isIntercepted && clientReq.method === "POST") {
      this.interceptAndForward(clientReq, clientRes, parsedUrl);
      return;
    }

    // Pass through.
    this.forwardRequest(clientReq, clientRes, parsedUrl);
  }

  // -----------------------------------------------------------------------
  // HTTPS CONNECT handler (tunnel)
  // -----------------------------------------------------------------------

  private handleConnect(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
  ): void {
    const [hostname, portStr] = (req.url ?? "").split(":");
    const port = parseInt(portStr, 10) || 443;

    this.config.onEvent({
      severity: "info",
      message: `CONNECT tunnel to ${hostname}:${port}`,
      host: hostname,
    });

    // For intercepted hosts, we would need MITM with a self-signed CA.
    // In this implementation we create a transparent tunnel and log the
    // connection. Full MITM would require the user to trust a local CA.
    const serverSocket = net.connect(port, hostname, () => {
      clientSocket.write(
        "HTTP/1.1 200 Connection Established\r\n" +
        "Proxy-Agent: Kill-AI-Leak\r\n" +
        "\r\n",
      );
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on("error", (err) => {
      this.config.onEvent({
        severity: "error",
        message: `Tunnel error to ${hostname}: ${err.message}`,
        host: hostname,
      });
      clientSocket.end();
    });

    clientSocket.on("error", () => {
      serverSocket.end();
    });
  }

  // -----------------------------------------------------------------------
  // Interception (scan body, then forward)
  // -----------------------------------------------------------------------

  private interceptAndForward(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse,
    url: URL,
  ): void {
    const chunks: Buffer[] = [];

    clientReq.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });

    clientReq.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf-8");
      const findings = quickScan(body);

      if (findings.length > 0) {
        this.config.onEvent({
          severity: "warning",
          message: `Detected ${findings.length} sensitive item(s) in request to ${url.hostname}${url.pathname}`,
          host: url.hostname,
          method: clientReq.method ?? "POST",
          path: url.pathname,
          findings,
        });

        // Forward event to Kill-AI-Leak API.
        this.reportToGateway(url.hostname, body, findings).catch(() => {});
      }

      // Forward the request regardless (monitoring mode).
      this.forwardWithBody(clientReq, clientRes, url, Buffer.concat(chunks));
    });
  }

  // -----------------------------------------------------------------------
  // Request forwarding
  // -----------------------------------------------------------------------

  private forwardRequest(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse,
    url: URL,
  ): void {
    const isHTTPS = url.protocol === "https:";
    const lib = isHTTPS ? https : http;

    const options: http.RequestOptions = {
      hostname: url.hostname,
      port: url.port || (isHTTPS ? 443 : 80),
      path: url.pathname + url.search,
      method: clientReq.method,
      headers: { ...clientReq.headers, host: url.hostname },
    };

    const proxyReq = lib.request(options, (proxyRes) => {
      clientRes.writeHead(proxyRes.statusCode ?? 500, proxyRes.headers);
      proxyRes.pipe(clientRes, { end: true });
    });

    proxyReq.on("error", (err) => {
      this.config.onEvent({
        severity: "error",
        message: `Forward error to ${url.hostname}: ${err.message}`,
        host: url.hostname,
      });
      clientRes.writeHead(502, { "Content-Type": "text/plain" });
      clientRes.end("Bad Gateway");
    });

    clientReq.pipe(proxyReq, { end: true });
  }

  private forwardWithBody(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse,
    url: URL,
    body: Buffer,
  ): void {
    const isHTTPS = url.protocol === "https:";
    const lib = isHTTPS ? https : http;

    const options: http.RequestOptions = {
      hostname: url.hostname,
      port: url.port || (isHTTPS ? 443 : 80),
      path: url.pathname + url.search,
      method: clientReq.method,
      headers: {
        ...clientReq.headers,
        host: url.hostname,
        "content-length": String(body.length),
      },
    };

    const proxyReq = lib.request(options, (proxyRes) => {
      // Scan the response body for the intercepted hosts.
      const responseChunks: Buffer[] = [];

      proxyRes.on("data", (chunk: Buffer) => {
        responseChunks.push(chunk);
      });

      proxyRes.on("end", () => {
        const responseBody = Buffer.concat(responseChunks).toString("utf-8");

        // Scan response.
        const responseFindings = quickScan(responseBody);
        if (responseFindings.length > 0) {
          this.config.onEvent({
            severity: "warning",
            message: `Detected ${responseFindings.length} sensitive item(s) in response from ${url.hostname}`,
            host: url.hostname,
            findings: responseFindings,
          });
        }

        // Write response to client.
        clientRes.writeHead(proxyRes.statusCode ?? 500, proxyRes.headers);
        clientRes.end(Buffer.concat(responseChunks));
      });
    });

    proxyReq.on("error", (err) => {
      this.config.onEvent({
        severity: "error",
        message: `Forward error to ${url.hostname}: ${err.message}`,
        host: url.hostname,
      });
      clientRes.writeHead(502, { "Content-Type": "text/plain" });
      clientRes.end("Bad Gateway");
    });

    proxyReq.write(body);
    proxyReq.end();
  }

  // -----------------------------------------------------------------------
  // Report to Kill-AI-Leak gateway
  // -----------------------------------------------------------------------

  private async reportToGateway(
    hostname: string,
    _body: string,
    findings: ProxyFinding[],
  ): Promise<void> {
    if (!this.config.serverUrl || !this.config.authToken) return;

    const event = {
      source: "ide",
      severity: findings.some((f) => f.severity === "critical")
        ? "critical"
        : "high",
      actor: {
        type: "user",
        id: "vscode-user",
      },
      target: {
        type: "llm_provider",
        id: hostname,
        provider: hostname,
        endpoint: `https://${hostname}`,
      },
      action: {
        type: "api_call",
        direction: "outbound",
        protocol: "https",
        method: "POST",
      },
      content: {
        has_prompt: true,
        blocked: false,
        anonymized: false,
        pii_detected: findings.map((f) => f.label),
      },
    };

    try {
      const url = `${this.config.serverUrl}/api/v1/events`;
      const body = JSON.stringify({ events: [event] });

      const parsedUrl = new URL(url);
      const isHTTPS = parsedUrl.protocol === "https:";
      const lib = isHTTPS ? https : http;

      await new Promise<void>((resolve, reject) => {
        const req = lib.request(
          {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (isHTTPS ? 443 : 80),
            path: parsedUrl.pathname,
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${this.config.authToken}`,
              "Content-Length": Buffer.byteLength(body).toString(),
            },
          },
          (res) => {
            res.resume(); // Drain response.
            resolve();
          },
        );

        req.on("error", reject);
        req.write(body);
        req.end();
      });
    } catch {
      // Silently fail — do not block the user's request.
    }
  }
}
