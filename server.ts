import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import axios from "axios";
import * as cheerio from "cheerio";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/scan", async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });

    try {
      const startTime = Date.now();
      const response = await axios.get(url, {
        headers: {
          'User-Agent': 'SecurifiAudit/1.0 (Ethical Security Researcher)',
        },
        timeout: 10000,
        validateStatus: () => true, // Capture all status codes
      });

      const $ = cheerio.load(response.data);
      const headers = response.headers;
      
      // Analyze Headers
      const securityHeaders = {
        "Content-Security-Policy": headers["content-security-policy"],
        "Strict-Transport-Security": headers["strict-transport-security"],
        "X-Frame-Options": headers["x-frame-options"],
        "X-Content-Type-Options": headers["x-content-type-options"],
        "Referrer-Policy": headers["referrer-policy"],
        "Permissions-Policy": headers["permissions-policy"],
      };

      const findings: any[] = [];
      
      // Basic Header Checks
      if (!securityHeaders["Content-Security-Policy"]) {
        findings.push({
          type: "Warning",
          category: "Security Headers",
          item: "CSP Missing",
          description: "Content Security Policy is not implemented. This increases vulnerability to XSS.",
          severity: "High"
        });
      }
      if (!securityHeaders["Strict-Transport-Security"]) {
         findings.push({
          type: "Warning",
          category: "Security Headers",
          item: "HSTS Missing",
          description: "HTTP Strict Transport Security not enforced. Risk of SSL stripping.",
          severity: "Medium"
        });
      }

      // Analyze Forms for potential XSS/SQLi risks (just looking for inputs)
      const formsCount = $("form").length;
      const inputs = $("input").length;
      if (formsCount > 0) {
        findings.push({
          type: "Info",
          category: "Attack Surface",
          item: "Active Forms Detected",
          description: `Found ${formsCount} forms with ${inputs} inputs. These are potential entry points for SQLi and XSS.`,
          severity: "Low"
        });
      }

      // Look for technology stack (Server, X-Powered-By)
      const serverHeader = headers["server"];
      const poweredBy = headers["x-powered-by"];
      if (serverHeader || poweredBy) {
        findings.push({
          type: "Warning",
          category: "Information Disclosure",
          item: "Server Signature Exposed",
          description: `Server: ${serverHeader || 'N/A'}, X-Powered-By: ${poweredBy || 'N/A'}. This helps attackers identify the tech stack.`,
          severity: "Low"
        });
      }

      // Extract metadata/tech stack hints
      const techStack = [];
      if ($('script[src*="react"]').length) techStack.push("React");
      if ($('script[src*="jquery"]').length) techStack.push("jQuery");
      if ($('meta[name="generator"]').length) techStack.push($('meta[name="generator"]').attr('content'));

      res.json({
        url,
        status: response.status,
        responseTime: Date.now() - startTime,
        headers: securityHeaders,
        techStack,
        findings,
        rawHtmlSnippet: response.data.toString().substring(0, 500),
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Mock Subdomain Scan (Using simulation logic)
  app.post("/api/subdomains", async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: "Domain is required" });

    // In a real app, you'd use APIs like SecurityTrails, crt.sh, or brute forcing.
    // For this demo, we'll simulate common subdomains for the provided root domain.
    const root = domain.replace(/^https?:\/\//, '').split('/')[0];
    const commonPrefixes = ['www', 'api', 'dev', 'staging', 'mail', 'admin', 'test', 'portal', 'm', 'docs'];
    
    // Simulate discovery
    const subdomains = commonPrefixes.map(p => ({
      host: `${p}.${root}`,
      status: Math.random() > 0.4 ? 'Active' : 'Unreachable',
      ip: `192.168.1.${Math.floor(Math.random() * 254)}`, // Simulation
    })).filter(s => s.status === 'Active');

    res.json({ domain: root, subdomains });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Securifi Server running on http://localhost:${PORT}`);
  });
}

startServer();
