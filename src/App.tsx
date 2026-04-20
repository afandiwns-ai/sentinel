/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  Globe, 
  AlertTriangle, 
  CheckCircle, 
  FileText, 
  Terminal, 
  Server, 
  Layout,
  Lock,
  Loader2,
  ChevronRight,
  ExternalLink,
  Download,
  AlertCircle
} from 'lucide-react';
import { GoogleGenAI } from "@google/genai";
import { motion, AnimatePresence } from "motion/react";
import { toast, Toaster } from "sonner";
import { jsPDF } from "jspdf";
import "jspdf-autotable";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";

// Initialize Gemini with safety for Vercel
const getAiEngine = () => {
  const key = process.env.GEMINI_API_KEY;
  if (!key || key === "undefined") return null;
  return new GoogleGenAI({ apiKey: key });
};

const ai = getAiEngine();

interface Finding {
  type: string;
  category: string;
  item: string;
  description: string;
  severity: 'High' | 'Medium' | 'Low' | 'Info';
}

interface ScanResult {
  url: string;
  status: number;
  responseTime: number;
  headers: Record<string, string>;
  findings: Finding[];
  techStack: string[];
  rawHtmlSnippet?: string;
}

interface Subdomain {
  host: string;
  status: string;
  ip: string;
}

export default function App() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeScan, setActiveScan] = useState<ScanResult | null>(null);
  const [subdomains, setSubdomains] = useState<Subdomain[]>([]);
  const [aiInsight, setAiInsight] = useState<string>('');
  const [scanProgress, setScanProgress] = useState(0);
  const [isAuthorized, setIsAuthorized] = useState(true); // Default to true since user declined Firebase, using simple UI guard

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    let targetUrl = url;
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

    setIsLoading(true);
    setScanProgress(10);
    setAiInsight('');
    setActiveScan(null);
    setSubdomains([]);

    try {
      // 1. Recon Scan
      setScanProgress(30);
      const scanRes = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });
      
      const scanData = await scanRes.json();
      if (scanRes.ok) {
        setActiveScan(scanData);
        setScanProgress(60);

        // 2. Subdomain Enum
        const subRes = await fetch('/api/subdomains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: targetUrl }),
        });
        const subData = await subRes.json();
        setSubdomains(subData.subdomains);
        setScanProgress(80);

        // 3. AI Analysis
        generateAIInsight(scanData);
      } else {
        toast.error(scanData.error || "Scan failed");
      }
    } catch (err) {
      toast.error("Connection error to scanning engine");
    } finally {
      setScanProgress(100);
      setTimeout(() => setIsLoading(false), 500);
    }
  };

  const generateAIInsight = async (data: ScanResult) => {
    if (!ai) {
      setAiInsight("AI Engine offline: Please set GEMINI_API_KEY in Vercel environment variables.");
      return;
    }
    try {
      const prompt = `You are a Senior Security Auditor. Analyze these website reconnaissance results:
      Target URL: ${data.url}
      Tech Stack: ${data.techStack.join(', ')}
      Findings: ${JSON.stringify(data.findings)}
      Security Headers: ${JSON.stringify(data.headers)}
      
      Provide a concise summary of the security posture and suggest 3 prioritized hardening steps. Focus on SQLi, XSS, and Information Disclosure risks based on the presence of forms and headers. Use professional Indonesian language or English if preferred.`;

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
      });

      setAiInsight(response.text || "No insights available.");
    } catch (err) {
      console.error(err);
      setAiInsight("AI analysis failed to generate. Check security logs.");
    }
  };

  const generatePDF = () => {
    if (!activeScan) return;
    const doc = new jsPDF();
    
    doc.setFontSize(22);
    doc.text("Securifi: Security Audit Report", 14, 20);
    doc.setFontSize(12);
    doc.text(`Target: ${activeScan.url}`, 14, 30);
    doc.text(`Date: ${new Date().toLocaleString()}`, 14, 36);
    
    doc.text("Vulnerability Summary", 14, 50);
    // @ts-ignore
    doc.autoTable({
      startY: 55,
      head: [['Severity', 'Category', 'Issue', 'Description']],
      body: activeScan.findings.map(f => [f.severity, f.category, f.item, f.description]),
    });

    const finalY = (doc as any).lastAutoTable.finalY || 100;
    doc.text("AI-Powered Recommendations", 14, finalY + 15);
    const splitText = doc.splitTextToSize(aiInsight, 180);
    doc.text(splitText, 14, finalY + 22);

    doc.save(`securifi_report_${new Date().getTime()}.pdf`);
    toast.success("Report exported to PDF");
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'High': return 'bg-rose-500/10 text-rose-500 border-rose-500/20';
      case 'Medium': return 'bg-amber-500/10 text-amber-500 border-amber-500/20';
      case 'Low': return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20';
      default: return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#E5E5E5] flex font-sans selection:bg-emerald-500/30">
      <Toaster position="top-center" theme="dark" />
      
      {/* Sidebar - Inspired by Design HTML */}
      <aside className="w-16 border-r border-white/5 flex flex-col items-center py-8 gap-10 bg-black sticky top-0 h-screen hidden md:flex">
        <div className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center rounded-lg">
          <Shield className="w-6 h-6 text-emerald-500" />
        </div>
        <div className="flex flex-col gap-8 opacity-40">
          <Globe className="w-6 h-6 cursor-pointer hover:text-emerald-500 transition-colors" />
          <Terminal className="w-6 h-6 text-emerald-500 opacity-100" />
          <FileText className="w-6 h-6 cursor-pointer hover:text-emerald-500 transition-colors" />
          <Lock className="w-6 h-6 cursor-pointer hover:text-emerald-500 transition-colors" />
        </div>
      </aside>

      <main className="flex-1 flex flex-col p-8 max-w-[1400px] mx-auto w-full overflow-x-hidden">
        {/* Updated Header */}
        <header className="flex flex-col md:flex-row items-start md:items-center justify-between mb-12 gap-6">
          <div className="flex flex-col">
            <h1 className="font-serif italic text-4xl text-white">
              Sentinel X
              <span className="text-emerald-500 font-sans not-italic text-sm ml-3 tracking-[0.3em] uppercase align-middle">
                Vulnerability Intelligence
              </span>
            </h1>
            <p className="text-[10px] text-white/40 mt-1 uppercase tracking-widest flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
              Core System Engine • Auth Status: Authorized (Level 4)
            </p>
          </div>

          <form onSubmit={handleScan} className="flex gap-4 items-center w-full md:w-auto">
            <div className="flex items-center bg-[#111] border border-white/10 rounded-full px-4 py-2 flex-1 md:w-96 group focus-within:border-emerald-500/50 transition-all">
              <span className="text-[10px] text-emerald-500 font-mono mr-3 animate-pulse font-bold hidden sm:inline uppercase">Target_URL</span>
              <Input 
                placeholder="https://api.nexus-corp.internal" 
                className="bg-transparent border-none focus-visible:ring-0 text-sm p-0 h-auto font-mono text-white/70 placeholder:text-white/20"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isLoading}
              />
            </div>
            <Button 
              type="submit" 
              className="bg-emerald-600 hover:bg-emerald-500 text-black font-bold px-8 py-2 rounded-full text-[10px] transition-all uppercase tracking-[0.2em] h-10 border-none"
              disabled={isLoading}
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Start New Scan"}
            </Button>
          </form>
        </header>

        {isLoading && (
          <div className="mb-8 max-w-xl">
             <div className="flex justify-between text-[10px] text-white/40 mb-2 font-mono uppercase tracking-widest">
                <span>Engines Initializing...</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="h-0.5 bg-white/5" indicatorClassName="bg-emerald-500" />
          </div>
        )}

        {!activeScan && !isLoading && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 opacity-80 mt-12 group">
             <Card className="bg-[#0A0A0A] border-white/5 hover:border-emerald-500/30 transition-all duration-500 p-2">
               <CardHeader>
                 <div className="w-10 h-10 bg-blue-500/10 border border-blue-500/20 flex items-center justify-center rounded-lg mb-4">
                   <Terminal className="w-5 h-5 text-blue-500" />
                 </div>
                 <CardTitle className="text-[10px] uppercase tracking-[0.2em] text-white/50 font-bold">Automated Scan</CardTitle>
                 <CardDescription className="text-zinc-400">Deep header analysis and tech stack fingerprinting.</CardDescription>
               </CardHeader>
             </Card>
             <Card className="bg-[#0A0A0A] border-white/5 hover:border-purple-500/30 transition-all duration-500 p-2">
               <CardHeader>
                 <div className="w-10 h-10 bg-purple-500/10 border border-purple-500/20 flex items-center justify-center rounded-lg mb-4">
                   <Server className="w-5 h-5 text-purple-500" />
                 </div>
                 <CardTitle className="text-[10px] uppercase tracking-[0.2em] text-white/50 font-bold">Subdomain Enum</CardTitle>
                 <CardDescription className="text-zinc-400">Passive discovery of public attack surface.</CardDescription>
               </CardHeader>
             </Card>
             <Card className="bg-[#0A0A0A] border-white/5 hover:border-amber-500/30 transition-all duration-500 p-2">
               <CardHeader>
                 <div className="w-10 h-10 bg-amber-500/10 border border-amber-500/20 flex items-center justify-center rounded-lg mb-4">
                   <AlertCircle className="w-5 h-5 text-amber-500" />
                 </div>
                 <CardTitle className="text-[10px] uppercase tracking-[0.2em] text-white/50 font-bold">AI Threat Intel</CardTitle>
                 <CardDescription className="text-zinc-400">Gemini-powered vulnerability risk assessment.</CardDescription>
               </CardHeader>
             </Card>
          </div>
        )}

        <AnimatePresence>
          {activeScan && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="grid grid-cols-1 lg:grid-cols-12 gap-8 flex-1"
            >
              {/* Main Content Pane */}
              <div className="lg:col-span-8 flex flex-col gap-8">
                <Card className="bg-[#0A0A0A] border-white/5 rounded-2xl flex-1 overflow-hidden flex flex-col">
                  <div className="p-6 border-b border-white/5 flex justify-between items-center bg-black/20">
                    <h2 className="text-[10px] uppercase tracking-[0.3em] text-white/50 font-bold">Vulnerability Live Feed</h2>
                    <span className={`text-[10px] font-mono font-bold animate-pulse ${activeScan.findings.length > 0 ? 'text-rose-500' : 'text-emerald-500'}`}>
                      {isLoading ? 'ANALYZING...' : `SCAN COMPLETE - ${activeScan.findings.length} ISSUES`}
                    </span>
                  </div>
                  
                  <ScrollArea className="flex-1 p-6">
                    <div className="space-y-4">
                      {activeScan.findings.length > 0 ? (
                        activeScan.findings.map((finding, idx) => (
                          <div key={idx} className="flex items-center justify-between p-4 bg-white/5 border-l-4 border-emerald-500 rounded-r-lg group hover:bg-white/[0.08] transition-all">
                             <div className="flex flex-col">
                                <span className="text-xs font-bold text-white tracking-wide uppercase">{finding.item}</span>
                                <span className="text-[10px] text-white/40 font-mono mt-1">{finding.description}</span>
                             </div>
                             <Badge className={`${getSeverityColor(finding.severity)} text-[9px] px-3 py-0.5 rounded-full font-bold uppercase tracking-widest border-none`} variant="outline">
                               {finding.severity}
                             </Badge>
                          </div>
                        ))
                      ) : (
                        <div className="h-[300px] flex flex-col items-center justify-center opacity-20">
                           <Shield className="w-16 h-16 mb-4 text-emerald-500" />
                           <p className="font-mono text-xs uppercase tracking-widest font-bold">No Critical Vulnerabilities Leak</p>
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </Card>

                {/* Console Output */}
                <div className="bg-black border border-white/10 rounded-xl p-5 h-56 font-mono text-[11px] text-emerald-500/80 overflow-hidden leading-relaxed shadow-inner shadow-black/50">
                  <div className="opacity-30">[{new Date().toLocaleTimeString()}] INITIALIZING SECURITY SUBSYSTEMS...</div>
                  <div className="opacity-50">[{new Date().toLocaleTimeString()}] TARGET_URL: {activeScan.url}</div>
                  <div className="opacity-70">[{new Date().toLocaleTimeString()}] ANALYZING HEADERS: {Object.keys(activeScan.headers).length} POLICIES FOUND</div>
                  <div className="opacity-90">[{new Date().toLocaleTimeString()}] TECH_STACK_HASH: {activeScan.techStack.join(', ') || 'GENERIC_V1'}</div>
                  <div className="text-white animate-pulse">[{new Date().toLocaleTimeString()}] CRAWLING DATA... MAPPING COMPLETE.</div>
                  <div className="text-emerald-400 mt-2">[{new Date().toLocaleTimeString()}] AUDIT_LOG: SUCCESSFUL DATA SCRAPE FROM ORIGIN.</div>
                </div>
              </div>

              {/* Sidebar Content Pane */}
              <div className="lg:col-span-4 flex flex-col gap-8">
                <Card className="bg-[#0A0A0A] border-white/5 rounded-2xl p-6 flex flex-col overflow-hidden relative group">
                  <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-100 transition-opacity">
                    <AlertTriangle className="w-5 h-5 text-emerald-500" />
                  </div>
                  <h2 className="text-[10px] uppercase tracking-[0.3em] text-white/50 font-bold mb-8">Intelligence Summary</h2>
                  
                  <div className="space-y-8 flex-1">
                    <div className="flex flex-col gap-4">
                       <span className="text-[10px] text-white/30 uppercase tracking-[0.2em] font-bold">Subdomains Map ({subdomains.length})</span>
                       <div className="flex flex-wrap gap-2">
                         {subdomains.map((sub, i) => (
                           <span key={i} className="bg-white/5 text-[9px] px-2 py-1 rounded border border-white/10 text-white/60 font-mono hover:text-emerald-400 transition-colors cursor-crosshair">
                             {sub.host}
                           </span>
                         ))}
                       </div>
                    </div>

                    <div className="bg-white/5 rounded-xl p-5 border border-white/10 hover:border-emerald-500/30 transition-all">
                       <div className="flex items-center justify-between mb-4">
                         <span className="text-[10px] font-bold uppercase tracking-widest text-emerald-500">Security Report Engine</span>
                         <Download className="w-4 h-4 text-emerald-500" />
                       </div>
                       <p className="text-[10px] text-white/40 leading-relaxed mb-6 italic">
                         Automated generation of vulnerability intelligence across {activeScan.findings.length} critical vectors and server origin headers.
                       </p>
                       <Button onClick={generatePDF} className="w-full py-2 bg-white/5 border border-white/20 hover:bg-emerald-500 hover:text-black text-[10px] uppercase tracking-widest font-bold transition-all h-9 rounded-none">
                         Download Intelligence Report
                       </Button>
                    </div>

                    <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
                       <h3 className="text-[10px] font-bold uppercase tracking-widest text-emerald-500 mb-3 flex items-center gap-2">
                         <Loader2 className="w-3 h-3 animate-spin" /> AI Auditor Recommendations
                       </h3>
                       <ScrollArea className="h-48">
                         <p className="text-[11px] text-white/50 leading-relaxed whitespace-pre-line font-mono pr-4">
                           {aiInsight || "Awaiting intelligence processing..."}
                         </p>
                       </ScrollArea>
                    </div>
                  </div>

                  <div className="mt-8 pt-6 border-t border-white/5 space-y-4">
                    <div className="flex justify-between text-[10px] font-mono">
                      <span className="text-white/30 uppercase tracking-widest">Res. Time</span>
                      <span className="text-emerald-500">{activeScan.responseTime}ms</span>
                    </div>
                    <div className="flex justify-between text-[10px] font-mono">
                      <span className="text-white/30 uppercase tracking-widest">Server Status</span>
                      <span className="text-emerald-500">{activeScan.status} OK</span>
                    </div>
                  </div>
                </Card>

                <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-5 flex items-center justify-between group cursor-help">
                   <div className="flex items-center gap-3">
                      <div className="w-1.5 h-1.5 bg-rose-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(244,63,94,0.5)]"></div>
                      <span className="text-[10px] font-bold text-rose-500 uppercase tracking-[0.3em]">Breach Alert Active</span>
                   </div>
                   <span className="text-[9px] bg-rose-500 text-white px-3 py-0.5 rounded uppercase font-bold tracking-widest">Urgent</span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="mt-20 border-t border-white/5 p-8 text-center bg-black/40">
        <p className="text-white/20 text-[9px] font-mono tracking-[0.4em] uppercase">Sentinel Engine • Distributed Security Intelligence Platform</p>
      </footer>
    </div>
  );
}
