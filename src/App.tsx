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
  intel?: {
    server: string;
    os: string;
    isp: string;
    ports: number[];
    technologies: string[];
  };
  scrapedData?: {
    title: string;
    description: string;
    linksCount: number;
    internalLinks: string[];
    discoveredPaths?: { path: string; status: number; type: string }[];
  };
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
  const [subdomainSource, setSubdomainSource] = useState<string>('');
  const [aiInsight, setAiInsight] = useState<string>('');
  const [scanProgress, setScanProgress] = useState(0);
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [activeView, setActiveView] = useState<'dashboard' | 'subdomains' | 'reports' | 'settings'>('dashboard');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  
  // Auth State
  const [user, setUser] = useState<{ username: string } | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('securifi_token'));
  const [isAuthMode, setIsAuthMode] = useState<'login' | 'signup'>('login');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => {
    if (token) {
      const storedUser = localStorage.getItem('securifi_user');
      if (storedUser) setUser(JSON.parse(storedUser));
      fetchHistory();
    }
  }, [token]);

  const fetchHistory = async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.error("History fetch failed");
    }
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAuthenticating(true);
    const endpoint = isAuthMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
    
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: authUsername, password: authPassword }),
      });
      const data = await res.json();
      
      if (res.ok) {
        if (isAuthMode === 'login') {
          setToken(data.token);
          setUser({ username: data.username });
          localStorage.setItem('securifi_token', data.token);
          localStorage.setItem('securifi_user', JSON.stringify({ username: data.username }));
          toast.success(`Welcome back, ${data.username}`);
        } else {
          setIsAuthMode('login');
          toast.success("Account created! Please login.");
        }
      } else {
        toast.error(data.error || "Authentication failed");
      }
    } catch (err) {
      toast.error("Auth connection error");
    } finally {
      setIsAuthenticating(false);
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('securifi_token');
    localStorage.removeItem('securifi_user');
    toast.info("Logged out successfully");
  };

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
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url: targetUrl }),
      });
      
      const scanData = await scanRes.json();
      if (scanRes.ok) {
        setActiveScan(scanData);
        fetchHistory(); // Refresh history after scan
        setScanProgress(60);

        // 2. Subdomain Enum
        const subRes = await fetch('/api/subdomains', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ domain: targetUrl }),
        });
        const subData = await subRes.json();
        setSubdomains(subData.subdomains);
        setSubdomainSource(subData.source || 'Standard Intelligence');
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
      const prompt = `You are a Senior Cyber Intelligence Auditor (Shodan-style). Analyze these raw reconnaissance results for REAL vulnerabilities:
      Target URL: ${data.url}
      Service Banners: ${data.intel?.server} / OS: ${data.intel?.os}
      Active Ports: ${data.intel?.ports?.join(', ')}
      Discovered Paths: ${JSON.stringify(data.scrapedData?.discoveredPaths)}
      Tech Stack: ${data.techStack.join(', ')}
      Findings: ${JSON.stringify(data.findings)}
      Security Headers: ${JSON.stringify(data.headers)}
      
      STRICT INSTRUCTIONS: 
      1. Do NOT hallucinate. Only comment on vulnerabilities that have a basis in the data above (e.g., if you see a specific server version or a sensitive path like /.git).
      2. Match the Server header versions against known CVE patterns if possible.
      3. If a sensitive path (like /.env or /admin) was discovered, prioritize that.
      4. Use professional Indonesian language.
      
      Provide a concise 3-step actionable exploit-prevention plan.`;

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
      
      {/* Auth Overlay */}
      <AnimatePresence>
        {!token && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/90 z-[200] flex items-center justify-center p-6 backdrop-blur-xl"
          >
            <Card className="w-full max-w-md bg-[#0A0A0A] border-white/10 shadow-2xl overflow-hidden relative">
              <div className="absolute top-0 inset-x-0 h-1 bg-emerald-500" />
              <CardHeader className="text-center pb-2">
                <div className="w-16 h-16 bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center rounded-2xl mx-auto mb-6 transform rotate-3">
                   <Shield className="w-8 h-8 text-emerald-500" />
                </div>
                <CardTitle className="font-serif italic text-3xl text-white">Sentinel X</CardTitle>
                <CardDescription className="text-[10px] uppercase tracking-widest text-emerald-500 font-bold mt-2">
                  Cognitive Security Intelligence
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleAuth} className="space-y-6 mt-4">
                   <div className="space-y-2">
                      <label className="text-[10px] text-white/30 uppercase tracking-widest font-mono">Operator ID</label>
                      <Input 
                        placeholder="username" 
                        className="bg-black border-white/5 focus:border-emerald-500/50"
                        value={authUsername}
                        onChange={(e) => setAuthUsername(e.target.value)}
                        required
                      />
                   </div>
                   <div className="space-y-2">
                      <label className="text-[10px] text-white/30 uppercase tracking-widest font-mono">Access Key</label>
                      <Input 
                        type="password" 
                        placeholder="••••••••" 
                        className="bg-black border-white/5 focus:border-emerald-500/50"
                        value={authPassword}
                        onChange={(e) => setAuthPassword(e.target.value)}
                        required
                      />
                   </div>
                   <Button 
                    className="w-full bg-emerald-600 hover:bg-emerald-500 text-black font-bold h-11 rounded-none uppercase tracking-widest text-xs"
                    disabled={isAuthenticating}
                   >
                     {isAuthenticating ? <Loader2 className="w-4 h-4 animate-spin" /> : 
                      isAuthMode === 'login' ? "Establish Connection" : "Initialize Account"}
                   </Button>
                </form>
              </CardContent>
              <CardFooter className="flex flex-col gap-4">
                 <button 
                  onClick={() => setIsAuthMode(isAuthMode === 'login' ? 'signup' : 'login')}
                  className="text-[10px] text-white/40 uppercase tracking-widest hover:text-emerald-500 transition-colors"
                 >
                   {isAuthMode === 'login' ? "Request new access credentials" : "Return to login terminal"}
                 </button>
                 <p className="text-[8px] text-white/20 text-center uppercase leading-relaxed font-mono">
                   Unauthorized access is strictly prohibited. All activities are monitored and logged.
                   By signing in, you agree to ethical usage policies.
                 </p>
              </CardFooter>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Sidebar - Integrated with Navigation State */}
      <aside className="w-16 border-r border-white/5 flex flex-col items-center py-8 gap-10 bg-black sticky top-0 h-screen hidden md:flex z-50">
        <div 
          onClick={() => setActiveView('dashboard')}
          className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center rounded-lg cursor-pointer hover:bg-emerald-500/20 transition-all"
        >
          <Shield className="w-6 h-6 text-emerald-500" />
        </div>
        <div className="flex flex-col gap-8">
          <div 
            onClick={() => setActiveView('dashboard')}
            title="Dashboard"
            className={`cursor-pointer transition-all hover:text-emerald-500 ${activeView === 'dashboard' ? 'text-emerald-500 opacity-100' : 'text-white/40'}`}
          >
            <Layout className="w-6 h-6" />
          </div>
          <div 
            onClick={() => setActiveView('subdomains')}
            title="Subdomains"
            className={`cursor-pointer transition-all hover:text-emerald-500 ${activeView === 'subdomains' ? 'text-emerald-500 opacity-100' : 'text-white/40'}`}
          >
            <Globe className="w-6 h-6" />
          </div>
          <div 
            onClick={() => setActiveView('reports')}
            title="Reports"
            className={`cursor-pointer transition-all hover:text-emerald-500 ${activeView === 'reports' ? 'text-emerald-500 opacity-100' : 'text-white/40'}`}
          >
            <FileText className="w-6 h-6" />
          </div>
          <div 
            onClick={() => setActiveView('settings')}
            title="Settings"
            className={`cursor-pointer transition-all hover:text-emerald-500 ${activeView === 'settings' ? 'text-emerald-500 opacity-100' : 'text-white/40'}`}
          >
            <Lock className="w-6 h-6" />
          </div>
        </div>

        <div className="mt-auto flex flex-col gap-6 items-center">
           <div className="w-8 h-8 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-[10px] font-bold text-emerald-500 uppercase">
             {user?.username?.[0] || 'O'}
           </div>
           <button onClick={logout} title="Logout" className="text-white/20 hover:text-rose-500 transition-colors">
             <Lock className="w-5 h-5" />
           </button>
        </div>
      </aside>

      {/* Mobile Menu Overlay */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div 
            initial={{ opacity: 0, x: -100 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -100 }}
            className="fixed inset-0 bg-black z-[100] p-8 flex flex-col gap-8 md:hidden"
          >
            <div className="flex justify-between items-center mb-10">
               <Shield className="w-10 h-10 text-emerald-500" />
               <Button variant="ghost" onClick={() => setIsMobileMenuOpen(false)} className="text-white">Close</Button>
            </div>
            <nav className="flex flex-col gap-6">
              <Button variant="ghost" onClick={() => { setActiveView('dashboard'); setIsMobileMenuOpen(false); }} className={`text-xl justify-start ${activeView === 'dashboard' ? 'text-emerald-500' : 'text-white/50'}`}>Dashboard</Button>
              <Button variant="ghost" onClick={() => { setActiveView('subdomains'); setIsMobileMenuOpen(false); }} className={`text-xl justify-start ${activeView === 'subdomains' ? 'text-emerald-500' : 'text-white/50'}`}>Subdomains</Button>
              <Button variant="ghost" onClick={() => { setActiveView('reports'); setIsMobileMenuOpen(false); }} className={`text-xl justify-start ${activeView === 'reports' ? 'text-emerald-500' : 'text-white/50'}`}>Reports</Button>
              <Button variant="ghost" onClick={() => { setActiveView('settings'); setIsMobileMenuOpen(false); }} className={`text-xl justify-start ${activeView === 'settings' ? 'text-emerald-500' : 'text-white/50'}`}>Settings</Button>
            </nav>
          </motion.div>
        )}
      </AnimatePresence>

      <main className="flex-1 flex flex-col p-8 max-w-[1400px] mx-auto w-full overflow-x-hidden">
        {/* Updated Header with Mobile Trigger */}
        <header className="flex flex-col md:flex-row items-start md:items-center justify-between mb-12 gap-6">
          <div className="flex items-center gap-4">
            <Button variant="ghost" className="md:hidden p-0 h-auto hover:bg-transparent" onClick={() => setIsMobileMenuOpen(true)}>
               <Layout className="w-8 h-8 text-white" />
            </Button>
            <div className="flex flex-col">
              <h1 className="font-serif italic text-4xl text-white">
                Sentinel X
                <span className="text-emerald-500 font-sans not-italic text-sm ml-3 tracking-[0.3em] uppercase align-middle">
                  Vulnerability Intelligence
                </span>
              </h1>
              <p className="text-[10px] text-white/40 mt-1 uppercase tracking-widest flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                Mode: {activeView.toUpperCase()} • Level 4 Security
              </p>
            </div>
          </div>
        </header>

        {/* View Switcher Logic */}
        <AnimatePresence mode="wait">
          {activeView === 'dashboard' && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.02 }}
              className="flex flex-col flex-1"
            >
              <form onSubmit={handleScan} className="flex gap-4 items-center w-full max-w-4xl mb-12">
                <div className="flex items-center bg-[#111] border border-white/10 rounded-full px-4 py-2 flex-1 group focus-within:border-emerald-500/50 transition-all">
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
                  className="bg-emerald-600 hover:bg-emerald-500 text-black font-bold px-8 py-2 rounded-full text-[10px] transition-all uppercase tracking-[0.2em] h-10 border-none shadow-[0_0_15px_rgba(16,185,129,0.2)]"
                  disabled={isLoading}
                >
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Run Scan"}
                </Button>
              </form>

              {isLoading && (
                <div className="mb-12 max-w-xl">
                   <div className="flex justify-between text-[10px] text-white/40 mb-2 font-mono uppercase tracking-widest">
                      <span>Engines Initializing...</span>
                      <span>{scanProgress}%</span>
                    </div>
                    <Progress value={scanProgress} className="h-0.5 bg-white/5" indicatorClassName="bg-emerald-500" />
                </div>
              )}

              {!activeScan && !isLoading && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 opacity-80 mt-12 group">
                   <Card className="bg-[#0A0A0A] border-white/5 hover:border-emerald-500/30 transition-all duration-500 p-2 transform hover:-translate-y-1">
                     <CardHeader>
                       <div className="w-10 h-10 bg-blue-500/10 border border-blue-500/20 flex items-center justify-center rounded-lg mb-4">
                         <Terminal className="w-5 h-5 text-blue-500" />
                       </div>
                       <CardTitle className="text-[10px] uppercase tracking-[0.2em] text-white/50 font-bold">Automated Recon</CardTitle>
                       <CardDescription className="text-zinc-400">Deep header analysis and tech stack fingerprinting.</CardDescription>
                     </CardHeader>
                   </Card>
                   <Card className="bg-[#0A0A0A] border-white/5 hover:border-purple-500/30 transition-all duration-500 p-2 transform hover:-translate-y-1">
                     <CardHeader>
                       <div className="w-10 h-10 bg-purple-500/10 border border-purple-500/20 flex items-center justify-center rounded-lg mb-4">
                         <Server className="w-5 h-5 text-purple-500" />
                       </div>
                       <CardTitle className="text-[10px] uppercase tracking-[0.2em] text-white/50 font-bold">Subdomain Mapper</CardTitle>
                       <CardDescription className="text-zinc-400">Passive discovery of public attack surface.</CardDescription>
                     </CardHeader>
                   </Card>
                   <Card className="bg-[#0A0A0A] border-white/5 hover:border-amber-500/30 transition-all duration-500 p-2 transform hover:-translate-y-1">
                     <CardHeader>
                       <div className="w-10 h-10 bg-amber-500/10 border border-amber-500/20 flex items-center justify-center rounded-lg mb-4">
                         <AlertCircle className="w-5 h-5 text-amber-500" />
                       </div>
                       <CardTitle className="text-[10px] uppercase tracking-[0.2em] text-white/50 font-bold">AI Threat Logic</CardTitle>
                       <CardDescription className="text-zinc-400">Gemini-powered vulnerability risk assessment.</CardDescription>
                     </CardHeader>
                   </Card>
                </div>
              )}

              {activeScan && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 flex-1">
                  {/* Main Content Pane */}
                  <div className="lg:col-span-8 flex flex-col gap-8">
                    <Card className="bg-[#0A0A0A] border-white/5 rounded-2xl flex-1 overflow-hidden flex flex-col min-h-[400px]">
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
                               <p className="font-mono text-xs uppercase tracking-widest font-bold">Safe Environment Verified</p>
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
                        <div className="bg-white/5 rounded-xl p-5 border border-white/10 hover:border-emerald-500/30 transition-all">
                           <div className="flex items-center justify-between mb-4">
                             <span className="text-[10px] font-bold uppercase tracking-widest text-emerald-500">Security Report Engine</span>
                             <Download className="w-4 h-4 text-emerald-500" />
                           </div>
                           <p className="text-[10px] text-white/40 leading-relaxed mb-6 italic">
                             Automated generation of vulnerability intelligence across {activeScan.findings.length} critical vectors.
                           </p>
                           <Button onClick={generatePDF} className="w-full py-2 bg-white/5 border border-white/20 hover:bg-emerald-500 hover:text-black text-[10px] uppercase tracking-widest font-bold transition-all h-9 rounded-none">
                             Download Technical PDF
                           </Button>
                        </div>

                        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
                           <h3 className="text-[10px] font-bold uppercase tracking-widest text-emerald-500 mb-3 flex items-center gap-2">
                             <Loader2 className="w-3 h-3 animate-spin" /> AI Auditor Recommendations
                           </h3>
                           <ScrollArea className="h-64">
                             <p className="text-[11px] text-white/50 leading-relaxed whitespace-pre-line font-mono pr-4">
                               {aiInsight || "Awaiting intelligence processing..."}
                             </p>
                           </ScrollArea>
                        </div>
                      </div>

                      <div className="mt-8 pt-6 border-t border-white/5 space-y-4">
                        {activeScan.intel && (
                          <div className="bg-emerald-500/10 rounded-xl p-5 border border-emerald-500/20 mb-4">
                            <h3 className="text-[10px] font-bold uppercase tracking-widest text-emerald-500 mb-3 block">Shodan-Style Intelligence</h3>
                            <div className="grid grid-cols-2 gap-4">
                               <div className="flex flex-col">
                                  <span className="text-[9px] text-white/20 uppercase font-mono tracking-tighter">Server Banner</span>
                                  <span className="text-[11px] text-white font-bold truncate">{activeScan.intel.server}</span>
                               </div>
                               <div className="flex flex-col">
                                  <span className="text-[9px] text-white/20 uppercase font-mono tracking-tighter">Active Ports</span>
                                  <span className="text-[11px] text-white font-bold">{activeScan.intel.ports.join(', ')}</span>
                               </div>
                               <div className="flex flex-col pt-2 col-span-2">
                                  <span className="text-[9px] text-white/20 uppercase font-mono tracking-tighter">OS Fingerprint</span>
                                  <span className="text-[11px] text-white/70 italic font-serif">{activeScan.intel.os}</span>
                               </div>
                            </div>
                          </div>
                        )}
                        
                        {activeScan.scrapedData?.discoveredPaths && activeScan.scrapedData.discoveredPaths.length > 0 && (
                          <div className="bg-rose-500/10 rounded-xl p-5 border border-rose-500/20 mb-4">
                            <h3 className="text-[10px] font-bold uppercase tracking-widest text-rose-500 mb-3 block">Accessible Public Paths</h3>
                            <div className="space-y-2">
                               {activeScan.scrapedData.discoveredPaths.map((p, i) => (
                                 <div key={i} className="flex items-center justify-between font-mono text-[10px] group/item">
                                    <span className="text-rose-300 group-hover/item:text-rose-500 transition-colors uppercase tracking-tighter">{p.path}</span>
                                    <Badge className="bg-rose-500/20 text-rose-500 hover:bg-rose-500/20 border-none text-[8px] px-1 py-0">{p.status} FOUND</Badge>
                                 </div>
                               ))}
                            </div>
                          </div>
                        )}

                        {activeScan.scrapedData && (
                          <div className="bg-white/5 rounded-xl p-5 border border-white/10 mb-4">
                            <h3 className="text-[10px] font-bold uppercase tracking-widest text-white/50 mb-3 block">Scraped Origin Data</h3>
                            <div className="space-y-2">
                               <div className="flex flex-col">
                                  <span className="text-[9px] text-white/20 uppercase font-mono tracking-tighter">Page Title</span>
                                  <span className="text-[11px] text-emerald-500 font-bold truncate max-w-full block">{activeScan.scrapedData.title || 'Untitled Archive'}</span>
                               </div>
                               <div className="flex flex-col pt-2">
                                  <span className="text-[9px] text-white/20 uppercase font-mono tracking-tighter">Link Extraction</span>
                                  <span className="text-[11px] text-white/70">{activeScan.scrapedData.linksCount} internal paths mapped</span>
                               </div>
                            </div>
                          </div>
                        )}
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
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {activeView === 'subdomains' && (
            <motion.div 
              key="subdomains"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex-1 flex flex-col gap-8"
            >
              <h2 className="text-2xl font-serif italic text-white flex items-center gap-4">
                Domain Surface Mapping
                <div className="flex gap-2">
                  <Badge variant="outline" className="text-[9px] uppercase border-emerald-500/30 text-emerald-500 font-mono tracking-tighter">
                    {subdomainSource || 'Ready'}
                  </Badge>
                  <Badge variant="outline" className="text-[9px] uppercase border-white/10 text-white/40 font-mono tracking-tighter">
                    Active Recon
                  </Badge>
                </div>
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <Card className="bg-[#0A0A0A] border-white/5 p-6 flex flex-col">
                  <span className="text-[10px] text-white/30 uppercase tracking-widest mb-2 font-bold font-mono">Total Hosts</span>
                  <span className="text-3xl font-mono text-white">{subdomains.length || '---'}</span>
                </Card>
                <Card className="bg-[#0A0A0A] border-white/5 p-6 flex flex-col">
                  <span className="text-[10px] text-white/30 uppercase tracking-widest mb-2 font-bold font-mono">Unique IPs</span>
                  <span className="text-3xl font-mono text-white">{new Set(subdomains.map(s => s.ip)).size || '---'}</span>
                </Card>
              </div>

              <Card className="bg-[#0A0A0A] border-white/5 overflow-hidden flex-1">
                <Table>
                  <TableHeader className="bg-black/40">
                    <TableRow className="border-white/5">
                      <TableHead className="text-[10px] text-white/40 uppercase font-mono">Host FQDN</TableHead>
                      <TableHead className="text-[10px] text-white/40 uppercase font-mono">Status</TableHead>
                      <TableHead className="text-[10px] text-white/40 uppercase font-mono">Resolved IP</TableHead>
                      <TableHead className="text-[10px] text-white/40 uppercase font-mono text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {subdomains.length > 0 ? (
                      subdomains.map((sub, i) => (
                        <TableRow key={i} className="border-white/5 hover:bg-white/[0.02]">
                          <TableCell className="font-mono text-xs text-white/80">{sub.host}</TableCell>
                          <TableCell>
                            <span className="bg-emerald-500/10 text-emerald-500 text-[9px] px-2 py-0.5 rounded font-bold uppercase">{sub.status}</span>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-white/40">{sub.ip}</TableCell>
                          <TableCell className="text-right">
                             <Button variant="ghost" className="h-8 w-8 p-0 hover:text-emerald-500"><ExternalLink className="w-4 h-4" /></Button>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={4} className="h-64 text-center text-white/20 italic font-mono text-xs">
                          No subdomain mapping data available. Run a scan to populate.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </Card>
            </motion.div>
          )}

          {activeView === 'reports' && (
            <motion.div 
              key="reports"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex-1 flex flex-col gap-8"
            >
              <div className="flex justify-between items-end">
                <h2 className="text-2xl font-serif italic text-white underline decoration-white/5 underline-offset-8">Intelligence Vault</h2>
                <span className="text-[10px] text-white/30 font-mono uppercase tracking-[0.2em]">{history.length} Record(s) Archived</span>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {history.length > 0 ? (
                   history.map((record, idx) => (
                    <Card key={record.id} className="bg-[#0A0A0A] border-white/5 hover:border-emerald-500/30 p-6 flex flex-col gap-4 relative group overflow-hidden transition-all duration-500 cursor-pointer" onClick={() => { setActiveScan(record.scan_data); setActiveView('dashboard'); }}>
                      <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                      <div className="flex justify-between items-start">
                         <div className="flex flex-col min-w-0">
                            <span className="text-base font-bold text-white font-mono break-all pr-4 uppercase truncate">{record.target_url.replace(/^https?:\/\//, '')}</span>
                            <span className="text-[9px] text-white/40 font-mono mt-1 uppercase">ARCHIVE_ID: {record.id.toString().padStart(4, '0')} • {new Date(record.scan_date).toLocaleDateString()}</span>
                         </div>
                         <div className="w-8 h-8 rounded bg-white/5 flex items-center justify-center group-hover:bg-emerald-500/10 transition-colors">
                           <FileText className="w-4 h-4 text-white/20 group-hover:text-emerald-500 transition-colors" />
                         </div>
                      </div>
                      <Separator className="bg-white/5" />
                      <div className="flex gap-2">
                        <Badge className="bg-white/5 text-white border-none text-[8px] uppercase px-2">{record.scan_data.findings.length} ISSUES</Badge>
                        <Badge className="bg-emerald-500/10 text-emerald-500 border-none text-[8px] uppercase px-2">{record.scan_data.status} OK</Badge>
                      </div>
                      <p className="text-[10px] text-white/30 leading-relaxed italic line-clamp-2">
                         Technical security audit containing {record.scan_data.techStack.join(', ') || 'undisclosed stack'} fingerprinting and vulnerability analysis.
                      </p>
                    </Card>
                   ))
                ) : (
                   <div className="col-span-full h-96 border border-dashed border-white/10 flex flex-col items-center justify-center opacity-30 mt-12 rounded-xl">
                      <FileText className="w-16 h-16 mb-4" />
                      <p className="font-mono text-xs uppercase tracking-widest">No Intelligence Records Found</p>
                      <Button variant="ghost" onClick={() => setActiveView('dashboard')} className="mt-6 text-[10px] uppercase tracking-widest hover:text-emerald-500">Initiate First Scan</Button>
                   </div>
                )}
              </div>
            </motion.div>
          )}

          {activeView === 'settings' && (
            <motion.div 
              key="settings"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex-1 flex flex-col gap-8"
            >
              <h2 className="text-2xl font-serif italic text-white underline decoration-emerald-500/30 underline-offset-8">System Configuration</h2>
              <div className="max-w-2xl space-y-12">
                <section className="space-y-4">
                   <h3 className="text-[10px] font-bold uppercase tracking-[0.3em] text-emerald-500">API Gateway</h3>
                   <div className="bg-[#0A0A0A] border border-white/5 p-6 rounded-xl space-y-6">
                      <div className="flex flex-col gap-2">
                        <label className="text-[10px] text-white/40 uppercase tracking-widest font-mono">Gemini AI Intelligence Key</label>
                        <div className="flex gap-4">
                          <Input value="••••••••••••••••••••••••" readOnly className="bg-black border-white/10 font-mono text-emerald-500/50" />
                          <Button variant="outline" className="border-white/10 hover:bg-emerald-500 hover:text-black transition-all">Rotated</Button>
                        </div>
                      </div>
                   </div>
                </section>

                <section className="space-y-4">
                   <h3 className="text-[10px] font-bold uppercase tracking-[0.3em] text-emerald-500">Engine Parameters</h3>
                   <div className="bg-[#0A0A0A] border border-white/5 p-6 rounded-xl space-y-4">
                      <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/5 group hover:border-emerald-500/30 transition-all">
                        <div className="flex flex-col gap-1">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest">Aggressive Recursive Scan</span>
                          <span className="text-[9px] text-white/30 italic uppercase font-mono">High depth mapping of all subdirectories</span>
                        </div>
                        <div className="w-10 h-5 bg-emerald-500/20 rounded-full relative p-1 cursor-not-allowed">
                           <div className="w-3 h-3 bg-emerald-500 rounded-full translate-x-5" />
                        </div>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/5 group hover:border-emerald-500/30 transition-all opacity-50">
                        <div className="flex flex-col gap-1">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest">Auto-Exploit Simulation</span>
                          <span className="text-[9px] text-white/30 italic uppercase font-mono">Requires Level 5 Authorization</span>
                        </div>
                        <div className="w-10 h-5 bg-white/10 rounded-full relative p-1 cursor-wait">
                           <div className="w-3 h-3 bg-white/20 rounded-full translate-x-0" />
                        </div>
                      </div>
                   </div>
                </section>
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
