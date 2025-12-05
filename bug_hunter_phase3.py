#!/usr/bin/env python3
"""
BUG HUNTER PRO v3.0 - Complete Enterprise Security Platform
Phase 3: CMS Scanners, E-commerce, Cloud Security, CI/CD & Dashboard
Author: Security Research Team
"""

import asyncio
import aiohttp
import json
import os
import sys
import re
import time
import socket
import ssl
import hashlib
import base64
import random
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import argparse
import threading
import queue
import csv
import yaml
import xml.etree.ElementTree as ET
from pathlib import Path
import dns.resolver
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import uuid
import html
import statistics
from collections import defaultdict
import secrets

# ============================================================================
# ENTERPRISE DASHBOARD & MANAGEMENT
# ============================================================================

class EnterpriseDashboard:
    """Real-time Dashboard for Bug Hunter Pro"""
    
    def __init__(self, engine):
        self.engine = engine
        self.scans = []
        self.teams = {}
        self.assets = {}
        self.vulnerability_trends = {}
        self.real_time_updates = queue.Queue()
        self.port = 8080
        
    async def start_dashboard(self, port: int = 8080):
        """Start web dashboard"""
        self.port = port
        print(f"[+] Starting Enterprise Dashboard on port {port}")
        print(f"[+] Dashboard available at: http://localhost:{port}")
        
        # Generate dashboard files
        self.generate_static_dashboard()
        await self.start_web_server()
        
    def generate_static_dashboard(self):
        """Generate interactive dashboard HTML"""
        dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Hunter Pro - Enterprise Dashboard</title>
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --danger: #dc3545;
            --warning: #ffc107;
            --success: #28a745;
            --info: #17a2b8;
            --dark: #343a40;
            --light: #f8f9fa;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; }
        
        .navbar { background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%); color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.5rem; font-weight: bold; }
        .nav-links a { color: white; margin-left: 1.5rem; text-decoration: none; }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin-bottom: 2rem; }
        
        .card { background: white; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); padding: 1.5rem; }
        .card-header { border-bottom: 1px solid #eee; padding-bottom: 1rem; margin-bottom: 1rem; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }
        .stat { text-align: center; padding: 1rem; background: var(--light); border-radius: 5px; }
        .stat-number { font-size: 2rem; font-weight: bold; color: var(--primary); }
        
        .chart-container { height: 300px; margin-top: 1rem; }
        
        .vulnerability-list { max-height: 400px; overflow-y: auto; }
        .vuln-item { padding: 1rem; border-bottom: 1px solid #eee; }
        .vuln-item.critical { border-left: 4px solid var(--danger); }
        .vuln-item.high { border-left: 4px solid var(--warning); }
        
        .btn { background: var(--primary); color: white; border: none; padding: 0.5rem 1rem; border-radius: 5px; cursor: pointer; }
        .btn:hover { opacity: 0.9; }
        
        .scan-progress { margin-top: 2rem; }
        .progress-bar { height: 10px; background: #eee; border-radius: 5px; overflow: hidden; }
        .progress-fill { height: 100%; background: var(--primary); }
        
        .realtime-updates { margin-top: 2rem; max-height: 300px; overflow-y: auto; border: 1px solid #eee; border-radius: 5px; padding: 1rem; }
        .update-item { padding: 0.5rem; border-bottom: 1px solid #eee; }
    </style>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <nav class="navbar">
        <div class="logo">🐛 Bug Hunter Pro v3.0</div>
        <div class="nav-links">
            <a href="#dashboard">Dashboard</a>
            <a href="#scans">Scans</a>
            <a href="#assets">Assets</a>
            <a href="#team">Team</a>
            <a href="#reports">Reports</a>
        </div>
    </nav>
    
    <div class="container">
        <h1>Enterprise Security Dashboard</h1>
        
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <h3>Security Overview</h3>
                </div>
                <div class="stats-grid">
                    <div class="stat">
                        <div class="stat-number" id="total-assets">0</div>
                        <div>Total Assets</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="active-scans">0</div>
                        <div>Active Scans</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="critical-vulns">0</div>
                        <div>Critical Vulnerabilities</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="vuln-trend">0%</div>
                        <div>30-Day Trend</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>Vulnerability Breakdown</h3>
                </div>
                <div class="chart-container">
                    <canvas id="vulnChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>Recent Critical Findings</h3>
                </div>
                <div class="vulnerability-list" id="critical-list">
                    <!-- Dynamic content -->
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>Quick Actions</h3>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                    <button class="btn" onclick="startNewScan()">🚀 New Scan</button>
                    <button class="btn" onclick="generateReport()">📊 Generate Report</button>
                    <button class="btn" onclick="scheduleScan()">⏰ Schedule Scan</button>
                    <button class="btn" onclick="exportData()">📁 Export Data</button>
                </div>
            </div>
        </div>
        
        <div class="card scan-progress">
            <div class="card-header">
                <h3>Active Scans</h3>
            </div>
            <div id="scan-progress-list">
                <!-- Dynamic content -->
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3>Real-time Updates</h3>
            </div>
            <div class="realtime-updates" id="realtime-updates">
                <!-- Updates will appear here -->
            </div>
        </div>
    </div>
    
    <script>
        // Initialize charts
        const ctx = document.getElementById('vulnChart').getContext('2d');
        const vulnChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [12, 19, 8, 15, 7],
                    backgroundColor: [
                        '#dc3545',
                        '#ffc107',
                        '#fd7e14',
                        '#28a745',
                        '#17a2b8'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
        
        // WebSocket for real-time updates
        const ws = new WebSocket('ws://localhost:8080/ws');
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };
        
        function updateDashboard(data) {
            // Update stats
            document.getElementById('total-assets').textContent = data.total_assets || 0;
            document.getElementById('active-scans').textContent = data.active_scans || 0;
            document.getElementById('critical-vulns').textContent = data.critical_vulns || 0;
            
            // Update chart
            if (data.vuln_stats) {
                vulnChart.data.datasets[0].data = data.vuln_stats;
                vulnChart.update();
            }
            
            // Add real-time update
            if (data.update) {
                const updatesDiv = document.getElementById('realtime-updates');
                const updateItem = document.createElement('div');
                updateItem.className = 'update-item';
                updateItem.innerHTML = `<strong>${new Date().toLocaleTimeString()}</strong>: ${data.update}`;
                updatesDiv.prepend(updateItem);
                
                // Limit to 10 updates
                if (updatesDiv.children.length > 10) {
                    updatesDiv.removeChild(updatesDiv.lastChild);
                }
            }
        }
        
        function startNewScan() {
            const target = prompt('Enter target URL:');
            if (target) {
                fetch('/api/scan/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                });
            }
        }
        
        function generateReport() {
            fetch('/api/report/generate')
                .then(response => response.json())
                .then(data => {
                    alert(`Report generated: ${data.report_url}`);
                });
        }
        
        // Simulate initial data
        setTimeout(() => {
            updateDashboard({
                total_assets: 156,
                active_scans: 3,
                critical_vulns: 12,
                vuln_stats: [12, 19, 8, 15, 7],
                update: "System initialized successfully"
            });
        }, 1000);
    </script>
</body>
</html>
"""
        
        # Save dashboard
        dashboard_path = "bug_hunter_dashboard/dashboard.html"
        os.makedirs(os.path.dirname(dashboard_path), exist_ok=True)
        
        with open(dashboard_path, 'w') as f:
            f.write(dashboard_html)
        
        print(f"[+] Dashboard generated: {dashboard_path}")
        print("[+] Access at: file://" + os.path.abspath(dashboard_path))
    
    async def start_web_server(self):
        """Start a simple web server for the dashboard"""
        import http.server
        import socketserver
        import threading
        
        handler = http.server.SimpleHTTPRequestHandler
        
        def run_server():
            os.chdir("bug_hunter_dashboard")
            with socketserver.TCPServer(("", self.port), handler) as httpd:
                print(f"[+] Dashboard server running at http://localhost:{self.port}")
                httpd.serve_forever()
        
        # Start server in background thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
    
    def add_scan(self, scan_data):
        """Add scan data to dashboard"""
        self.scans.append(scan_data)
        self.real_time_updates.put(f"New scan started: {scan_data.get('target', 'Unknown')}")
    
    def add_finding(self, finding):
        """Add vulnerability finding to dashboard"""
        severity = finding.get('severity', 'info')
        if severity in ['critical', 'high']:
            self.real_time_updates.put(f"Critical finding: {finding.get('title', 'Unknown')}")
    
    def get_stats(self):
        """Get dashboard statistics"""
        return {
            'total_assets': len(self.assets),
            'active_scans': len([s for s in self.scans if s.get('status') == 'running']),
            'critical_vulns': len([s for s in self.scans if any(f.get('severity') == 'critical' for f in s.get('findings', []))])
        }

# ============================================================================
# CMS SCANNERS
# ============================================================================

class CMSScanner:
    """Base class for CMS scanners"""
    
    def __init__(self, engine):
        self.engine = engine
        self.cms_type = "generic"
        
    async def scan(self, url: str) -> List[Dict[str, Any]]:
        """Scan for CMS-specific vulnerabilities"""
        findings = []
        
        # Detect CMS version
        version = await self.detect_version(url)
        if version:
            findings.append({
                "title": f"{self.cms_type.upper()} Detected",
                "description": f"{self.cms_type.upper()} version {version} detected",
                "severity": "info",
                "url": url,
                "evidence": f"Version: {version}",
                "confidence": "high"
            })
            
            # Check for known vulnerabilities
            vuln_findings = await self.check_known_vulnerabilities(url, version)
            findings.extend(vuln_findings)
        
        # Scan for common files
        file_findings = await self.scan_files(url)
        findings.extend(file_findings)
        
        # Test for common vulnerabilities
        common_findings = await self.test_common_vulnerabilities(url)
        findings.extend(common_findings)
        
        return findings
    
    async def detect_version(self, url: str) -> Optional[str]:
        """Detect CMS version - to be overridden by subclasses"""
        return None
    
    async def check_known_vulnerabilities(self, url: str, version: str) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities - to be overridden"""
        return []
    
    async def scan_files(self, url: str) -> List[Dict[str, Any]]:
        """Scan for CMS-specific files"""
        return []
    
    async def test_common_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Test for common CMS vulnerabilities"""
        return []

class WordPressScanner(CMSScanner):
    """WordPress Security Scanner"""
    
    def __init__(self, engine):
        super().__init__(engine)
        self.cms_type = "wordpress"
        
        # WordPress-specific files and paths
        self.wp_files = [
            "/wp-admin/", "/wp-includes/", "/wp-content/",
            "/wp-login.php", "/xmlrpc.php", "/wp-config.php",
            "/readme.html", "/license.txt"
        ]
        
        # Common WordPress vulnerabilities
        self.common_vulns = {
            "xmlrpc": {
                "path": "/xmlrpc.php",
                "tests": [
                    ("POST", "pingback.ping", "XML-RPC pingback enabled"),
                    ("POST", "system.listMethods", "XML-RPC methods exposed")
                ]
            },
            "user_enum": {
                "path": "/?author=1",
                "tests": [("GET", "", "User enumeration via author parameter")]
            },
            "wp_config": {
                "path": "/wp-config.php",
                "tests": [("GET", "", "wp-config.php accessible")]
            }
        }
    
    async def detect_version(self, url: str) -> Optional[str]:
        """Detect WordPress version"""
        try:
            # Check readme.html
            readme_url = f"{url.rstrip('/')}/readme.html"
            async with self.engine.session.get(readme_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    version_match = re.search(r'Version\s+([\d.]+)', content)
                    if version_match:
                        return version_match.group(1)
            
            # Check generator meta tag
            async with self.engine.session.get(url, timeout=5) as response:
                content = await response.text()
                meta_match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', content)
                if meta_match:
                    return meta_match.group(1)
                
                # Check in stylesheet links
                version_match = re.search(r'wp-includes/css/dist/block-library/style.min.css\?ver=([\d.]+)', content)
                if version_match:
                    return version_match.group(1)
        
        except Exception as e:
            pass
        
        return None
    
    async def scan_files(self, url: str) -> List[Dict[str, Any]]:
        """Scan for WordPress-specific files"""
        findings = []
        
        for wp_file in self.wp_files:
            file_url = f"{url.rstrip('/')}{wp_file}"
            
            try:
                async with self.engine.session.head(file_url, timeout=5) as response:
                    if response.status == 200:
                        if wp_file == "/wp-config.php":
                            findings.append({
                                "title": "WordPress Configuration File Exposed",
                                "description": "wp-config.php is publicly accessible",
                                "severity": "critical",
                                "url": file_url,
                                "evidence": "wp-config.php file accessible",
                                "confidence": "high"
                            })
                        elif wp_file == "/readme.html":
                            findings.append({
                                "title": "WordPress Readme File Exposed",
                                "description": "readme.html reveals WordPress version",
                                "severity": "low",
                                "url": file_url,
                                "evidence": "readme.html file accessible",
                                "confidence": "high"
                            })
                        elif wp_file == "/xmlrpc.php":
                            findings.append({
                                "title": "WordPress XML-RPC Enabled",
                                "description": "XML-RPC interface is enabled",
                                "severity": "medium",
                                "url": file_url,
                                "evidence": "xmlrpc.php file accessible",
                                "confidence": "high"
                            })
            
            except Exception as e:
                continue
        
        return findings
    
    async def test_common_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Test for common WordPress vulnerabilities"""
        findings = []
        
        # Test XML-RPC vulnerabilities
        xmlrpc_url = f"{url.rstrip('/')}/xmlrpc.php"
        
        try:
            # Test pingback
            pingback_payload = """<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://evil.com</string></value></param>
<param><value><string>http://target.com</string></value></param>
</params>
</methodCall>"""
            
            async with self.engine.session.post(
                xmlrpc_url,
                data=pingback_payload,
                headers={"Content-Type": "text/xml"},
                timeout=10
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    if "faultCode" not in content:
                        findings.append({
                            "title": "WordPress XML-RPC Pingback Enabled",
                            "description": "XML-RPC pingback can be used for DDoS",
                            "severity": "medium",
                            "url": xmlrpc_url,
                            "evidence": "pingback.ping method accepted",
                            "confidence": "high"
                        })
        
        except Exception as e:
            pass
        
        # Test user enumeration
        for user_id in range(1, 10):
            enum_url = f"{url.rstrip('/')}/?author={user_id}"
            
            try:
                async with self.engine.session.get(enum_url, allow_redirects=False, timeout=5) as response:
                    if response.status in [301, 302]:
                        location = response.headers.get("location", "")
                        if "/author/" in location:
                            username = location.split("/author/")[-1].rstrip("/")
                            findings.append({
                                "title": "WordPress User Enumeration",
                                "description": "Usernames can be enumerated via author parameter",
                                "severity": "low",
                                "url": enum_url,
                                "evidence": f"Username found: {username}",
                                "confidence": "high"
                            })
                            break
            
            except Exception as e:
                continue
        
        # Test login page brute force protection
        login_url = f"{url.rstrip('/')}/wp-login.php"
        
        try:
            # Send multiple login attempts
            for i in range(5):
                form_data = {
                    "log": f"admin{i}",
                    "pwd": "wrongpassword",
                    "wp-submit": "Log In"
                }
                
                async with self.engine.session.post(login_url, data=form_data, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for lockout message
                        if "locked out" in content.lower() or "too many" in content.lower():
                            findings.append({
                                "title": "WordPress Login Brute Force Protection",
                                "description": "Login page has brute force protection",
                                "severity": "info",
                                "url": login_url,
                                "evidence": "Login attempts are rate limited",
                                "confidence": "medium"
                            })
                            break
            
            # If no lockout detected
            if len([f for f in findings if "Brute Force Protection" in f.get("title", "")]) == 0:
                findings.append({
                    "title": "WordPress Login Brute Force Vulnerability",
                    "description": "Login page may be vulnerable to brute force attacks",
                    "severity": "medium",
                    "url": login_url,
                    "evidence": "No brute force protection detected after 5 attempts",
                    "confidence": "medium"
                })
        
        except Exception as e:
            pass
        
        return findings

class JoomlaScanner(CMSScanner):
    """Joomla Security Scanner"""
    
    def __init__(self, engine):
        super().__init__(engine)
        self.cms_type = "joomla"
        
        self.joomla_files = [
            "/administrator/", "/components/", "/modules/",
            "/templates/", "/plugins/", "/configuration.php",
            "/README.txt", "/htaccess.txt"
        ]
    
    async def detect_version(self, url: str) -> Optional[str]:
        """Detect Joomla version"""
        try:
            # Check meta generator tag
            async with self.engine.session.get(url, timeout=5) as response:
                content = await response.text()
                
                # Meta generator tag
                meta_match = re.search(r'<meta name="generator" content="Joomla! ([\d.]+)', content)
                if meta_match:
                    return meta_match.group(1)
                
                # Check in JavaScript/CSS files
                version_match = re.search(r'/media/system/js/core.js\?([\d.]+)', content)
                if version_match:
                    return version_match.group(1)
        
        except Exception as e:
            pass
        
        return None
    
    async def scan_files(self, url: str) -> List[Dict[str, Any]]:
        """Scan for Joomla-specific files"""
        findings = []
        
        for joomla_file in self.joomla_files:
            file_url = f"{url.rstrip('/')}{joomla_file}"
            
            try:
                async with self.engine.session.head(file_url, timeout=5) as response:
                    if response.status == 200:
                        if joomla_file == "/configuration.php":
                            findings.append({
                                "title": "Joomla Configuration File Exposed",
                                "description": "configuration.php is publicly accessible",
                                "severity": "critical",
                                "url": file_url,
                                "evidence": "configuration.php file accessible",
                                "confidence": "high"
                            })
                        elif joomla_file == "/administrator/":
                            findings.append({
                                "title": "Joomla Administrator Panel Accessible",
                                "description": "Administrator login panel is publicly accessible",
                                "severity": "medium",
                                "url": file_url,
                                "evidence": "Joomla admin panel accessible",
                                "confidence": "high"
                            })
            
            except Exception as e:
                continue
        
        return findings
    
    async def test_common_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Test for common Joomla vulnerabilities"""
        findings = []
        
        # Test for Joomla user enumeration
        try:
            user_enum_url = f"{url.rstrip('/')}/index.php?option=com_users&view=users"
            async with self.engine.session.get(user_enum_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    if "com_users" in content and "view=users" in content:
                        findings.append({
                            "title": "Joomla User Enumeration",
                            "description": "User information may be enumerable",
                            "severity": "low",
                            "url": user_enum_url,
                            "evidence": "User component accessible without authentication",
                            "confidence": "medium"
                        })
        except Exception as e:
            pass
        
        return findings

class DrupalScanner(CMSScanner):
    """Drupal Security Scanner"""
    
    def __init__(self, engine):
        super().__init__(engine)
        self.cms_type = "drupal"
        
        self.drupal_files = [
            "/sites/default/", "/modules/", "/themes/",
            "/profiles/", "/CHANGELOG.txt", "/README.txt",
            "/sites/default/settings.php"
        ]
    
    async def detect_version(self, url: str) -> Optional[str]:
        """Detect Drupal version"""
        try:
            # Check CHANGELOG.txt
            changelog_url = f"{url.rstrip('/')}/CHANGELOG.txt"
            async with self.engine.session.get(changelog_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    version_match = re.search(r'Drupal ([\d.]+)', content[:500])
                    if version_match:
                        return version_match.group(1)
            
            # Check meta generator tag
            async with self.engine.session.get(url, timeout=5) as response:
                content = await response.text()
                meta_match = re.search(r'<meta name="Generator" content="Drupal ([\d.]+)', content)
                if meta_match:
                    return meta_match.group(1)
        
        except Exception as e:
            pass
        
        return None
    
    async def scan_files(self, url: str) -> List[Dict[str, Any]]:
        """Scan for Drupal-specific files"""
        findings = []
        
        for drupal_file in self.drupal_files:
            file_url = f"{url.rstrip('/')}{drupal_file}"
            
            try:
                async with self.engine.session.head(file_url, timeout=5) as response:
                    if response.status == 200:
                        if drupal_file == "/sites/default/settings.php":
                            findings.append({
                                "title": "Drupal Settings File Exposed",
                                "description": "settings.php is publicly accessible",
                                "severity": "critical",
                                "url": file_url,
                                "evidence": "settings.php file accessible",
                                "confidence": "high"
                            })
                        elif drupal_file == "/CHANGELOG.txt":
                            findings.append({
                                "title": "Drupal Changelog Exposed",
                                "description": "CHANGELOG.txt reveals Drupal version",
                                "severity": "low",
                                "url": file_url,
                                "evidence": "CHANGELOG.txt file accessible",
                                "confidence": "high"
                            })
            
            except Exception as e:
                continue
        
        return findings

# ============================================================================
# E-COMMERCE SCANNERS
# ============================================================================

class EcommerceScanner:
    """Base class for e-commerce scanners"""
    
    def __init__(self, engine):
        self.engine = engine
        self.platform = "generic"
        
    async def scan(self, url: str) -> List[Dict[str, Any]]:
        """Scan e-commerce platform for vulnerabilities"""
        findings = []
        
        # Detect platform
        platform_info = await self.detect_platform(url)
        if platform_info:
            findings.append({
                "title": f"{self.platform.upper()} E-commerce Platform",
                "description": f"{self.platform.upper()} e-commerce platform detected",
                "severity": "info",
                "url": url,
                "evidence": platform_info,
                "confidence": "high"
            })
        
        # Test checkout process
        checkout_findings = await self.test_checkout(url)
        findings.extend(checkout_findings)
        
        # Test payment processing
        payment_findings = await self.test_payment(url)
        findings.extend(payment_findings)
        
        # Test cart manipulation
        cart_findings = await self.test_cart(url)
        findings.extend(cart_findings)
        
        return findings
    
    async def detect_platform(self, url: str) -> Optional[str]:
        """Detect e-commerce platform"""
        return None
    
    async def test_checkout(self, url: str) -> List[Dict[str, Any]]:
        """Test checkout process vulnerabilities"""
        return []
    
    async def test_payment(self, url: str) -> List[Dict[str, Any]]:
        """Test payment processing vulnerabilities"""
        return []
    
    async def test_cart(self, url: str) -> List[Dict[str, Any]]:
        """Test shopping cart vulnerabilities"""
        return []

class MagentoScanner(EcommerceScanner):
    """Magento Security Scanner"""
    
    def __init__(self, engine):
        super().__init__(engine)
        self.platform = "magento"
        
    async def detect_platform(self, url: str) -> Optional[str]:
        """Detect Magento"""
        try:
            async with self.engine.session.get(url, timeout=5) as response:
                content = await response.text()
                
                # Check for Magento indicators
                if "Magento" in content or "mage/" in content:
                    # Try to get version from HTML
                    version_match = re.search(r'Magento/([\d.]+)', content)
                    if version_match:
                        return f"Magento {version_match.group(1)}"
                    return "Magento detected"
        
        except Exception as e:
            pass
        
        return None
    
    async def test_checkout(self, url: str) -> List[Dict[str, Any]]:
        """Test Magento checkout vulnerabilities"""
        findings = []
        
        # Test for Magento admin panel
        try:
            admin_url = f"{url.rstrip('/')}/admin"
            async with self.engine.session.get(admin_url, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "title": "Magento Admin Panel Accessible",
                        "description": "Magento admin panel is publicly accessible",
                        "severity": "medium",
                        "url": admin_url,
                        "evidence": "Admin login page accessible",
                        "confidence": "high"
                    })
        except Exception as e:
            pass
        
        return findings

class ShopifyScanner(EcommerceScanner):
    """Shopify Security Scanner"""
    
    def __init__(self, engine):
        super().__init__(engine)
        self.platform = "shopify"
        
    async def detect_platform(self, url: str) -> Optional[str]:
        """Detect Shopify"""
        try:
            async with self.engine.session.get(url, timeout=5) as response:
                headers = response.headers
                content = await response.text()
                
                # Shopify headers
                if "X-ShopId" in headers or "X-Shopify-Shop-Id" in headers:
                    return "Shopify platform"
                
                # Check content
                if "shopify" in content.lower():
                    return "Shopify detected"
        
        except Exception as e:
            pass
        
        return None

class WooCommerceScanner(EcommerceScanner):
    """WooCommerce Security Scanner (extends WordPress scanner)"""
    
    def __init__(self, engine):
        super().__init__(engine)
        self.platform = "woocommerce"
        self.wordpress_scanner = WordPressScanner(engine)
        
    async def detect_platform(self, url: str) -> Optional[str]:
        """Detect WooCommerce"""
        try:
            async with self.engine.session.get(url, timeout=5) as response:
                content = await response.text()
                
                # Check for WooCommerce
                if "WooCommerce" in content or "woocommerce" in content.lower():
                    return "WooCommerce detected"
                
                # Check for WooCommerce API
                api_url = f"{url.rstrip('/')}/wp-json/wc/v3/"
                async with self.engine.session.head(api_url, timeout=5) as api_response:
                    if api_response.status in [200, 401, 403]:
                        return "WooCommerce API detected"
        
        except Exception as e:
            pass
        
        return None
    
    async def test_checkout(self, url: str) -> List[Dict[str, Any]]:
        """Test WooCommerce checkout vulnerabilities"""
        findings = []
        
        # Test for WooCommerce API exposure
        try:
            api_url = f"{url.rstrip('/')}/wp-json/wc/v3/products"
            async with self.engine.session.get(api_url, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "title": "WooCommerce API Exposed",
                        "description": "WooCommerce REST API is publicly accessible",
                        "severity": "medium",
                        "url": api_url,
                        "evidence": "Products API endpoint accessible without authentication",
                        "confidence": "high"
                    })
        except Exception as e:
            pass
        
        return findings

# ============================================================================
# FRAMEWORK-SPECIFIC SCANNERS
# ============================================================================

class FrameworkScanner:
    """Framework-specific vulnerability scanner"""
    
    def __init__(self, engine):
        self.engine = engine
        
    async def scan_framework(self, url: str, framework: str) -> List[Dict[str, Any]]:
        """Scan for framework-specific vulnerabilities"""
        findings = []
        
        if framework.lower() == "laravel":
            laravel_findings = await self.scan_laravel(url)
            findings.extend(laravel_findings)
        
        elif framework.lower() == "django":
            django_findings = await self.scan_django(url)
            findings.extend(django_findings)
        
        elif framework.lower() == "rails":
            rails_findings = await self.scan_rails(url)
            findings.extend(rails_findings)
        
        elif framework.lower() == "spring":
            spring_findings = await self.scan_spring(url)
            findings.extend(spring_findings)
        
        return findings
    
    async def scan_laravel(self, url: str) -> List[Dict[str, Any]]:
        """Scan Laravel applications"""
        findings = []
        
        # Check for Laravel debug mode
        try:
            debug_url = f"{url.rstrip('/')}/_ignition/execute-solution"
            async with self.engine.session.post(
                debug_url,
                json={"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution"},
                timeout=5
            ) as response:
                if response.status == 200:
                    findings.append({
                        "title": "Laravel Debug Mode Enabled",
                        "description": "Laravel debug/ignition mode is enabled in production",
                        "severity": "critical",
                        "url": debug_url,
                        "evidence": "Ignition debug endpoint accessible",
                        "confidence": "high"
                    })
        except:
            pass
        
        # Check for Laravel storage directory exposure
        try:
            storage_url = f"{url.rstrip('/')}/storage/logs/laravel.log"
            async with self.engine.session.get(storage_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    if "Stack trace" in content or "Exception" in content:
                        findings.append({
                            "title": "Laravel Log File Exposure",
                            "description": "Laravel log files are publicly accessible",
                            "severity": "high",
                            "url": storage_url,
                            "evidence": "Log file containing stack traces",
                            "confidence": "high"
                        })
        except:
            pass
        
        return findings
    
    async def scan_django(self, url: str) -> List[Dict[str, Any]]:
        """Scan Django applications"""
        findings = []
        
        # Check for Django debug mode
        try:
            debug_url = f"{url.rstrip('/')}/__debug__/"
            async with self.engine.session.get(debug_url, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "title": "Django Debug Mode Enabled",
                        "description": "Django debug mode is enabled in production",
                        "severity": "critical",
                        "url": debug_url,
                        "evidence": "Django debug toolbar accessible",
                        "confidence": "high"
                    })
        except:
            pass
        
        # Check for Django admin panel
        try:
            admin_url = f"{url.rstrip('/')}/admin/"
            async with self.engine.session.get(admin_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    if "Django administration" in content:
                        findings.append({
                            "title": "Django Admin Panel Accessible",
                            "description": "Django admin panel is publicly accessible",
                            "severity": "medium",
                            "url": admin_url,
                            "evidence": "Django admin login page",
                            "confidence": "high"
                        })
        except:
            pass
        
        return findings
    
    async def scan_rails(self, url: str) -> List[Dict[str, Any]]:
        """Scan Ruby on Rails applications"""
        findings = []
        
        # Check for Rails debug information
        try:
            # Common Rails paths
            rails_paths = [
                "/rails/info/properties",
                "/rails/info/routes",
                "/rails/mailers"
            ]
            
            for path in rails_paths:
                rails_url = f"{url.rstrip('/')}{path}"
                async with self.engine.session.get(rails_url, timeout=5) as response:
                    if response.status == 200:
                        findings.append({
                            "title": "Rails Development Information Exposure",
                            "description": "Rails development/debug endpoints accessible",
                            "severity": "high",
                            "url": rails_url,
                            "evidence": "Rails debug information exposed",
                            "confidence": "high"
                        })
                        break
        except:
            pass
        
        return findings
    
    async def scan_spring(self, url: str) -> List[Dict[str, Any]]:
        """Scan Spring Boot applications"""
        findings = []
        
        # Spring Boot Actuator endpoints
        actuator_endpoints = [
            "/actuator", "/actuator/health", "/actuator/info",
            "/actuator/env", "/actuator/configprops",
            "/actuator/beans", "/actuator/mappings",
            "/actuator/httptrace", "/actuator/logfile"
        ]
        
        for endpoint in actuator_endpoints:
            try:
                actuator_url = f"{url.rstrip('/')}{endpoint}"
                async with self.engine.session.get(actuator_url, timeout=5) as response:
                    if response.status == 200:
                        findings.append({
                            "title": "Spring Boot Actuator Exposed",
                            "description": f"Spring Boot actuator endpoint {endpoint} is publicly accessible",
                            "severity": "medium" if endpoint == "/actuator/health" else "high",
                            "url": actuator_url,
                            "evidence": "Spring Boot actuator endpoint accessible",
                            "confidence": "high"
                        })
                        
                        # Check for sensitive information
                        if endpoint in ["/actuator/env", "/actuator/configprops"]:
                            content = await response.text()
                            if any(sensitive in content.lower() for sensitive in 
                                  ["password", "secret", "key", "token"]):
                                findings.append({
                                    "title": "Spring Boot Sensitive Information Exposure",
                                    "description": f"Sensitive information in actuator endpoint {endpoint}",
                                    "severity": "critical",
                                    "url": actuator_url,
                                    "evidence": "Sensitive data in actuator response",
                                    "confidence": "high"
                                })
            except:
                continue
        
        return findings

# ============================================================================
# CLOUD SECURITY SCANNER
# ============================================================================

class CloudSecurityScanner:
    """Cloud Infrastructure Security Scanner"""
    
    def __init__(self, engine):
        self.engine = engine
        
    async def scan_cloud(self, domain: str) -> List[Dict[str, Any]]:
        """Scan for cloud security misconfigurations"""
        findings = []
        
        print(f"  [+] Scanning cloud infrastructure for: {domain}")
        
        # Detect cloud provider
        cloud_provider = await self.detect_cloud_provider(domain)
        
        if cloud_provider:
            print(f"    [+] Detected cloud provider: {cloud_provider}")
            
            if cloud_provider == "aws":
                aws_findings = await self.scan_aws(domain)
                findings.extend(aws_findings)
            
            elif cloud_provider == "azure":
                azure_findings = await self.scan_azure(domain)
                findings.extend(azure_findings)
            
            elif cloud_provider == "gcp":
                gcp_findings = await self.scan_gcp(domain)
                findings.extend(gcp_findings)
        
        # Check for common cloud misconfigurations
        common_findings = await self.scan_common_cloud(domain)
        findings.extend(common_findings)
        
        return findings
    
    async def detect_cloud_provider(self, domain: str) -> Optional[str]:
        """Detect cloud service provider"""
        try:
            # Check DNS records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                
                for answer in answers:
                    cname = str(answer.target).lower()
                    
                    if any(aws_indicator in cname for aws_indicator in 
                          [".amazonaws.com", ".cloudfront.net", ".s3."]):
                        return "aws"
                    
                    elif any(azure_indicator in cname for azure_indicator in 
                            [".azure.com", ".azurewebsites.net", ".cloudapp.net"]):
                        return "azure"
                    
                    elif any(gcp_indicator in cname for gcp_indicator in 
                            [".google.com", ".googleapis.com", ".appspot.com"]):
                        return "gcp"
            except:
                pass
            
            # Check A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    # Check if IP belongs to cloud providers
                    # AWS: 52.0.0.0/10, 35.180.0.0/16, etc.
                    # Azure: 13.64.0.0/11, 40.74.0.0/15, etc.
                    # GCP: 8.34.208.0/20, 23.236.48.0/20, etc.
                    # This would require IP range databases
                    pass
            except:
                pass
            
            # Check for provider-specific headers
            try:
                async with self.engine.session.get(f"http://{domain}", timeout=5) as response:
                    headers = response.headers
                    
                    if "server" in headers:
                        server = headers["server"].lower()
                        if "ec2" in server or "cloudfront" in server:
                            return "aws"
                        elif "azure" in server:
                            return "azure"
                        elif "google" in server or "gws" in server:
                            return "gcp"
            except:
                pass
            
        except Exception as e:
            pass
        
        return None
    
    async def scan_aws(self, domain: str) -> List[Dict[str, Any]]:
        """Scan AWS-specific configurations"""
        findings = []
        
        # Check for S3 bucket misconfigurations
        try:
            # Test for S3 bucket access
            s3_url = f"http://{domain}.s3.amazonaws.com"
            async with self.engine.session.get(s3_url, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "title": "Public S3 Bucket Detected",
                        "description": "AWS S3 bucket is publicly accessible",
                        "severity": "high",
                        "url": s3_url,
                        "evidence": "S3 bucket accessible without authentication",
                        "confidence": "medium"
                    })
        except Exception as e:
            pass
        
        # Check for CloudFront misconfigurations
        try:
            cf_url = f"http://{domain}"
            async with self.engine.session.get(cf_url, timeout=5) as response:
                headers = response.headers
                if "server" in headers and "CloudFront" in headers["server"]:
                    # Check for security headers
                    if "x-frame-options" not in headers:
                        findings.append({
                            "title": "CloudFront Missing Security Headers",
                            "description": "CloudFront distribution missing security headers",
                            "severity": "medium",
                            "url": cf_url,
                            "evidence": "Missing X-Frame-Options header",
                            "confidence": "high"
                        })
        except Exception as e:
            pass
        
        return findings
    
    async def scan_azure(self, domain: str) -> List[Dict[str, Any]]:
        """Scan Azure-specific configurations"""
        findings = []
        
        # Check for Azure Blob Storage exposure
        try:
            blob_url = f"http://{domain}.blob.core.windows.net"
            async with self.engine.session.get(blob_url, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "title": "Public Azure Blob Storage",
                        "description": "Azure Blob Storage container is publicly accessible",
                        "severity": "high",
                        "url": blob_url,
                        "evidence": "Blob storage accessible without authentication",
                        "confidence": "medium"
                    })
        except Exception as e:
            pass
        
        return findings
    
    async def scan_gcp(self, domain: str) -> List[Dict[str, Any]]:
        """Scan GCP-specific configurations"""
        findings = []
        
        # Check for Google Cloud Storage exposure
        try:
            gcs_url = f"http://storage.googleapis.com/{domain}"
            async with self.engine.session.get(gcs_url, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "title": "Public Google Cloud Storage Bucket",
                        "description": "GCS bucket is publicly accessible",
                        "severity": "high",
                        "url": gcs_url,
                        "evidence": "GCS bucket accessible without authentication",
                        "confidence": "medium"
                    })
        except Exception as e:
            pass
        
        return findings
    
    async def scan_common_cloud(self, domain: str) -> List[Dict[str, Any]]:
        """Scan for common cloud misconfigurations"""
        findings = []
        
        # Check for exposed cloud metadata endpoints
        metadata_endpoints = [
            ("AWS", "http://169.254.169.254/latest/meta-data/"),
            ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("GCP", "http://metadata.google.internal/computeMetadata/v1/")
        ]
        
        for provider, endpoint in metadata_endpoints:
            try:
                async with self.engine.session.get(
                    endpoint,
                    headers={"Metadata": "true"} if provider in ["Azure", "GCP"] else {},
                    timeout=3
                ) as response:
                    if response.status == 200:
                        findings.append({
                            "title": f"Cloud Metadata Endpoint Exposed",
                            "description": f"{provider} metadata endpoint accessible from domain",
                            "severity": "critical",
                            "url": endpoint,
                            "evidence": f"{provider} metadata endpoint accessible",
                            "confidence": "high"
                        })
            except Exception as e:
                continue
        
        # Check for database exposure
        db_ports = [
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (27017, "MongoDB"),
            (1433, "MSSQL"),
            (6379, "Redis"),
            (5984, "CouchDB")
        ]
        
        try:
            for port, db_type in db_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                
                if result == 0:
                    findings.append({
                        "title": f"Exposed Database: {db_type}",
                        "description": f"{db_type} database is publicly accessible on port {port}",
                        "severity": "critical",
                        "url": f"{domain}:{port}",
                        "evidence": f"Port {port} open and accessible",
                        "confidence": "high"
                    })
        except Exception as e:
            pass
        
        return findings

# ============================================================================
# CI/CD SECURITY SCANNER
# ============================================================================

class CICDScanner:
    """CI/CD Pipeline Security Scanner"""
    
    def __init__(self, engine):
        self.engine = engine
        
    async def scan_cicd(self, url: str) -> List[Dict[str, Any]]:
        """Scan for CI/CD pipeline vulnerabilities"""
        findings = []
        
        print(f"  [+] Scanning CI/CD configuration for: {url}")
        
        # Check for common CI/CD files
        cicd_files = [
            "/.github/workflows/",
            "/.gitlab-ci.yml",
            "/.circleci/config.yml",
            "/.travis.yml",
            "/Jenkinsfile",
            "/azure-pipelines.yml",
            "/bitbucket-pipelines.yml"
        ]
        
        for cicd_file in cicd_files:
            file_url = f"{url.rstrip('/')}{cicd_file}"
            
            try:
                async with self.engine.session.head(file_url, timeout=5) as response:
                    if response.status == 200:
                        findings.append({
                            "title": "CI/CD Configuration File Exposed",
                            "description": f"CI/CD configuration file found: {cicd_file}",
                            "severity": "medium",
                            "url": file_url,
                            "evidence": f"{cicd_file} publicly accessible",
                            "confidence": "high"
                        })
                        
                        # Try to download and analyze the file
                        if cicd_file.endswith('.yml') or cicd_file.endswith('.yaml'):
                            async with self.engine.session.get(file_url, timeout=5) as file_response:
                                if file_response.status == 200:
                                    content = await file_response.text()
                                    file_findings = await self.analyze_cicd_file(content, cicd_file)
                                    findings.extend(file_findings)
            except Exception as e:
                continue
        
        # Check for exposed CI/CD tools
        cicd_tools = [
            ("/jenkins/", "Jenkins"),
            ("/gitlab/", "GitLab"),
            ("/teamcity/", "TeamCity"),
            ("/bamboo/", "Bamboo"),
            ("/drone/", "Drone"),
            ("/argo/", "ArgoCD")
        ]
        
        for path, tool in cicd_tools:
            tool_url = f"{url.rstrip('/')}{path}"
            
            try:
                async with self.engine.session.head(tool_url, timeout=5) as response:
                    if response.status == 200:
                        findings.append({
                            "title": f"Exposed CI/CD Tool: {tool}",
                            "description": f"{tool} CI/CD tool is publicly accessible",
                            "severity": "high",
                            "url": tool_url,
                            "evidence": f"{tool} interface accessible",
                            "confidence": "high"
                        })
            except Exception as e:
                continue
        
        return findings
    
    async def analyze_cicd_file(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """Analyze CI/CD configuration file for vulnerabilities"""
        findings = []
        
        try:
            # Check for hardcoded secrets
            secret_patterns = [
                (r'(?i)password\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "Hardcoded password"),
                (r'(?i)secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "Hardcoded secret"),
                (r'(?i)token\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "Hardcoded token"),
                (r'(?i)key\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "Hardcoded key"),
                (r'(?i)api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "Hardcoded API key"),
                (r'sk_live_[a-zA-Z0-9]{24}', "Stripe secret key"),
                (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
                (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "AWS secret key")
            ]
            
            for pattern, description in secret_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    if len(match) > 4:  # Filter out very short matches
                        findings.append({
                            "title": f"Hardcoded Secret in CI/CD Config",
                            "description": f"{description} found in {filename}",
                            "severity": "critical",
                            "url": filename,
                            "evidence": f"Secret pattern found: {match[:20]}...",
                            "confidence": "medium"
                        })
            
            # Check for insecure commands
            insecure_patterns = [
                (r'curl.*(http://|ftp://)', "Insecure protocol usage"),
                (r'wget.*(http://|ftp://)', "Insecure protocol usage"),
                (r'(?i)eval\s*\(', "Eval command usage"),
                (r'(?i)rm\s+-rf\s+/', "Dangerous rm command"),
                (r'(?i)chmod\s+777', "Insecure permissions")
            ]
            
            for pattern, description in insecure_patterns:
                if re.search(pattern, content):
                    findings.append({
                        "title": f"Insecure Command in CI/CD Config",
                        "description": f"{description} found in {filename}",
                        "severity": "high",
                        "url": filename,
                        "evidence": f"Insecure pattern: {pattern}",
                        "confidence": "medium"
                    })
            
            # Check for shell injection vulnerabilities
            if re.search(r'\$[{(].*[)}]', content):
                findings.append({
                    "title": "Potential Shell Injection in CI/CD Config",
                    "description": "Variable expansion may lead to shell injection",
                    "severity": "medium",
                    "url": filename,
                    "evidence": "Shell variable expansion detected",
                    "confidence": "low"
                })
        
        except Exception as e:
            pass
        
        return findings

# ============================================================================
# MAIN ENGINE
# ============================================================================

class BugHunterEngine:
    """Main Bug Hunter Pro Engine"""
    
    def __init__(self):
        self.session = None
        self.dashboard = None
        self.cms_scanners = {}
        self.ecommerce_scanners = {}
        self.framework_scanner = None
        self.cloud_scanner = None
        self.cicd_scanner = None
        self.findings = []
        self.scan_history = []
        
    async def initialize(self):
        """Initialize the engine"""
        print("[+] Initializing Bug Hunter Pro v3.0")
        
        # Create aiohttp session
        self.session = aiohttp.ClientSession()
        
        # Initialize dashboard
        self.dashboard = EnterpriseDashboard(self)
        
        # Initialize scanners
        self.cms_scanners = {
            "wordpress": WordPressScanner(self),
            "joomla": JoomlaScanner(self),
            "drupal": DrupalScanner(self)
        }
        
        self.ecommerce_scanners = {
            "magento": MagentoScanner(self),
            "shopify": ShopifyScanner(self),
            "woocommerce": WooCommerceScanner(self)
        }
        
        self.framework_scanner = FrameworkScanner(self)
        self.cloud_scanner = CloudSecurityScanner(self)
        self.cicd_scanner = CICDScanner(self)
        
        print("[+] Engine initialized successfully")
    
    async def scan_target(self, target: str, scan_types: List[str] = None) -> Dict[str, Any]:
        """Scan a target for vulnerabilities"""
        
        if scan_types is None:
            scan_types = ["cms", "ecommerce", "framework", "cloud", "cicd"]
        
        print(f"[+] Starting scan for: {target}")
        
        scan_result = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scan_types": scan_types,
            "findings": [],
            "status": "running"
        }
        
        # Add to dashboard
        if self.dashboard:
            self.dashboard.add_scan(scan_result)
        
        all_findings = []
        
        # CMS Scan
        if "cms" in scan_types:
            print(f"  [+] Running CMS scan...")
            cms_findings = await self.scan_cms(target)
            all_findings.extend(cms_findings)
        
        # E-commerce Scan
        if "ecommerce" in scan_types:
            print(f"  [+] Running E-commerce scan...")
            ecommerce_findings = await self.scan_ecommerce(target)
            all_findings.extend(ecommerce_findings)
        
        # Framework Scan
        if "framework" in scan_types:
            print(f"  [+] Running Framework scan...")
            framework_findings = await self.scan_frameworks(target)
            all_findings.extend(framework_findings)
        
        # Cloud Security Scan
        if "cloud" in scan_types:
            print(f"  [+] Running Cloud security scan...")
            # Extract domain from URL
            domain = target.split("//")[-1].split("/")[0]
            cloud_findings = await self.cloud_scanner.scan_cloud(domain)
            all_findings.extend(cloud_findings)
        
        # CI/CD Scan
        if "cicd" in scan_types:
            print(f"  [+] Running CI/CD security scan...")
            cicd_findings = await self.cicd_scanner.scan_cicd(target)
            all_findings.extend(cicd_findings)
        
        scan_result["findings"] = all_findings
        scan_result["status"] = "completed"
        scan_result["findings_count"] = len(all_findings)
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in all_findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] += 1
        
        scan_result["severity_counts"] = dict(severity_counts)
        
        # Add to history
        self.scan_history.append(scan_result)
        self.findings.extend(all_findings)
        
        # Update dashboard
        for finding in all_findings:
            if self.dashboard:
                self.dashboard.add_finding(finding)
        
        print(f"[+] Scan completed. Found {len(all_findings)} vulnerabilities.")
        
        return scan_result
    
    async def scan_cms(self, url: str) -> List[Dict[str, Any]]:
        """Detect and scan CMS platforms"""
        findings = []
        
        # Try to detect CMS
        detected_cms = await self.detect_cms(url)
        
        if detected_cms:
            print(f"    [+] Detected CMS: {detected_cms}")
            scanner = self.cms_scanners.get(detected_cms)
            if scanner:
                cms_findings = await scanner.scan(url)
                findings.extend(cms_findings)
        else:
            # Try all CMS scanners
            for cms_type, scanner in self.cms_scanners.items():
                try:
                    cms_findings = await scanner.scan(url)
                    if cms_findings:
                        findings.extend(cms_findings)
                        break
                except Exception as e:
                    continue
        
        return findings
    
    async def detect_cms(self, url: str) -> Optional[str]:
        """Detect CMS platform"""
        try:
            async with self.session.get(url, timeout=5) as response:
                content = await response.text()
                
                # WordPress detection
                if "wp-content" in content or "wp-includes" in content:
                    return "wordpress"
                
                # Joomla detection
                if "joomla" in content.lower() or "/media/system/" in content:
                    return "joomla"
                
                # Drupal detection
                if "drupal" in content.lower() or "sites/default/" in content:
                    return "drupal"
        
        except Exception as e:
            pass
        
        return None
    
    async def scan_ecommerce(self, url: str) -> List[Dict[str, Any]]:
        """Detect and scan e-commerce platforms"""
        findings = []
        
        # Try all e-commerce scanners
        for platform, scanner in self.ecommerce_scanners.items():
            try:
                ecommerce_findings = await scanner.scan(url)
                if ecommerce_findings:
                    findings.extend(ecommerce_findings)
                    print(f"    [+] Detected e-commerce platform: {platform}")
                    break
            except Exception as e:
                continue
        
        return findings
    
    async def scan_frameworks(self, url: str) -> List[Dict[str, Any]]:
        """Detect and scan web frameworks"""
        findings = []
        
        # Common framework indicators
        framework_indicators = [
            ("laravel", ["_ignition", "storage/", "vendor/laravel"]),
            ("django", ["__debug__", "/admin/", "Django"]),
            ("rails", ["rails/info", "assets/rails"]),
            ("spring", ["actuator", "springframework"])
        ]
        
        try:
            async with self.session.get(url, timeout=5) as response:
                content = await response.text()
                headers = response.headers
                
                for framework, indicators in framework_indicators:
                    for indicator in indicators:
                        if indicator in content or indicator in str(headers):
                            print(f"    [+] Detected framework: {framework}")
                            framework_findings = await self.framework_scanner.scan_framework(url, framework)
                            findings.extend(framework_findings)
                            break
        except Exception as e:
            pass
        
        return findings
    
    async def generate_report(self, scan_result: Dict[str, Any], format: str = "html") -> str:
        """Generate vulnerability report"""
        print(f"[+] Generating {format.upper()} report...")
        
        if format == "html":
            return self.generate_html_report(scan_result)
        elif format == "json":
            return self.generate_json_report(scan_result)
        elif format == "csv":
            return self.generate_csv_report(scan_result)
        else:
            return self.generate_text_report(scan_result)
    
    def generate_html_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate HTML report"""
        findings = scan_result.get("findings", [])
        
        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Bug Hunter Pro - Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .info {{ border-left: 5px solid #17a2b8; }}
        .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; }}
        .critical-badge {{ background: #dc3545; color: white; }}
        .high-badge {{ background: #fd7e14; color: white; }}
        .medium-badge {{ background: #ffc107; color: black; }}
        .low-badge {{ background: #28a745; color: white; }}
        .info-badge {{ background: #17a2b8; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🐛 Bug Hunter Pro Security Report</h1>
        <p>Target: {scan_result.get('target', 'N/A')}</p>
        <p>Scan Date: {scan_result.get('timestamp', 'N/A')}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Total Findings: {len(findings)}</p>
        <p>Critical: {scan_result.get('severity_counts', {}).get('critical', 0)}</p>
        <p>High: {scan_result.get('severity_counts', {}).get('high', 0)}</p>
        <p>Medium: {scan_result.get('severity_counts', {}).get('medium', 0)}</p>
        <p>Low: {scan_result.get('severity_counts', {}).get('low', 0)}</p>
        <p>Info: {scan_result.get('severity_counts', {}).get('info', 0)}</p>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        for finding in findings:
            severity = finding.get("severity", "info")
            severity_class = severity.lower()
            
            html_report += f"""
    <div class="finding {severity_class}">
        <h3>{finding.get('title', 'N/A')}</h3>
        <p><span class="severity {severity_class}-badge">{severity.upper()}</span></p>
        <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
        <p><strong>URL:</strong> <a href="{finding.get('url', '#')}" target="_blank">{finding.get('url', 'N/A')}</a></p>
        <p><strong>Evidence:</strong> {finding.get('evidence', 'N/A')}</p>
        <p><strong>Confidence:</strong> {finding.get('confidence', 'N/A')}</p>
    </div>
"""
        
        html_report += """
</body>
</html>
"""
        
        # Save report
        report_dir = "bug_hunter_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"report_{timestamp}.html")
        
        with open(report_path, 'w') as f:
            f.write(html_report)
        
        print(f"[+] HTML report saved: {report_path}")
        return report_path
    
    def generate_json_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate JSON report"""
        report_dir = "bug_hunter_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"report_{timestamp}.json")
        
        with open(report_path, 'w') as f:
            json.dump(scan_result, f, indent=2)
        
        print(f"[+] JSON report saved: {report_path}")
        return report_path
    
    def generate_csv_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate CSV report"""
        findings = scan_result.get("findings", [])
        
        report_dir = "bug_hunter_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"report_{timestamp}.csv")
        
        with open(report_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Title", "Severity", "Description", "URL", "Evidence", "Confidence"])
            
            for finding in findings:
                writer.writerow([
                    finding.get("title", ""),
                    finding.get("severity", ""),
                    finding.get("description", ""),
                    finding.get("url", ""),
                    finding.get("evidence", ""),
                    finding.get("confidence", "")
                ])
        
        print(f"[+] CSV report saved: {report_path}")
        return report_path
    
    def generate_text_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate text report"""
        findings = scan_result.get("findings", [])
        
        report_text = f"""
===========================================
BUG HUNTER PRO - SECURITY REPORT
===========================================

Target: {scan_result.get('target', 'N/A')}
Scan Date: {scan_result.get('timestamp', 'N/A')}
Total Findings: {len(findings)}

Severity Breakdown:
  Critical: {scan_result.get('severity_counts', {}).get('critical', 0)}
  High: {scan_result.get('severity_counts', {}).get('high', 0)}
  Medium: {scan_result.get('severity_counts', {}).get('medium', 0)}
  Low: {scan_result.get('severity_counts', {}).get('low', 0)}
  Info: {scan_result.get('severity_counts', {}).get('info', 0)}

===========================================
DETAILED FINDINGS
===========================================

"""
        
        for i, finding in enumerate(findings, 1):
            report_text += f"""
[{i}] {finding.get('title', 'N/A')}
    Severity: {finding.get('severity', 'N/A')}
    Description: {finding.get('description', 'N/A')}
    URL: {finding.get('url', 'N/A')}
    Evidence: {finding.get('evidence', 'N/A')}
    Confidence: {finding.get('confidence', 'N/A')}
"""
        
        report_dir = "bug_hunter_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"report_{timestamp}.txt")
        
        with open(report_path, 'w') as f:
            f.write(report_text)
        
        print(f"[+] Text report saved: {report_path}")
        return report_path
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        print("[+] Engine cleanup completed")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

async def main():
    """Main command line interface"""
    parser = argparse.ArgumentParser(description="Bug Hunter Pro v3.0 - Enterprise Security Platform")
    parser.add_argument("target", help="Target URL or domain to scan")
    parser.add_argument("--scan-types", help="Types of scans to perform (comma-separated)",
                       default="cms,ecommerce,framework,cloud,cicd")
    parser.add_argument("--dashboard", action="store_true", help="Start web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--report-format", choices=["html", "json", "csv", "text"],
                       default="html", help="Report format")
    parser.add_argument("--output", help="Output directory for reports")
    
    args = parser.parse_args()
    
    # Create engine
    engine = BugHunterEngine()
    await engine.initialize()
    
    # Start dashboard if requested
    if args.dashboard:
        await engine.dashboard.start_dashboard(args.dashboard_port)
    
    # Parse scan types
    scan_types = [st.strip() for st in args.scan_types.split(",")]
    
    # Run scan
    try:
        result = await engine.scan_target(args.target, scan_types)
        
        # Generate report
        report_path = await engine.generate_report(result, args.report_format)
        print(f"[+] Report generated: {report_path}")
        
        # Print summary
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {result['target']}")
        print(f"Total Findings: {result['findings_count']}")
        
        for severity, count in result.get('severity_counts', {}).items():
            print(f"  {severity.upper()}: {count}")
        
        # List critical findings
        critical_findings = [f for f in result['findings'] if f.get('severity') == 'critical']
        if critical_findings:
            print(f"\nCRITICAL FINDINGS ({len(critical_findings)}):")
            for finding in critical_findings[:5]:  # Show first 5
                print(f"  • {finding['title']}")
        
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Keep dashboard running if started
        if args.dashboard:
            print("\n[+] Dashboard is running. Press Ctrl+C to exit.")
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\n[+] Shutting down...")
        
        await engine.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
