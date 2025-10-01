from mitmproxy import http
import requests
import re
import urllib.parse

def request(flow: http.HTTPFlow) -> None:
    try:
        url = flow.request.pretty_url
        path = flow.request.path
        
        # Handle whitelist addition requests
        if path == '/api/whitelist/add' and flow.request.method == 'POST':
            handle_whitelist_add(flow)
            return
        
        # Debug logging
        print(f"🔍 Processing request: {url}")
        print(f"   Path: {path}")
        print(f"   Accept header: {flow.request.headers.get('accept', 'None')}")
        
        # Skip analysis for non-essential resources to reduce API calls
        if should_skip_analysis(url, path, flow):
            print(f"🚀 Skipping analysis for resource: {url}")
            return  # Allow the request to proceed without analysis
        
        print(f"🔍 Analyzing main content: {url}")
        
        # Use the Docker service name instead of localhost
        resp = requests.post('http://anti-phishing-gateway:8080/ai-check', json={'url': url})
        decision = resp.json().get('decision')
        
        print(f"🎯 Decision for {url}: {decision}")
        
        if decision == 'BLOCK':
            # Create block page HTML with whitelist functionality
            block_html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚫 Suspicious Site Blocked</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #1a1a1a;
            color: #fff;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }}
        .container {{
            background: #222;
            border-radius: 12px;
            box-shadow: 0 4px 24px #000a;
            padding: 32px 24px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        h1 {{
            color: #ff4444;
            margin-bottom: 16px;
        }}
        .url {{
            color: #00aaff;
            word-break: break-all;
            margin-bottom: 12px;
        }}
        .btn {{
            background: #00ff99;
            color: #222;
            border: none;
            border-radius: 4px;
            padding: 10px 24px;
            font-size: 1em;
            cursor: pointer;
            margin-top: 18px;
            transition: background 0.2s;
        }}
        .btn:hover {{
            background: #00cc77;
        }}
        .msg {{
            margin-top: 16px;
            color: #00ff99;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Suspicious Site Blocked</h1>
        <div class="url">{url}</div>
        <div style="background: #333; border-radius: 6px; padding: 10px; margin: 10px 0; color: #ffaa00;">
            <strong>Reason:</strong> This site matches phishing patterns and is blocked for your safety.
        </div>
        <button class="btn" id="whitelistBtn">Add to Whitelist & Retry</button>
        <div class="msg" id="msg"></div>
    </div>
    <script>
        document.getElementById('whitelistBtn').onclick = function() {{
            fetch('/api/whitelist/add', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ url: '{url}' }})
            }})
            .then(res => res.json())
            .then(data => {{
                if (data.success) {{
                    document.getElementById('msg').textContent = 'URL added to whitelist! Reloading...';
                    setTimeout(() => {{
                        window.location.href = '{url}';
                    }}, 1200);
                }} else {{
                    document.getElementById('msg').textContent = data.message || 'Failed to add to whitelist.';
                }}
            }})
            .catch(() => {{
                document.getElementById('msg').textContent = 'Error adding to whitelist.';
            }});
        }};
    </script>
</body>
</html>
            '''
            flow.response = http.Response.make(403, block_html.encode('utf-8'), {"Content-Type": "text/html"})
        elif decision == 'WARN':
            # Create warning page HTML with whitelist functionality
            warn_html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚠️ Suspicious Site Warning</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #1a1a1a;
            color: #fff;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }}
        .container {{
            background: #222;
            border-radius: 12px;
            box-shadow: 0 4px 24px #000a;
            padding: 32px 24px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        h1 {{
            color: #ffaa00;
            margin-bottom: 16px;
        }}
        .url {{
            color: #00aaff;
            word-break: break-all;
            margin-bottom: 12px;
        }}
        .btn {{
            background: #ffaa00;
            color: #222;
            border: none;
            border-radius: 4px;
            padding: 10px 24px;
            font-size: 1em;
            cursor: pointer;
            margin-top: 18px;
            transition: background 0.2s;
        }}
        .btn:hover {{
            background: #ffcc00;
        }}
        .msg {{
            margin-top: 16px;
            color: #00ff99;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Suspicious Site Warning</h1>
        <div class="url">{url}</div>
        <div style="background: #333; border-radius: 6px; padding: 10px; margin: 10px 0; color: #ffaa00;">
            <strong>Reason:</strong> Potential security concerns detected
        </div>
        <button class="btn" id="whitelistBtn">Add to Whitelist & Retry</button>
        <div class="msg" id="msg"></div>
    </div>
    <script>
        document.getElementById('whitelistBtn').onclick = function() {{
            fetch('/api/whitelist/add', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ url: '{url}' }})
            }})
            .then(res => res.json())
            .then(data => {{
                if (data.success) {{
                    document.getElementById('msg').textContent = 'URL added to whitelist! Reloading...';
                    setTimeout(() => {{
                        window.location.href = '{url}';
                    }}, 1200);
                }} else {{
                    document.getElementById('msg').textContent = data.message || 'Failed to add to whitelist.';
                }}
            }})
            .catch(() => {{
                document.getElementById('msg').textContent = 'Error adding to whitelist.';
            }});
        }};
    </script>
</body>
</html>
            '''
            flow.response = http.Response.make(200, warn_html.encode('utf-8'), {"Content-Type": "text/html"})
        # else: allow
        
    except Exception as e:
        print(f"AI backend error: {e}")

def handle_whitelist_add(flow: http.HTTPFlow) -> None:
    """Handle whitelist addition requests"""
    try:
        # Get the JSON body from the request
        body = flow.request.content.decode('utf-8')
        import json
        data = json.loads(body)
        url_to_whitelist = data.get('url')
        
        if url_to_whitelist:
            print(f"➕ Adding to whitelist: {url_to_whitelist}")
            
            # First, remove from blocklist if it exists there
            try:
                blocklist_resp = requests.delete('http://anti-phishing-gateway:8080/api/blocklist/remove', 
                                               json={'url': url_to_whitelist})
                if blocklist_resp.status_code == 200:
                    blocklist_result = blocklist_resp.json()
                    if blocklist_result.get('success'):
                        print(f"🗑️ Removed from blocklist: {url_to_whitelist}")
                    else:
                        print(f"ℹ️ URL was not in blocklist: {url_to_whitelist}")
                else:
                    print(f"⚠️ Could not check/remove from blocklist: {blocklist_resp.status_code}")
            except Exception as e:
                print(f"⚠️ Error checking blocklist: {e}")
            
            # Then add to whitelist
            try:
                whitelist_resp = requests.post('http://anti-phishing-gateway:8080/api/whitelist/add', 
                                             json={'url': url_to_whitelist})
                
                if whitelist_resp.status_code == 200:
                    result = whitelist_resp.json()
                    if result.get('success'):
                        print(f"✅ Successfully added to whitelist: {url_to_whitelist}")
                        # Return success response
                        response_data = {
                            'success': True,
                            'message': 'URL added to whitelist successfully',
                            'url': url_to_whitelist
                        }
                    else:
                        print(f"⚠️ Failed to add to whitelist: {result.get('message', 'Unknown error')}")
                        response_data = {
                            'success': False,
                            'message': result.get('message', 'Failed to add to whitelist')
                        }
                else:
                    print(f"❌ Error calling whitelist API: {whitelist_resp.status_code}")
                    response_data = {
                        'success': False,
                        'message': 'Error communicating with whitelist service'
                    }
            except Exception as e:
                print(f"❌ Error adding to whitelist: {e}")
                response_data = {
                    'success': False,
                    'message': 'Error communicating with whitelist service'
                }
        else:
            response_data = {
                'success': False,
                'message': 'No URL provided'
            }
        
        # Return JSON response
        response_json = json.dumps(response_data)
        flow.response = http.Response.make(
            200, 
            response_json.encode('utf-8'), 
            {"Content-Type": "application/json"}
        )
        
    except Exception as e:
        print(f"❌ Error handling whitelist add: {e}")
        error_response = json.dumps({
            'success': False,
            'message': 'Internal error'
        })
        flow.response = http.Response.make(
            500, 
            error_response.encode('utf-8'), 
            {"Content-Type": "application/json"}
        )

def should_skip_analysis(url, path, flow):
    """
    Determine if we should skip AI analysis for this resource.
    Only analyze main page content, not assets/resources.
    """
    
    # Skip if it's not the main document
    if flow.request.headers.get('accept', '').find('text/html') == -1:
        return True
    
    # Skip common asset patterns
    asset_patterns = [
        r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$',
        r'/(css|js|images|img|assets|static|media|fonts)/',
        r'\.min\.(css|js)$',
        r'/api/',
        r'/ajax/',
        r'/tracking/',
        r'/analytics/',
        r'/pixel',
        r'/beacon',
        r'/gtm',
        r'/ga\.js',
        r'/analytics\.js',
        r'/doubleclick\.net',
        r'/googleads\.',
        r'/facebook\.com/tr',
        r'/googletagmanager\.com',
        r'/google-analytics\.com',
        r'/hotjar\.com',
        r'/segment\.com',
        r'/mixpanel\.com'
    ]
    
    for pattern in asset_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    # Skip if path has query parameters (likely tracking/analytics) - but not for main pages
    if '?' in path and any(param in path.lower() for param in ['id=', 'ev=', 'guid=', 'script=', 'data=']):
        # Don't skip if it's the main page (no path or just '/')
        if path != '/' and path != '':
            return True
    
    # Skip subdomain resources (CDN, static content)
    domain_parts = url.split('/')[2].split('.')
    if len(domain_parts) > 2:  # Has subdomain
        subdomain = domain_parts[0].lower()
        if subdomain in ['cdn', 'static', 'assets', 'media', 'images', 'img', 'js', 'css', 'fonts']:
            return True
    
    return False
