 ver-.*# ver-2025-10-26-11:32:16 by yutian81
 ver-.*import os
 ver-.*import re
 ver-.*import json
 ver-.*import time
 ver-.*import base64
 ver-.*import shutil
 ver-.*import asyncio
 ver-.*import requests
 ver-.*import platform
 ver-.*import subprocess
 ver-.*import threading
 ver-.*from threading import Thread
 ver-.*
 ver-.*# Environment variables
 ver-.*UPLOAD_URL = os.environ.get('UPLOAD_URL', '')            # 节点或订阅上传地址,只填写这个地址将上传节点,同时填写PROJECT_URL将上传订阅，例如：https://merge.serv00.net
 ver-.*PROJECT_URL = os.environ.get('PROJECT_URL', '')          # 项目url,需要自动保活或自动上传订阅需要填写,例如：https://www.google.com,
 ver-.*AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'  # false关闭自动保活, true开启自动保活，默认关闭
 ver-.*FILE_PATH = os.environ.get('FILE_PATH', './.cache')      # 运行路径,sub.txt保存路径
 ver-.*SUB_PATH = os.environ.get('SUB_PATH', 'sub')              # 订阅token,默认sub，例如：https://www.google.com/sub
 ver-.*UUID = os.environ.get('UUID', '20e6e496-cf19-45c8-b883-14f5e11cd9f1')  # UUID,如使用哪吒v1,在不同的平台部署需要修改,否则会覆盖
 ver-.*NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')        # 哪吒面板域名或ip, v1格式: nezha.xxx.com:8008, v0格式: nezha.xxx.com
 ver-.*NEZHA_PORT = os.environ.get('NEZHA_PORT', '')            # v1哪吒请留空, v0哪吒的agent通信端口,自动匹配tls
 ver-.*NEZHA_KEY = os.environ.get('NEZHA_KEY', '')              # v1哪吒的NZ_CLIENT_SECRET或v0哪吒agent密钥
 ver-.*ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', '')          # Argo固定隧道域名,留空即使用临时隧道
 ver-.*ARGO_AUTH = os.environ.get('ARGO_AUTH', '')              # Argo固定隧道密钥,留空即使用临时隧道
 ver-.*ARGO_PORT = int(os.environ.get('PORT', '8001'))
 ver-.*CFIP = os.environ.get('CFIP', 'cf.877774.xyz')          # 优选ip或优选域名
 ver-.*CFPORT = int(os.environ.get('CFPORT', '443'))            # 优选ip或优选域名对应端口
 ver-.*NAME = os.environ.get('NAME', 'Stream')                      # 节点名称
 ver-.*CHAT_ID = os.environ.get('CHAT_ID', '')                  # Telegram chat_id,推送节点到tg,两个变量同时填写才会推送
 ver-.*BOT_TOKEN = os.environ.get('BOT_TOKEN', '')              # Telegram bot_token
 ver-.*
 ver-.*# Create running folder
 ver-.*def create_directory():
 ver-.*    print('\033c', end='')
 ver-.*    if not os.path.exists(FILE_PATH):
 ver-.*        os.makedirs(FILE_PATH)
 ver-.*        print(f"{FILE_PATH} is created")
 ver-.*    else:
 ver-.*        print(f"{FILE_PATH} already exists")
 ver-.*
 ver-.*# Global variables
 ver-.*npm_path = os.path.join(FILE_PATH, 'npm')
 ver-.*php_path = os.path.join(FILE_PATH, 'php')
 ver-.*web_path = os.path.join(FILE_PATH, 'web')
 ver-.*bot_path = os.path.join(FILE_PATH, 'bot')
 ver-.*sub_path = os.path.join(FILE_PATH, 'sub.txt')
 ver-.*list_path = os.path.join(FILE_PATH, 'list.txt')
 ver-.*boot_log_path = os.path.join(FILE_PATH, 'boot.log')
 ver-.*config_path = os.path.join(FILE_PATH, 'config.json')
 ver-.*
 ver-.*# Delete nodes
 ver-.*def delete_nodes():
 ver-.*    try:
 ver-.*        if not UPLOAD_URL:
 ver-.*            return
 ver-.*
 ver-.*        if not os.path.exists(sub_path):
 ver-.*            return
 ver-.*
 ver-.*        try:
 ver-.*            with open(sub_path, 'r') as file:
 ver-.*                file_content = file.read()
 ver-.*        except:
 ver-.*            return None
 ver-.*
 ver-.*        decoded = base64.b64decode(file_content).decode('utf-8')
 ver-.*        nodes = [line for line in decoded.split('\n') if any(protocol in line for protocol in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
 ver-.*
 ver-.*        if not nodes:
 ver-.*            return
 ver-.*
 ver-.*        try:
 ver-.*            requests.post(f"{UPLOAD_URL}/api/delete-nodes",
 ver-.*                          data=json.dumps({"nodes": nodes}),
 ver-.*                          headers={"Content-Type": "application/json"})
 ver-.*        except:
 ver-.*            return None
 ver-.*    except Exception as e:
 ver-.*        print(f"Error in delete_nodes: {e}")
 ver-.*        return None
 ver-.*
 ver-.*# Clean up old files
 ver-.*def cleanup_old_files():
 ver-.*    paths_to_delete = ['web', 'bot', 'npm', 'php', 'boot.log', 'list.txt']
 ver-.*    for file in paths_to_delete:
 ver-.*        file_path = os.path.join(FILE_PATH, file)
 ver-.*        try:
 ver-.*            if os.path.exists(file_path):
 ver-.*                if os.path.isdir(file_path):
 ver-.*                    shutil.rmtree(file_path)
 ver-.*                else:
 ver-.*                    os.remove(file_path)
 ver-.*        except Exception as e:
 ver-.*            print(f"Error removing {file_path}: {e}")
 ver-.*
 ver-.*# Determine system architecture
 ver-.*def get_system_architecture():
 ver-.*    architecture = platform.machine().lower()
 ver-.*    if 'arm' in architecture or 'aarch64' in architecture:
 ver-.*        return 'arm'
 ver-.*    else:
 ver-.*        return 'amd'
 ver-.*
 ver-.*# Download file based on architecture
 ver-.*def download_file(file_name, file_url):
 ver-.*    file_path = os.path.join(FILE_PATH, file_name)
 ver-.*    try:
 ver-.*        response = requests.get(file_url, stream=True)
 ver-.*        response.raise_for_status()
 ver-.*
 ver-.*        with open(file_path, 'wb') as f:
 ver-.*            for chunk in response.iter_content(chunk_size=8192):
 ver-.*                f.write(chunk)
 ver-.*
 ver-.*        print(f"Download {file_name} successfully")
 ver-.*        return True
 ver-.*    except Exception as e:
 ver-.*        if os.path.exists(file_path):
 ver-.*            os.remove(file_path)
 ver-.*        print(f"Download {file_name} failed: {e}")
 ver-.*        return False
 ver-.*
 ver-.*# Get files for architecture
 ver-.*def get_files_for_architecture(architecture):
 ver-.*    if architecture == 'arm':
 ver-.*        base_files = [
 ver-.*            {"fileName": "web", "fileUrl": "https://arm64.ssss.nyc.mn/web"},
 ver-.*            {"fileName": "bot", "fileUrl": "https://arm64.ssss.nyc.mn/2go"}
 ver-.*        ]
 ver-.*    else:
 ver-.*        base_files = [
 ver-.*            {"fileName": "web", "fileUrl": "https://amd64.ssss.nyc.mn/web"},
 ver-.*            {"fileName": "bot", "fileUrl": "https://amd64.ssss.nyc.mn/2go"}
 ver-.*        ]
 ver-.*
 ver-.*    if NEZHA_SERVER and NEZHA_KEY:
 ver-.*        if NEZHA_PORT:
 ver-.*            npm_url = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/agent"
 ver-.*            base_files.insert(0, {"fileName": "npm", "fileUrl": npm_url})
 ver-.*        else:
 ver-.*            php_url = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/v1"
 ver-.*            base_files.insert(0, {"fileName": "php", "fileUrl": php_url})
 ver-.*
 ver-.*    return base_files
 ver-.*
 ver-.*# Authorize files with execute permission
 ver-.*def authorize_files(file_paths):
 ver-.*    for relative_file_path in file_paths:
 ver-.*        absolute_file_path = os.path.join(FILE_PATH, relative_file_path)
 ver-.*        if os.path.exists(absolute_file_path):
 ver-.*            try:
 ver-.*                os.chmod(absolute_file_path, 0o775)
 ver-.*                print(f"Empowerment success for {absolute_file_path}: 775")
 ver-.*            except Exception as e:
 ver-.*                print(f"Empowerment failed for {absolute_file_path}: {e}")
 ver-.*
 ver-.*# Configure Argo tunnel
 ver-.*def argo_type():
 ver-.*    if not ARGO_AUTH or not ARGO_DOMAIN:
 ver-.*        print("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels")
 ver-.*        return
 ver-.*
 ver-.*    if "TunnelSecret" in ARGO_AUTH:
 ver-.*        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
 ver-.*            f.write(ARGO_AUTH)
 ver-.*
 ver-.*        tunnel_id = ARGO_AUTH.split('"')[11]
 ver-.*        tunnel_yml = f"""
 ver-.*tunnel: {tunnel_id}
 ver-.*credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
 ver-.*protocol: http2
 ver-.*
 ver-.*ingress:
 ver-.*  - hostname: {ARGO_DOMAIN}
 ver-.*    service: http://localhost:{ARGO_PORT}
 ver-.*    originRequest:
 ver-.*      noTLSVerify: true
 ver-.*  - service: http_status:404
 ver-.*"""
 ver-.*        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
 ver-.*            f.write(tunnel_yml)
 ver-.*    else:
 ver-.*        print("Use token connect to tunnel,please set the {ARGO_PORT} in cloudflare")
 ver-.*
 ver-.*# Execute shell command and return output
 ver-.*def exec_cmd(command):
 ver-.*    try:
 ver-.*        process = subprocess.Popen(
 ver-.*            command,
 ver-.*            shell=True,
 ver-.*            stdout=subprocess.PIPE,
 ver-.*            stderr=subprocess.PIPE,
 ver-.*            text=True
 ver-.*        )
 ver-.*        stdout, stderr = process.communicate()
 ver-.*        return stdout + stderr
 ver-.*    except Exception as e:
 ver-.*        print(f"Error executing command: {e}")
 ver-.*        return str(e)
 ver-.*
 ver-.*# Download and run necessary files
 ver-.*async def download_files_and_run():
 ver-.*    global private_key, public_key
 ver-.*
 ver-.*    architecture = get_system_architecture()
 ver-.*    files_to_download = get_files_for_architecture(architecture)
 ver-.*
 ver-.*    if not files_to_download:
 ver-.*        print("Can't find a file for the current architecture")
 ver-.*        return
 ver-.*
 ver-.*    # Download all files
 ver-.*    download_success = True
 ver-.*    for file_info in files_to_download:
 ver-.*        if not download_file(file_info["fileName"], file_info["fileUrl"]):
 ver-.*            download_success = False
 ver-.*
 ver-.*    if not download_success:
 ver-.*        print("Error downloading files")
 ver-.*        return
 ver-.*
 ver-.*    # Authorize files
 ver-.*    files_to_authorize = ['npm', 'web', 'bot'] if NEZHA_PORT else ['php', 'web', 'bot']
 ver-.*    authorize_files(files_to_authorize)
 ver-.*
 ver-.*    # Check TLS
 ver-.*    port = NEZHA_SERVER.split(":")[-1] if ":" in NEZHA_SERVER else ""
 ver-.*    if port in ["443", "8443", "2096", "2087", "2083", "2053"]:
 ver-.*        nezha_tls = "true"
 ver-.*    else:
 ver-.*        nezha_tls = "false"
 ver-.*
 ver-.*    # Configure nezha
 ver-.*    if NEZHA_SERVER and NEZHA_KEY:
 ver-.*        if not NEZHA_PORT:
 ver-.*            # Generate config.yaml for v1
 ver-.*            config_yaml = f"""
 ver-.*client_secret: {NEZHA_KEY}
 ver-.*debug: false
 ver-.*disable_auto_update: true
 ver-.*disable_command_execute: false
 ver-.*disable_force_update: true
 ver-.*disable_nat: false
 ver-.*disable_send_query: false
 ver-.*gpu: false
 ver-.*insecure_tls: false
 ver-.*ip_report_period: 1800
 ver-.*report_delay: 4
 ver-.*server: {NEZHA_SERVER}
 ver-.*skip_connection_count: false
 ver-.*skip_procs_count: false
 ver-.*temperature: false
 ver-.*tls: {nezha_tls}
 ver-.*use_gitee_to_upgrade: false
 ver-.*use_ipv6_country_code: false
 ver-.*uuid: {UUID}"""
 ver-.*
 ver-.*            with open(os.path.join(FILE_PATH, 'config.yaml'), 'w') as f:
 ver-.*                f.write(config_yaml)
 ver-.*
 ver-.*    # Generate configuration file
 ver-.*    config ={"log":{"access":"/dev/null","error":"/dev/null","loglevel":"none",},"inbounds":[{"port":ARGO_PORT ,"protocol":"vless","settings":{"clients":[{"id":UUID ,"flow":"xtls-rprx-vision",},],"decryption":"none","fallbacks":[{"dest":3001 },{"path":"/vless-argo","dest":3002 },{"path":"/vmess-argo","dest":3003 },{"path":"/trojan-argo","dest":3004 },],},"streamSettings":{"network":"tcp",},},{"port":3001 ,"listen":"127.0.0.1","protocol":"vless","settings":{"clients":[{"id":UUID },],"decryption":"none"},"streamSettings":{"network":"ws","security":"none"}},{"port":3002 ,"listen":"127.0.0.1","protocol":"vless","settings":{"clients":[{"id":UUID ,"level":0 }],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless-argo"}},"sniffing":{"enabled":True ,"destOverride":["http","tls","quic"],"metadataOnly":False }},{"port":3003 ,"listen":"127.0.0.1","protocol":"vmess","settings":{"clients":[{"id":UUID ,"alterId":0 }]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vmess-argo"}},"sniffing":{"enabled":True ,"destOverride":["http","tls","quic"],"metadataOnly":False }},{"port":3004 ,"listen":"127.0.0.1","protocol":"trojan","settings":{"clients":[{"password":UUID },]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/trojan-argo"}},"sniffing":{"enabled":True ,"destOverride":["http","tls","quic"],"metadataOnly":False }},],"outbounds":[{"protocol":"freedom","tag": "direct" },{"protocol":"blackhole","tag":"block"}]}
 ver-.*    with open(os.path.join(FILE_PATH, 'config.json'), 'w', encoding='utf-8') as config_file:
 ver-.*        json.dump(config, config_file, ensure_ascii=False, indent=2)
 ver-.*
 ver-.*    # Run nezha
 ver-.*    if NEZHA_SERVER and NEZHA_PORT and NEZHA_KEY:
 ver-.*        tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
 ver-.*        nezha_tls = '--tls' if NEZHA_PORT in tls_ports else ''
 ver-.*        command = f"nohup {os.path.join(FILE_PATH, 'npm')} -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} {nezha_tls} >/dev/null 2>&1 &"
 ver-.*
 ver-.*        try:
 ver-.*            exec_cmd(command)
 ver-.*            print('npm is running')
 ver-.*            time.sleep(1)
 ver-.*        except Exception as e:
 ver-.*            print(f"npm running error: {e}")
 ver-.*
 ver-.*    elif NEZHA_SERVER and NEZHA_KEY:
 ver-.*        # Run V1
 ver-.*        command = f"nohup {FILE_PATH}/php -c \"{FILE_PATH}/config.yaml\" >/dev/null 2>&1 &"
 ver-.*        try:
 ver-.*            exec_cmd(command)
 ver-.*            print('php is running')
 ver-.*            time.sleep(1)
 ver-.*        except Exception as e:
 ver-.*            print(f"php running error: {e}")
 ver-.*    else:
 ver-.*        print('NEZHA variable is empty, skipping running')
 ver-.*
 ver-.*    # Run sbX
 ver-.*    command = f"nohup {os.path.join(FILE_PATH, 'web')} -c {os.path.join(FILE_PATH, 'config.json')} >/dev/null 2>&1 &"
 ver-.*    try:
 ver-.*        exec_cmd(command)
 ver-.*        print('web is running')
 ver-.*        time.sleep(1)
 ver-.*    except Exception as e:
 ver-.*        print(f"web running error: {e}")
 ver-.*
 ver-.*    # Run cloudflared
 ver-.*    if os.path.exists(os.path.join(FILE_PATH, 'bot')):
 ver-.*        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
 ver-.*            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {ARGO_AUTH}"
 ver-.*        elif "TunnelSecret" in ARGO_AUTH:
 ver-.*            args = f"tunnel --edge-ip-version auto --config {os.path.join(FILE_PATH, 'tunnel.yml')} run"
 ver-.*        else:
 ver-.*            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {os.path.join(FILE_PATH, 'boot.log')} --loglevel info --url http://localhost:{ARGO_PORT}"
 ver-.*
 ver-.*        try:
 ver-.*            exec_cmd(f"nohup {os.path.join(FILE_PATH, 'bot')} {args} >/dev/null 2>&1 &")
 ver-.*            print('bot is running')
 ver-.*            time.sleep(2)
 ver-.*        except Exception as e:
 ver-.*            print(f"Error executing command: {e}")
 ver-.*
 ver-.*    time.sleep(5)
 ver-.*
 ver-.*    # Extract domains and generate sub.txt
 ver-.*    await extract_domains()
 ver-.*
 ver-.*# Extract domains from cloudflared logs
 ver-.*async def extract_domains():
 ver-.*    argo_domain = None
 ver-.*
 ver-.*    if ARGO_AUTH and ARGO_DOMAIN:
 ver-.*        argo_domain = ARGO_DOMAIN
 ver-.*        print(f'ARGO_DOMAIN: {argo_domain}')
 ver-.*        await generate_links(argo_domain)
 ver-.*    else:
 ver-.*        try:
 ver-.*            with open(boot_log_path, 'r') as f:
 ver-.*                file_content = f.read()
 ver-.*
 ver-.*            lines = file_content.split('\n')
 ver-.*            argo_domains = []
 ver-.*
 ver-.*            for line in lines:
 ver-.*                domain_match = re.search(r'https?://([^ ]*trycloudflare\.com)/?', line)
 ver-.*                if domain_match:
 ver-.*                    domain = domain_match.group(1)
 ver-.*                    argo_domains.append(domain)
 ver-.*
 ver-.*            if argo_domains:
 ver-.*                argo_domain = argo_domains[0]
 ver-.*                print(f'ArgoDomain: {argo_domain}')
 ver-.*                await generate_links(argo_domain)
 ver-.*            else:
 ver-.*                print('ArgoDomain not found, re-running bot to obtain ArgoDomain')
 ver-.*                # Remove boot.log and restart bot
 ver-.*                if os.path.exists(boot_log_path):
 ver-.*                    os.remove(boot_log_path)
 ver-.*
 ver-.*                try:
 ver-.*                    exec_cmd('pkill -f "[b]ot" > /dev/null 2>&1')
 ver-.*                except:
 ver-.*                    pass
 ver-.*
 ver-.*                time.sleep(1)
 ver-.*                args = f'tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {FILE_PATH}/boot.log --loglevel info --url http://localhost:{ARGO_PORT}'
 ver-.*                exec_cmd(f'nohup {os.path.join(FILE_PATH, "bot")} {args} >/dev/null 2>&1 &')
 ver-.*                print('bot is running.')
 ver-.*                time.sleep(6)  # Wait 6 seconds
 ver-.*                await extract_domains()  # Try again
 ver-.*        except Exception as e:
 ver-.*            print(f'Error reading boot.log: {e}')
 ver-.*
 ver-.*# Upload nodes to subscription service
 ver-.*def upload_nodes():
 ver-.*    if UPLOAD_URL and PROJECT_URL:
 ver-.*        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
 ver-.*        json_data = {
 ver-.*            "subscription": [subscription_url]
 ver-.*        }
 ver-.*
 ver-.*        try:
 ver-.*            response = requests.post(
 ver-.*                f"{UPLOAD_URL}/api/add-subscriptions",
 ver-.*                json=json_data,
 ver-.*                headers={"Content-Type": "application/json"}
 ver-.*            )
 ver-.*
 ver-.*            if response.status_code == 200:
 ver-.*                print('Subscription uploaded successfully')
 ver-.*        except Exception as e:
 ver-.*            pass
 ver-.*
 ver-.*    elif UPLOAD_URL:
 ver-.*        if not os.path.exists(list_path):
 ver-.*            return
 ver-.*
 ver-.*        with open(list_path, 'r') as f:
 ver-.*            content = f.read()
 ver-.*
 ver-.*        nodes = [line for line in content.split('\n') if any(protocol in line for protocol in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
 ver-.*
 ver-.*        if not nodes:
 ver-.*            return
 ver-.*
 ver-.*        json_data = json.dumps({"nodes": nodes})
 ver-.*
 ver-.*        try:
 ver-.*            response = requests.post(
 ver-.*                f"{UPLOAD_URL}/api/add-nodes",
 ver-.*                data=json_data,
 ver-.*                headers={"Content-Type": "application/json"}
 ver-.*            )
 ver-.*
 ver-.*            if response.status_code == 200:
 ver-.*                print('Nodes uploaded successfully')
 ver-.*        except:
 ver-.*            return None
 ver-.*    else:
 ver-.*        return
 ver-.*
 ver-.*# Send notification to Telegram
 ver-.*def send_telegram():
 ver-.*    if not BOT_TOKEN or not CHAT_ID:
 ver-.*        # print('TG variables is empty, Skipping push nodes to TG')
 ver-.*        return
 ver-.*
 ver-.*    try:
 ver-.*        with open(sub_path, 'r') as f:
 ver-.*            message = f.read()
 ver-.*
 ver-.*        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
 ver-.*
 ver-.*        escaped_name = re.sub(r'([_*\[\]()~>#+=|{}.!\-])', r'\\\1', NAME)
 ver-.*
 ver-.*        params = {
 ver-.*            "chat_id": CHAT_ID,
 ver-.*            "text": f"**{escaped_name}节点推送通知**\n{message}",
 ver-.*            "parse_mode": "MarkdownV2"
 ver-.*        }
 ver-.*
 ver-.*        requests.post(url, params=params)
 ver-.*        print('Telegram message sent successfully')
 ver-.*    except Exception as e:
 ver-.*        print(f'Failed to send Telegram message: {e}')
 ver-.*
 ver-.*# Generate links and subscription content
 ver-.*async def generate_links(argo_domain):
 ver-.*    meta_info = subprocess.run(['curl', '-s', 'https://speed.cloudflare.com/meta'], capture_output=True, text=True)
 ver-.*    meta_info = meta_info.stdout.split('"')
 ver-.*    ISP = f"{meta_info[25]}-{meta_info[17]}".replace(' ', '_').strip()
 ver-.*
 ver-.*    time.sleep(2)
 ver-.*    VMESS = {"v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID, "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": argo_domain, "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": argo_domain, "alpn": "", "fp": "chrome"}
 ver-.*
 ver-.*    list_txt = f"""
 ver-.*vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}
 ver-.*
 ver-.*vmess://{ base64.b64encode(json.dumps(VMESS).encode('utf-8')).decode('utf-8')}
 ver-.*
 ver-.*trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
 ver-.*    """
 ver-.*
 ver-.*    with open(os.path.join(FILE_PATH, 'list.txt'), 'w', encoding='utf-8') as list_file:
 ver-.*        list_file.write(list_txt)
 ver-.*
 ver-.*    sub_txt = base64.b64encode(list_txt.encode('utf-8')).decode('utf-8')
 ver-.*    with open(os.path.join(FILE_PATH, 'sub.txt'), 'w', encoding='utf-8') as sub_file:
 ver-.*        sub_file.write(sub_txt)
 ver-.*
 ver-.*    print(sub_txt)
 ver-.*
 ver-.*    print(f"{FILE_PATH}/sub.txt saved successfully")
 ver-.*
 ver-.*    # Additional actions
 ver-.*    send_telegram()
 ver-.*    upload_nodes()
 ver-.*
 ver-.*    return sub_txt
 ver-.*
 ver-.*# Add automatic access task
 ver-.*def add_visit_task():
 ver-.*    if not AUTO_ACCESS or not PROJECT_URL:
 ver-.*        print("Skipping adding automatic access task")
 ver-.*        return
 ver-.*
 ver-.*    try:
 ver-.*        response = requests.post(
 ver-.*            'https://keep.gvrander.eu.org/add-url',
 ver-.*            json={"url": PROJECT_URL},
 ver-.*            headers={"Content-Type": "application/json"}
 ver-.*        )
 ver-.*        print('automatic access task added successfully')
 ver-.*    except Exception as e:
 ver-.*        print(f'Failed to add URL: {e}')
 ver-.*
 ver-.*# Clean up files after 90 seconds
 ver-.*def clean_files():
 ver-.*    def _cleanup():
 ver-.*        time.sleep(90)  # Wait 90 seconds
 ver-.*        files_to_delete = [boot_log_path, config_path, list_path, web_path, bot_path, php_path, npm_path]
 ver-.*
 ver-.*        if NEZHA_PORT:
 ver-.*            files_to_delete.append(npm_path)
 ver-.*        elif NEZHA_SERVER and NEZHA_KEY:
 ver-.*            files_to_delete.append(php_path)
 ver-.*
 ver-.*        for file in files_to_delete:
 ver-.*            try:
 ver-.*                if os.path.exists(file):
 ver-.*                    if os.path.isdir(file):
 ver-.*                        shutil.rmtree(file)
 ver-.*                    else:
 ver-.*                        os.remove(file)
 ver-.*            except:
 ver-.*                pass
 ver-.*
 ver-.*        print('\033c', end='')
 ver-.*        print('App is running')
 ver-.*        print('Thank you for using this script, enjoy!')
 ver-.*
 ver-.*    threading.Thread(target=_cleanup, daemon=True).start()
 ver-.*
 ver-.*# Main function to start the server
 ver-.*async def start_server():
 ver-.*    delete_nodes()
 ver-.*    cleanup_old_files()
 ver-.*    create_directory()
 ver-.*    argo_type()
 ver-.*    await download_files_and_run()
 ver-.*    add_visit_task()
 ver-.*
 ver-.*    # --- MODIFICATION 3: Removed the thread that starts the python server ---
 ver-.*    # The server_thread code block has been deleted.
 ver-.*
 ver-.*    clean_files()
 ver-.*    print("Running done!")
 ver-.*    print(f"\nLogs will be deleted in 90 seconds")
 ver-.*
 ver-.*
 ver-.*def run_async():
 ver-.*    loop = asyncio.new_event_loop()
 ver-.*    asyncio.set_event_loop(loop)
 ver-.*    loop.run_until_complete(start_server())
 ver-.*
 ver-.*    # This loop keeps the main python script alive, which is necessary for the background processes to continue running.
 ver-.*    while True:
 ver-.*        time.sleep(3600)
 ver-.*
 ver-.*if __name__ == "__main__":
 ver-.*    run_async()
