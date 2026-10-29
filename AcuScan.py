import os
import subprocess
import config
import json
import Acunetix
from datetime import datetime
import telegram
from telegram import ParseMode
import threading
import time
import html
import re

target_log = "Logs/target.log"
current_target_log = "Logs/current_target.json"
heavy_scan_acunetix_target_log = "Logs/heavy_scan_acunetix_target_log.json"
os.makedirs("Logs", exist_ok=True)
os.makedirs("Target_Logs", exist_ok=True)

out_scope_vuln_nuclei = getattr(config, 'OUT_SCOPE_VULN_NUCLEI', [])
out_scope_vuln_acunetix = getattr(config, 'OUT_SCOPE_VULN_ACUNETIX', [])

api_key = config.TELEGRAM_API_KEY
chat_id = config.ALLOWED_USER_ID
is_scan_dead = False

# Gunakan instance telegram.Bot tunggal untuk mengirim notifikasi tanpa bentrok polling
bot = telegram.Bot(token=api_key)

def send_message(msg: str) -> None:
    try:
        bot.send_message(chat_id=chat_id, text=msg, disable_web_page_preview=True)
    except Exception as e:
        print(f"[ERROR] - send_message: {e}")

def send_message_markdown(msg: str) -> None:
    try:
        bot.send_message(chat_id=chat_id, text=msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    except Exception as e:
        print(f"[ERROR] - send_message_markdown: {e}")

def send_html_message(html_content: str) -> None:
    modified_html_content = html_content.replace('<span ', '<span class="tg-spoiler" ')
    modified_html_content = modified_html_content.replace('<br/>', '\n')
    modified_html_content = re.sub(r'<\s*p[^>]*>', '', modified_html_content)
    modified_html_content = re.sub(r'<\s*/\s*p\s*>', '', modified_html_content)
    try:
        bot.send_message(chat_id=chat_id, text=modified_html_content, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as e:
        print(f"[ERROR] - send_html_message: {e}")

def write_logs(message: str, log_path: str) -> None:
    try:
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        content = ""
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                content = f.read()
        new_content = f"[{current_datetime}] : {message}\n{content}"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(new_content)
    except Exception as e:
        print(f"[WARN] - write_logs error: {e}")

def get_targets_not_scan_nuclei() -> list:
    false_targets = []
    try:
        if os.path.exists(current_target_log):
            with open(current_target_log, 'r', encoding='utf-8') as file:
                data = json.load(file)
            for target_name, properties in data.get('current_target', {}).items():
                if not properties.get('is_scan_nuclei'):
                    false_targets.append(target_name)
    except Exception as e:
        print(f"[WARN] - get_targets_not_scan_nuclei: {e}")
    return false_targets

def add_to_current_target_log(new_target: str, is_scan_nuclei: bool) -> None:
    try:
        data = {"current_target": {}}
        if os.path.exists(current_target_log):
            with open(current_target_log, 'r', encoding='utf-8') as file:
                data = json.load(file)
        if "current_target" not in data:
            data["current_target"] = {}
        data['current_target'][new_target] = {"is_scan_nuclei": is_scan_nuclei}
        with open(current_target_log, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"[WARN] - add_to_current_target_log: {e}")

def delete_from_current_target_log(target_to_delete: str) -> None:
    try:
        if os.path.exists(current_target_log):
            with open(current_target_log, 'r', encoding='utf-8') as file:
                data = json.load(file)
            if target_to_delete in data.get('current_target', {}):
                del data['current_target'][target_to_delete]
                with open(current_target_log, 'w', encoding='utf-8') as file:
                    json.dump(data, file, indent=4)
    except Exception as e:
        print(f"[WARN] - delete_from_current_target_log: {e}")

def is_out_scope_vuln(string: str) -> bool:
    for item in out_scope_vuln_nuclei:
        if item in string:
            return True
    return False

def check_file(file_path: str) -> bool:
    if os.path.exists(file_path):
        return os.path.getsize(file_path) > 3
    return False

def Add_Acunetix_targets(target_domain: str, description: str, group_id=None) -> None:
    """Membaca daftar subdomain dari file log dan memasukkannya ke Acunetix target group."""
    target_lists = []
    target_directory = os.path.join("Target_Logs", target_domain)
    target_file_path = os.path.join(target_directory, f"{target_domain}_subdomains.txt")
    if not os.path.exists(target_file_path):
        print(f"[WARN] - Subdomains file not found: {target_file_path}")
        return

    with open(target_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            addr = line.strip()
            if addr:
                target_lists.append({
                    'address': addr,
                    'description': description
                })

    if target_lists:
        created = Acunetix.AddTarget(target_lists, group_id)
        print(f"[INFO] - Successfully added {len(created)} targets into Acunetix group {group_id}")

def run_subfinder_httpx(target: str) -> None:
    """Menjalankan subfinder & httpx untuk mencari subdomain lalu mendaftarkannya ke Acunetix."""
    try:
        print(f'Start finding subdomains for {target}...')
        send_message(f'🔍 Mencari subdomain untuk: {target}...')
        target_directory = os.path.join("Target_Logs", target)
        os.makedirs(target_directory, exist_ok=True)
        output_file_path = os.path.join(target_directory, f"{target}_subdomains.txt")
        target_count = 0

        if not check_file(output_file_path):
            command = f"subfinder -d {target} --silent | httpx --silent"
            try:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                with open(output_file_path, "w", encoding="utf-8") as f:
                    for line in process.stdout:
                        clean_line = line.strip()
                        if clean_line:
                            f.write(f"{clean_line}\n")
                            target_count += 1
                process.wait()
            except Exception as e:
                print(f"[ERROR] - Subprocess subfinder/httpx: {e}")
                write_logs(f'[__ERROR__] - {target} - {str(e)}', target_log)
                send_message(f'❌ Error saat menjalankan subfinder/httpx: {e}')
                return

            write_logs(f'[Scan Subdomain] - {target} found {target_count} subdomains', target_log)
        else:
            with open(output_file_path, 'r', encoding='utf-8') as f:
                target_count = len([line for line in f if line.strip()])

        add_to_current_target_log(target, False)

        # Buat/ambil group di Acunetix dan masukkan targets
        group_id = Acunetix.AddGroup(f'{target} subdomains')
        Add_Acunetix_targets(target, f'Auto Scan tool for {target}', group_id)

        if target_count == 0:
            send_message(f'⚠️ Tidak ditemukan subdomain aktif untuk: {target}')
        else:
            send_message(f'✅ Berhasil menemukan {target_count} subdomain untuk: {target}\nSemua target sudah dimasukkan ke Target Group Acunetix!')
            send_message_markdown(
                f'Target akan otomatis di-scan di background (max {config.NUMBER_OF_TARGETS_SIMULTANEOUSLY} target concurrent).\n'
                f'Atau ketik `/start_scan {target}` untuk segera memicu scanning di Acunetix.'
            )
    except Exception as e:
        print(f'[ERROR] - run_subfinder_httpx: {e}')
        write_logs(f'[ERROR] - run_subfinder_httpx: {str(e)}', target_log)
        send_message(f'❌ Error in run_subfinder_httpx: {str(e)}')

def run_nuclei(target: str) -> None:
    print(f'Start scanning Nuclei for {target}...')
    write_logs(f'[Start Nuclei Scan] - {target}', target_log)
    if target.startswith('http://') or target.startswith('https://'):
        target_directory = "Target_Logs/Single_targets"
        os.makedirs(target_directory, exist_ok=True)
        command = f"nuclei -u {target} -as -nc"
        output_file_path = os.path.join(target_directory, f"{target.replace('://', '_')}_nuclei_scan_result.txt")
    else:
        target_directory = os.path.join("Target_Logs", target)
        target_file_path = os.path.join(target_directory, f"{target}_subdomains.txt")
        command = f"nuclei -l {target_file_path} -as -nc"
        output_file_path = os.path.join(target_directory, f"{target}_nuclei_scan_result.txt")
    
    send_message('Start scanning Nuclei...')
    list_vuln = ''
    is_vuln = False

    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with open(output_file_path, "w", encoding="utf-8") as f:
            for line in process.stdout:
                line_str = line.strip()
                f.write(f"{line_str}\n")
                if '[critical]' in line_str.lower():
                    is_vuln = True
                    list_vuln += f'[Nuclei] - {line_str}\n'
                    send_message(f'🚨 CRITICAL VULN for {target}: {line_str}')
                elif '[high]' in line_str.lower():
                    is_vuln = True
                    list_vuln += f'[Nuclei] - {line_str}\n'
                    send_message(f'⚠️ HIGH VULN for {target}: {line_str}')
                elif '[medium]' in line_str.lower() and not is_out_scope_vuln(line_str):
                    is_vuln = True
                    list_vuln += f'[Nuclei] - {line_str}\n'
                    send_message(f'⚡ MEDIUM VULN for {target}: {line_str}')
    except Exception as e:
        print(f"[ERROR] - run_nuclei: {e}")
        write_logs(f'[__ERROR__] - {target} - {e}', target_log)
        return

    add_to_current_target_log(target, True)
    write_logs(f'[Done Nuclei Scan] - {target}', target_log)
    if is_vuln:
        send_message(f'List Vuln from Nuclei:\n{list_vuln}')
    else:
        send_message(f'Nuclei scan completed for {target}. No Medium/High/Critical findings.')

def compare_datetime_with_current(datetime_str: str) -> int:
    """Menghitung selisih jam dari datetime ISO string secara aman."""
    if not datetime_str:
        return 0
    try:
        clean_str = datetime_str.rstrip('Z')
        if '+' in clean_str:
            clean_str = clean_str.split('+')[0]
        dt_format = "%Y-%m-%dT%H:%M:%S.%f" if '.' in clean_str else "%Y-%m-%dT%H:%M:%S"
        given_datetime = datetime.strptime(clean_str, dt_format)
        current_datetime = datetime.utcnow()
        hours_difference = (current_datetime - given_datetime).total_seconds() / 3600
        return max(0, int(hours_difference))
    except Exception as e:
        print(f"[WARN] - compare_datetime_with_current ({datetime_str}): {e}")
        return 0

def replace_markdown_message(msg: str) -> str:
    if not msg:
        return ""
    chars_to_escape = ['*', '_', '`', '[']
    for ch in chars_to_escape:
        msg = msg.replace(ch, f'\\{ch}')
    html_tags = ['<strong>', '</strong>', '<li>', '</li>', '<ul>', '</ul>', '<br/>']
    for tag in html_tags:
        msg = msg.replace(tag, '\n' if tag in ('<li>', '<br/>') else '')
    return msg

def get_new_vuln_acunetix() -> None:
    """Thread background untuk otomatis memulai scan pada target yang belum di-scan,
    mengirim notifikasi vulnerability baru, dan auto-abort jika melebihi SCAN_TIME.
    """
    global is_scan_dead
    profile_id = Acunetix.GetValidScanProfileId()
    print(f"[INFO] - Background Auto Scanner started with profile_id: {profile_id}")

    while True:
        try:
            is_scan_dead = False
            last_seen = ""
            log_file = "Logs/last_seen_acunetix.log"
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as f:
                    last_seen = f.read().strip()

            # 1. Cek vulnerability baru jika NOTIFICATION aktif
            if getattr(config, 'NOTIFICATION', False):
                list_latest_vulns = Acunetix.GetLatestVuln(last_seen)
                for vuln in list_latest_vulns:
                    vt_id = vuln.get('vt_id')
                    if vt_id not in config.OUT_SCOPE_VULN_ACUNETIX:
                        affects_url = vuln.get('affects_url')
                        confidence = vuln.get('confidence')
                        vt_name = vuln.get('vt_name')
                        vuln_id = vuln.get('vuln_id')
                        severity = vuln.get('severity')
                        sev_labels = {1: '[Low]', 2: '[Medium]', 3: '[High]', 4: '[Critical]'}
                        txt_severity = sev_labels.get(severity, '[Info]')

                        vuln_details = Acunetix.get_vuln_details(vuln_id)
                        detail_snip = html.unescape(vuln_details.get('details', '')[:300])
                        msg = (
                            f"*{txt_severity} - {vt_name}* (Confidence: {confidence})\n"
                            f"Target: {affects_url}\n"
                            f"----------------------\n"
                            f"Details:\n{replace_markdown_message(detail_snip)}\n"
                            f"----------------------\n"
                            f"To stop notification: `/stop_vuln {vt_id}`\n"
                            f"For full detail: `/vuln_detail {vuln_id}`"
                        )
                        send_message_markdown(msg)
                        time.sleep(1)

            # 2. Cek scan yang sedang berjalan (processing & queued)
            in_process_target = Acunetix.GetInProcessTargets('processing')
            queued_target = Acunetix.GetInProcessTargets('queued')

            list_in_process_targets = in_process_target.get('scans', [])
            list_queued_targets = queued_target.get('scans', [])
            running_scans_count = len(list_in_process_targets) + len(list_queued_targets)

            # Auto-abort untuk scan yang melebihi batas SCAN_TIME
            for scan in list_in_process_targets:
                scan_id = scan.get('scan_id')
                target_obj = scan.get('target', {})
                target_address = target_obj.get('address', '')
                curr_session = scan.get('current_session', {})
                start_date = curr_session.get('start_date')
                target_vulns = curr_session.get('severity_counts', {})
                time_scanned = compare_datetime_with_current(start_date)

                if time_scanned >= config.SCAN_TIME:
                    msg = (
                        f"🛑 Menghentikan scan Acunetix untuk {target_address} karena melebihi {config.SCAN_TIME} jam.\n"
                        f"Severity: {json.dumps(target_vulns, indent=2)}"
                    )
                    send_message_markdown(msg)
                    Acunetix.StopScan(scan_id=scan_id)
                    Acunetix.delete_to_heavy_scan_acunetix_target_log(scan_id)
                    write_logs(f"[Acunetix Scan] - Auto abort scan target {target_address}", target_log)

            # 3. Mulai scan otomatis untuk target never_scanned jika ada slot kosong
            simultaneous_limit = getattr(config, 'NUMBER_OF_TARGETS_SIMULTANEOUSLY', 3)
            slots_available = simultaneous_limit - running_scans_count

            if slots_available > 0:
                never_scanned_targets = Acunetix.GetListTarget(never_scan='never_scanned', limit=50)
                if never_scanned_targets:
                    targets_to_start = never_scanned_targets[:slots_available]
                    for t in targets_to_start:
                        t_id = t.get('target_id')
                        t_addr = t.get('address')
                        if Acunetix.StartScan(t_id, profile_id):
                            write_logs(f'[Acunetix Scan] - Started scan target {t_addr}', target_log)
                            send_message(f'🚀 Started Acunetix scan on target:\n{t_addr}')
                        else:
                            write_logs(f'[Acunetix Scan] - Failed to start scan target {t_addr}', target_log)
                        time.sleep(1)

            # Istirahat 60 detik sebelum iterasi berikutnya
            time.sleep(60)

        except Exception as e:
            print(f'[ERROR] - get_new_vuln_acunetix loop error: {e}')
            write_logs(f'[ERROR] - Auto scanner loop: {str(e)}', target_log)
            is_scan_dead = True
            time.sleep(30)

# Jalankan background auto scanner sebagai daemon thread
auto_scanner_thread = threading.Thread(target=get_new_vuln_acunetix, daemon=True)
auto_scanner_thread.start()
