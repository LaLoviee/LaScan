import requests
import config
import sys
import json
import urllib3
import os
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.dont_write_bytecode = True

heavy_scan_acunetix_target_log = "Logs/heavy_scan_acunetix_target_log.json"
os.makedirs("Logs", exist_ok=True)

apikey = config.ACUNETIX_API_KEY
host = config.HOST.rstrip('/')
headers = {
    "X-Auth": apikey,
    "Content-Type": "application/json"
}

DEFAULT_SCAN_PROFILES = {
    "Full Scan": "11111111-1111-1111-1111-111111111111",
    "High Risk": "11111111-1111-1111-1111-111111111112",
    "SQL Injection": "11111111-1111-1111-1111-111111111113",
    "Weak Passwords": "11111111-1111-1111-1111-111111111115",
    "XSS": "11111111-1111-1111-1111-111111111116",
    "Crawl Only": "11111111-1111-1111-1111-111111111117"
}

def AddTarget(ListTarget: list, group: str = None) -> list:
    """Tambahkan list target ke Acunetix dengan opsi target group."""
    if not ListTarget:
        return []
    groups = [group] if (group and group != "") else []
    data = {
        "targets": ListTarget,
        "groups": groups
    }
    try:
        response = requests.post(f"{host}/api/v1/targets/add", json=data, headers=headers, verify=False, timeout=30)
        if response.status_code in (200, 201):
            json_response = response.json()
            return json_response.get('targets', [])
        else:
            print(f"[ERROR] - AddTarget failed ({response.status_code}): {response.text}")
            return []
    except Exception as e:
        print(f"[ERROR] - AddTarget exception: {e}")
        return []

def AddGroup(GroupName: str) -> str:
    """Buat target group atau gunakan group yang sudah ada jika sudah terdaftar."""
    try:
        # Cek apakah group sudah ada sebelumnya
        res = requests.get(f"{host}/api/v1/target_groups?q=text_search:*{GroupName};", headers=headers, verify=False, timeout=15)
        if res.status_code == 200:
            existing_groups = res.json().get('groups', [])
            for grp in existing_groups:
                if grp.get('name') == GroupName:
                    return grp.get('group_id')
    except Exception as e:
        print(f"[WARN] - Check existing group error: {e}")

    count = 0
    while count < 10:
        name = GroupName if count == 0 else f"{GroupName} ({count})"
        json_data = {
            'name': name,
            'description': 'Created by Telegram Bot',
        }
        try:
            response = requests.post(f"{host}/api/v1/target_groups", headers=headers, json=json_data, verify=False, timeout=15)
            if response.status_code in (200, 201):
                return response.json().get('group_id')
            elif response.status_code == 409:
                count += 1
            else:
                print(f"[ERROR] - AddGroup ({response.status_code}): {response.text}")
                return None
        except Exception as e:
            print(f"[ERROR] - AddGroup exception: {e}")
            return None
    return None

def GetListTarget(never_scan: str = 'never_scanned', target_address: str = None, target_group: str = None, limit: int = 50) -> list:
    """Ambil list target dari Acunetix berdasarkan filter.
    Memperbaiki bug query string 'group_id:;' yang sebelumnya memfilter keluar semua target dalam group.
    """
    query_parts = []
    if never_scan:
        query_parts.append(never_scan)
    if target_address:
        query_parts.append(f"text_search:*{target_address}")
    if target_group:
        query_parts.append(f"group_id:{target_group}")
    
    query = ";".join(query_parts)
    if query:
        query += ";"

    url = f"{host}/api/v1/targets?l={limit}"
    if query:
        url += f"&q={query}"

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=20)
        if response.status_code == 200:
            json_response = response.json()
            result_list = []
            for target in json_response.get("targets", []):
                address = target.get("address")
                target_id = target.get("target_id")
                if address and target_id:
                    result_list.append({"address": address, "target_id": target_id})
            return result_list
        else:
            print(f"[ERROR] - GetListTarget failed ({response.status_code}): {response.text}")
            return []
    except Exception as e:
        print(f"[ERROR] - GetListTarget exception: {e}")
        return []

def GetTargetsLeft() -> int:
    """Mengembalikan jumlah target yang berstatus never_scanned."""
    try:
        response = requests.get(f"{host}/api/v1/targets?l=1&q=never_scanned;", headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            return response.json().get('pagination', {}).get('count', 0)
    except Exception as e:
        print(f"[ERROR] - GetTargetsLeft: {e}")
    return 0

def StartScan(target_id: str, profile_id: str = None) -> bool:
    """Mulai proses scanning pada target di Acunetix.
    Memperbaiki format boolean (False bukan 'false') dan kompatibilitas Acunetix 24.x (user_authorized_to_scan).
    """
    if not profile_id or profile_id.startswith('xxx') or profile_id == 'None':
        profile_id = GetValidScanProfileId()

    json_data = {
        'profile_id': profile_id,
        'incremental': False,
        'schedule': {
            'disable': False,
            'start_date': None,
            'time_sensitive': False,
        },
        'target_id': target_id,
        'user_authorized_to_scan': 'yes'
    }

    try:
        response = requests.post(f"{host}/api/v1/scans", headers=headers, json=json_data, verify=False, timeout=20)
        if response.status_code in (200, 201):
            print(f"[SUCCESS] - Acunetix.StartScan: Target {target_id} scan started successfully.")
            return True
        elif response.status_code == 409:
            print(f"[WARN] - Acunetix.StartScan 409 Conflict: Target {target_id} is already being scanned.")
            return False
        else:
            print(f"[ERROR] - Acunetix.StartScan ({response.status_code}): {response.text}")
            return False
    except Exception as e:
        print(f"[ERROR] - Acunetix.StartScan exception: {e}")
        return False

def update_scan_profile_id(start_with: str, new_id: str) -> None:
    """Update SCAN_PROFILE_ID di config.py."""
    if not new_id:
        return
    config.SCAN_PROFILE_ID = new_id
    file_path = 'config.py'
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            for i, line in enumerate(lines):
                if line.strip().startswith(f"{start_with}"):
                    lines[i] = f"{start_with} = '{new_id}'\n"
                    break
            with open(file_path, 'w', encoding='utf-8') as file:
                file.writelines(lines)
    except Exception as e:
        print(f"[WARN] - update_scan_profile_id error: {e}")

def AddScanProfile() -> str:
    """Menambahkan custom scan profile ke Acunetix jika didukung."""
    scan_profile_payload = getattr(config, 'SCAN_PROFILE', None)
    if not scan_profile_payload:
        return None
    try:
        response = requests.post(f"{host}/api/v1/scanning_profiles", headers=headers, json=scan_profile_payload, verify=False, timeout=20)
        if response.status_code in (200, 201):
            return response.json().get('profile_id')
    except Exception as e:
        print(f"[ERROR] - AddScanProfile: {e}")
    return None

def GetValidScanProfileId() -> str:
    """Menemukan profile_id yang valid dan dapat digunakan di Acunetix.
    Mencegah bug profile_id None atau placeholder 'xxxxxxxx' yang menyebabkan scan gagal.
    """
    configured = getattr(config, 'SCAN_PROFILE_ID', '')
    if configured and not configured.startswith('xxx') and configured != 'None' and len(configured) > 10:
        return configured

    try:
        response = requests.get(f"{host}/api/v1/scanning_profiles", headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            profiles = response.json().get('scanning_profiles', [])
            for p in profiles:
                if p.get('name') == 'AcuScan Auto Profile':
                    pid = p.get('profile_id')
                    update_scan_profile_id('SCAN_PROFILE_ID', pid)
                    return pid
            for p in profiles:
                if p.get('name') == 'Full Scan':
                    pid = p.get('profile_id')
                    update_scan_profile_id('SCAN_PROFILE_ID', pid)
                    return pid
    except Exception as e:
        print(f"[WARN] - GetValidScanProfileId exception: {e}")

    fallback = DEFAULT_SCAN_PROFILES["Full Scan"]
    update_scan_profile_id('SCAN_PROFILE_ID', fallback)
    return fallback

def CheckScanProfile() -> str:
    return GetValidScanProfileId()

def SortBySeverity(data: list) -> list:
    return sorted(data, key=lambda x: x.get("severity", 0), reverse=True)

def GetVulnType() -> list:
    try:
        response = requests.get(f"{host}/api/v1/vulnerability_types?q=text_search:*", headers=headers, verify=False, timeout=20)
        if response.status_code == 200:
            json_response = response.json().get('vulnerability_types', [])
            list_vuln_type = [{"name": item.get("name"), "vt_id": item.get("vt_id"), "severity": item.get("severity")} for item in json_response]
            return SortBySeverity(list_vuln_type)
    except Exception as e:
        print(f"[ERROR] - GetVulnType: {e}")
    return []

def Format_DateTime(LastSeen: str) -> str:
    if not LastSeen:
        return ""
    plus_index = LastSeen.find('+')
    if plus_index != -1:
        return LastSeen[:plus_index] + 'Z'
    return LastSeen

def UpdateLogFile(new_datetime: str) -> None:
    if not new_datetime:
        return
    log_file_path = "Logs/last_seen_acunetix.log"
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    try:
        current_datetime_str = ""
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r', encoding='utf-8') as file:
                current_datetime_str = file.read().strip()
        if not current_datetime_str:
            with open(log_file_path, 'w', encoding='utf-8') as file:
                file.write(new_datetime)
        else:
            try:
                current_clean = current_datetime_str.rstrip('Z').split('+')[0]
                new_clean = new_datetime.rstrip('Z').split('+')[0]
                c_fmt = "%Y-%m-%dT%H:%M:%S.%f" if '.' in current_clean else "%Y-%m-%dT%H:%M:%S"
                n_fmt = "%Y-%m-%dT%H:%M:%S.%f" if '.' in new_clean else "%Y-%m-%dT%H:%M:%S"
                if datetime.strptime(new_clean, n_fmt) > datetime.strptime(current_clean, c_fmt):
                    with open(log_file_path, 'w', encoding='utf-8') as file:
                        file.write(new_datetime)
            except Exception:
                with open(log_file_path, 'w', encoding='utf-8') as file:
                    file.write(new_datetime)
    except Exception as e:
        print(f"[WARN] - UpdateLogFile error: {e}")

def GetLatestVuln(LastSeen: str = None, severity: str = '2,3,4', vt_id: str = '') -> list:
    """Ambil daftar vulnerability terbaru tanpa query rusak."""
    Formated_LastSeen = Format_DateTime(LastSeen)
    query_parts = []
    if vt_id:
        query_parts.append(f"vt_id:{vt_id}")
    if severity:
        query_parts.append(f"severity:{severity}")
    if Formated_LastSeen:
        query_parts.append(f"date:>{Formated_LastSeen}")
    query_parts.append("status:!ignored")
    query_parts.append("status:!fixed")
    query = ";".join(query_parts) + ";"

    CursorsId = ''
    List_vulns = []
    is_latest = False

    while True:
        try:
            url = f"{host}/api/v1/vulnerabilities?c={CursorsId}&l=100&q={query}&s=last_seen:desc"
            response = requests.get(url, headers=headers, verify=False, timeout=20)
            if response.status_code != 200:
                break
            json_data = response.json()
            vulns = json_data.get('vulnerabilities', [])
            if not vulns:
                break

            if not is_latest and len(vulns) > 0:
                try:
                    latest = Format_DateTime(vulns[0].get('last_seen'))
                    UpdateLogFile(latest)
                except Exception:
                    pass
                is_latest = True

            for item in vulns:
                List_vulns.append({
                    "affects_url": item.get("affects_url", ""),
                    "severity": item.get("severity", 0),
                    "confidence": item.get("confidence", 0),
                    "target_id": item.get("target_id", ""),
                    "vt_id": item.get("vt_id", ""),
                    "vt_name": item.get("vt_name", ""),
                    "vuln_id": item.get("vuln_id", "")
                })

            cursors = json_data.get('pagination', {}).get('cursors', [])
            if len(cursors) > 1:
                CursorsId = cursors[1]
            else:
                break
        except Exception as e:
            print(f"[ERROR] - GetLatestVuln exception: {e}")
            break

    return List_vulns

def GetInProcessTargets(status: str) -> dict:
    """Ambil status scan aktif / queued dari Acunetix."""
    try:
        response = requests.get(f"{host}/api/v1/scans?l=50&q=status:{status};", headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            return response.json()
        print(f"[WARN] - GetInProcessTargets ({status}) returned status {response.status_code}")
    except Exception as e:
        print(f"[ERROR] - GetInProcessTargets exception: {e}")
    return {'scans': [], 'pagination': {'count': 0}}

def get_vuln_details(vuln_id: str) -> dict:
    """Ambil detail vulnerability secara aman."""
    try:
        response = requests.get(f"{host}/api/v1/vulnerabilities/{vuln_id}", headers=headers, verify=False, timeout=20)
        if response.status_code != 200:
            return {"highlighted_text": "", "details": "", "request": ""}
        json_response = response.json()
        highlights = json_response.get('highlights') or []
        details = json_response.get('details') or ""
        request_text = json_response.get('request') or ""

        http_response = ""
        try:
            resp_http = requests.get(f"{host}/api/v1/vulnerabilities/{vuln_id}/http_response", headers=headers, verify=False, timeout=15)
            if resp_http.status_code == 200:
                http_response = resp_http.text
        except Exception:
            pass

        highlighted_text = ""
        for highlight in highlights:
            index = highlight.get("index", 0)
            length = highlight.get("length", 0)
            if length > 200:
                length = 200
            start = max(0, index - 20)
            end = min(len(http_response), index + length + 20)
            highlighted_text += f"{http_response[start:end]}\n"

        if not highlighted_text:
            highlighted_text = "No highlight snippet available\n"

        return {
            "highlighted_text": highlighted_text,
            "details": details,
            "request": request_text
        }
    except Exception as e:
        print(f"[ERROR] - get_vuln_details: {e}")
        return {"highlighted_text": "", "details": "", "request": ""}

def GetTargetScanInfo(target_address: str = None, target_id: str = None) -> dict:
    try:
        if target_id is None and target_address:
            res = requests.get(f"{host}/api/v1/targets?l=10&q=text_search:*{target_address};", headers=headers, verify=False, timeout=15)
            if res.status_code == 200:
                targets = res.json().get('targets', [])
                if targets:
                    target_id = targets[0].get('target_id')
        if target_id:
            response = requests.get(f"{host}/api/v1/scans?l=10&q=status:processing;target_id:{target_id};", headers=headers, verify=False, timeout=15)
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        print(f"[ERROR] - GetTargetScanInfo: {e}")
    return {'scans': []}

def StopScan(target_address: str = None, scan_id: str = None) -> bool:
    try:
        if scan_id is None and target_address:
            res = requests.get(f"{host}/api/v1/targets?l=10&q=text_search:*{target_address};", headers=headers, verify=False, timeout=15)
            if res.status_code == 200:
                targets = res.json().get('targets', [])
                if targets:
                    t_id = targets[0].get('target_id')
                    scan_info = requests.get(f"{host}/api/v1/scans?l=5&q=status:processing;target_id:{t_id};", headers=headers, verify=False, timeout=15)
                    if scan_info.status_code == 200:
                        scans = scan_info.json().get('scans', [])
                        if scans:
                            scan_id = scans[0].get('scan_id')
        if scan_id:
            res = requests.post(f"{host}/api/v1/scans/{scan_id}/abort", headers=headers, json={}, verify=False, timeout=15)
            return res.status_code in (200, 204)
    except Exception as e:
        print(f"[ERROR] - StopScan: {e}")
    return False

def GetDetailFromScanId(scan_id: str) -> dict:
    try:
        response = requests.get(f"{host}/api/v1/scans/{scan_id}", headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"[ERROR] - GetDetailFromScanId: {e}")
    return {}

def add_to_heavy_scan_acunetix_target_log(scan_id: str = None, target_id: str = None, target_address: str = None, is_remind: bool = True, is_auto_stop: bool = True) -> None:
    try:
        data = {'heavy_targets': {}}
        if os.path.exists(heavy_scan_acunetix_target_log):
            with open(heavy_scan_acunetix_target_log, 'r', encoding='utf-8') as file:
                data = json.load(file)

        if 'heavy_targets' not in data:
            data['heavy_targets'] = {}

        if scan_id:
            if scan_id not in data['heavy_targets']:
                data['heavy_targets'][scan_id] = {
                    'address': target_address or '',
                    'target_id': target_id or '',
                    'is_remind': is_remind,
                    'is_auto_stop': is_auto_stop
                }
            else:
                data['heavy_targets'][scan_id]['is_remind'] = is_remind
                data['heavy_targets'][scan_id]['is_auto_stop'] = is_auto_stop

        with open(heavy_scan_acunetix_target_log, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"[WARN] - add_to_heavy_scan_acunetix_target_log: {e}")

def delete_to_heavy_scan_acunetix_target_log(target_to_delete: str) -> None:
    try:
        if os.path.exists(heavy_scan_acunetix_target_log):
            with open(heavy_scan_acunetix_target_log, 'r', encoding='utf-8') as file:
                data = json.load(file)
            if 'heavy_targets' in data and target_to_delete in data['heavy_targets']:
                del data['heavy_targets'][target_to_delete]
                with open(heavy_scan_acunetix_target_log, 'w', encoding='utf-8') as file:
                    json.dump(data, file, indent=4)
    except Exception as e:
        print(f"[WARN] - delete_to_heavy_scan_acunetix_target_log: {e}")
