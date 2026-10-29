import threading
import time
import os
import logging
import concurrent.futures
import psutil
import json
import jwt
import requests
from concurrent.futures import ThreadPoolExecutor

import telegram.ext
from telegram import ParseMode, Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Updater,
    CommandHandler,
    CallbackContext,
    CallbackQueryHandler,
    ConversationHandler,
    MessageHandler,
    Filters
)

import config
import Acunetix
import AcuScan

api_key = config.TELEGRAM_API_KEY
chat_id = config.ALLOWED_USER_ID
TOKEN_EXPIRATION = getattr(config, 'TOKEN_EXPIRATION', 3600)
SECRET_KEY = getattr(config, 'SECRET_KEY', 'SECRET_KEY')
API_PORT = getattr(config, 'API_PORT', 5000)
note_file_path = 'Logs/Notes.txt'
os.makedirs("Logs", exist_ok=True)

# Inisialisasi logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logging.getLogger("telegram.vendor.ptb_urllib3.urllib3").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

updater = Updater(api_key, use_context=True)
disp = updater.dispatcher
executor = ThreadPoolExecutor(max_workers=5)
user_tokens = {}

def is_authorized(user_id: int) -> bool:
    return user_id == chat_id

def generate_token(user_id: int) -> str:
    payload = {'user_id': user_id}
    if TOKEN_EXPIRATION is not None:
        payload['exp'] = time.time() + TOKEN_EXPIRATION
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def get_api_token(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    token = generate_token(user_id)
    user_tokens[user_id] = token
    update.message.reply_text(f'Your API token:\n`{token}`', parse_mode=ParseMode.MARKDOWN)

def error_handler(update, context):
    logger.error("Exception while handling an update:", exc_info=context.error)

def start_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to use this bot!')
        return
    msg = (
        "🤖 *Acunetix Automation Bot is Online!*\n\n"
        "Gunakan perintah berikut:\n"
        "• `/add_target <domain>` - Cari subdomain via subfinder dan masukkan ke Acunetix\n"
        "• `/start_scan <target/domain>` - Mulai proses scan Acunetix\n"
        "• `/get_processing_targets` - Cek target yang sedang di-scan\n"
        "• `/list_target` - Cek daftar target yang belum di-scan\n"
        "• `/help` - Bantuan lengkap semua perintah"
    )
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

def add_target_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Format: `/add_target <domain>` (contoh: `/add_target example.com`)", parse_mode=ParseMode.MARKDOWN)
        return
    # Bersihkan input jika ada scheme
    clean_target = target.replace('http://', '').replace('https://', '').rstrip('/')
    update.message.reply_text(f'🚀 Memulai pencarian subdomain untuk *{clean_target}*...', parse_mode=ParseMode.MARKDOWN)
    threading.Thread(target=AcuScan.run_subfinder_httpx, args=(clean_target,), daemon=True).start()

def list_target_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    targets_unscanned = Acunetix.GetListTarget(never_scan='never_scanned', limit=20)
    targets_left = Acunetix.GetTargetsLeft()
    
    msg = f"📋 *Target belum di-scan di Acunetix* (Total tersisa: {targets_left}):\n\n"
    if targets_unscanned:
        for t in targets_unscanned[:15]:
            msg += f"• `{t.get('address')}`\n"
        if targets_left > 15:
            msg += f"\n_...dan {targets_left - 15} target lainnya._\n"
        msg += "\nKetik `/start_scan <target>` atau biarkan background scanner memproses secara otomatis."
    else:
        msg += "Tidak ada target yang menunggu antrean scan."
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

def print_subdomains_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Format: `/print_subdomains <domain>`", parse_mode=ParseMode.MARKDOWN)
        return
    clean_target = target.replace('http://', '').replace('https://', '').rstrip('/')
    file_path = f'Target_Logs/{clean_target}/{clean_target}_subdomains.txt'
    if not os.path.exists(file_path):
        update.message.reply_text(f'Target {clean_target} belum ada. Gunakan `/add_target {clean_target}` terlebih dahulu.')
        return
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        total = len(subdomains)
        output = f"Daftar Subdomain untuk {clean_target} (Total: {total}):\n\n"
        for sub in subdomains[:30]:
            output += f"• {sub}\n"
        if total > 30:
            output += f"\n...dan {total - 30} subdomain lainnya."
        update.message.reply_text(output, disable_web_page_preview=True)
    except Exception as e:
        update.message.reply_text(f"Error membaca subdomain: {e}")

def start_scan_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Format: `/start_scan <URL atau domain>`\nContoh: `/start_scan https://example.com` atau `/start_scan example.com`", parse_mode=ParseMode.MARKDOWN)
        return

    profile_id = Acunetix.GetValidScanProfileId()

    # Kasus 1: Target adalah Single URL (http:// atau https://)
    if target.startswith('http://') or target.startswith('https://'):
        acu_target = [{"address": target, "description": "Single target scan"}]
        created = Acunetix.AddTarget(acu_target, '')
        if created:
            target_id = created[0].get('target_id')
            if Acunetix.StartScan(target_id, profile_id):
                update.message.reply_text(f'✅ Scan Acunetix dimulai untuk target single:\n{target}', disable_web_page_preview=True)
                AcuScan.write_logs(f'[Start Scan Acunetix] - {target}', AcuScan.target_log)
            else:
                update.message.reply_text(f'❌ Gagal memulai scan untuk {target}. Cek log terminal.')
        else:
            update.message.reply_text(f'❌ Gagal mendaftarkan target {target} ke Acunetix.')

    # Kasus 2: Target adalah domain (koleksi subdomain)
    else:
        clean_target = target.replace('http://', '').replace('https://', '').rstrip('/')
        unscanned = Acunetix.GetListTarget(never_scan='never_scanned', target_address=clean_target, limit=100)
        
        if not unscanned:
            # Jika tidak ada yang match text_search, cari semua target never_scanned
            unscanned = Acunetix.GetListTarget(never_scan='never_scanned', limit=20)

        if not unscanned:
            update.message.reply_text(f'ℹ️ Tidak ada target unscanned untuk domain *{clean_target}* di Acunetix.', parse_mode=ParseMode.MARKDOWN)
            return

        update.message.reply_text(f'🔍 Menemukan {len(unscanned)} target unscanned untuk {clean_target}. Memulai scan di Acunetix...')
        started_count = 0
        for item in unscanned[:config.NUMBER_OF_TARGETS_SIMULTANEOUSLY]:
            t_id = item.get('target_id')
            addr = item.get('address')
            if Acunetix.StartScan(t_id, profile_id):
                started_count += 1
                AcuScan.write_logs(f'[Start Scan Acunetix] - {addr}', AcuScan.target_log)
                time.sleep(1)

        update.message.reply_text(
            f'🚀 Berhasil memulai/antrekan {started_count} scan di Acunetix.\n'
            f'Sisa target lainnya akan otomatis di-scan secara bergantian oleh background auto-scanner!'
        )

def set_targets_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    num_str = context.args[0] if context.args else None
    if not num_str or not num_str.isdigit():
        update.message.reply_text("Format: `/set_targets <angka>` (contoh: `/set_targets 5`)", parse_mode=ParseMode.MARKDOWN)
        return
    num = int(num_str)
    config.NUMBER_OF_TARGETS_SIMULTANEOUSLY = num
    update.message.reply_text(f'✅ Jumlah scan concurrent Acunetix diatur ke: *{num}*', parse_mode=ParseMode.MARKDOWN)
    AcuScan.write_logs(f'[Config] - Set number of targets simultaneously to {num}', AcuScan.target_log)

def stop_vuln_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    vuln_id = context.args[0] if context.args else None
    if not vuln_id:
        update.message.reply_text("Format: `/stop_vuln <vt_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    if vuln_id not in config.OUT_SCOPE_VULN_ACUNETIX:
        config.OUT_SCOPE_VULN_ACUNETIX.append(vuln_id)
    update.message.reply_text(f'✅ Dihentikan notifikasi untuk vuln type ID: `{vuln_id}`', parse_mode=ParseMode.MARKDOWN)

def auto_abort_scan_false_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Format: `/auto_abort_scan_false <scan_id atau URL>`", parse_mode=ParseMode.MARKDOWN)
        return
    if target.startswith('http://') or target.startswith('https://'):
        Acunetix.add_to_heavy_scan_acunetix_target_log(target_address=target, is_auto_stop=False)
    else:
        Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=target, is_auto_stop=False)
    update.message.reply_text(f'✅ Auto-abort dinonaktifkan untuk target: `{target}`', parse_mode=ParseMode.MARKDOWN)

def auto_abort_scan_true_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Format: `/auto_abort_scan_true <scan_id atau URL>`", parse_mode=ParseMode.MARKDOWN)
        return
    if target.startswith('http://') or target.startswith('https://'):
        Acunetix.add_to_heavy_scan_acunetix_target_log(target_address=target, is_auto_stop=True)
    else:
        Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=target, is_auto_stop=True)
    update.message.reply_text(f'✅ Auto-abort diaktifkan untuk target: `{target}`', parse_mode=ParseMode.MARKDOWN)

def ram_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    mem = psutil.virtual_memory()
    msg = f"💻 *System Resource*\nMemory Usage: {mem.percent}%\nTotal: {round(mem.total / (1024**3), 2)} GB\nAvailable: {round(mem.available / (1024**3), 2)} GB"
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

def get_processing_targets_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    in_process = Acunetix.GetInProcessTargets('processing')
    queued = Acunetix.GetInProcessTargets('queued')

    scans_proc = in_process.get('scans', [])
    scans_queue = queued.get('scans', [])
    target_left = Acunetix.GetTargetsLeft()

    msg = (
        f"📊 *Status Scan Acunetix*\n"
        f"• Processing: {len(scans_proc)} / {config.NUMBER_OF_TARGETS_SIMULTANEOUSLY}\n"
        f"• Queued: {len(scans_queue)}\n"
        f"• Unscanned Targets Left: {target_left}\n\n"
    )

    if not scans_proc and not scans_queue:
        msg += "Tidak ada scan yang sedang berjalan saat ini."
    else:
        for sc in scans_proc:
            t_obj = sc.get('target', {})
            addr = t_obj.get('address', 'Unknown')
            sc_id = sc.get('scan_id', '')
            session = sc.get('current_session', {})
            start_d = session.get('start_date')
            time_sc = AcuScan.compare_datetime_with_current(start_d)
            vuln_counts = session.get('severity_counts', {})
            msg += (
                f"🎯 *Target*: {addr}\n"
                f"• Scan ID: `{sc_id}`\n"
                f"• Durasi: ~{time_sc} jam\n"
                f"• Findings: {json.dumps(vuln_counts)}\n"
                f"• Hentikan: `/stop_scan_acunetix {sc_id}`\n\n"
            )

    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

def stop_scan_acunetix_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    scan_id = context.args[0] if context.args else None
    if not scan_id:
        update.message.reply_text("Format: `/stop_scan_acunetix <scan_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    keyboard = [
        [
            InlineKeyboardButton("Ya, Hentikan", callback_data=f"stop_scan_yes:{scan_id}"),
            InlineKeyboardButton("Batal", callback_data="stop_scan_no")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text(f"Konfirmasi: Apakah Anda yakin ingin membatalkan scan `{scan_id}`?", reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

def button_click_stop_scan(update: Update, context: CallbackContext):
    query = update.callback_query
    data = query.data.split(':')
    action = data[0]
    scan_id = data[1] if len(data) > 1 else None
    if action == 'stop_scan_yes' and scan_id:
        success = Acunetix.StopScan(scan_id=scan_id)
        Acunetix.delete_to_heavy_scan_acunetix_target_log(scan_id)
        if success:
            query.edit_message_text(f"🛑 Scan `{scan_id}` berhasil dihentikan.", parse_mode=ParseMode.MARKDOWN)
            AcuScan.write_logs(f'[Acunetix Scan] - Manual aborted scan {scan_id}', AcuScan.target_log)
        else:
            query.edit_message_text(f"⚠️ Gagal menghentikan scan `{scan_id}` atau scan sudah selesai.", parse_mode=ParseMode.MARKDOWN)
    else:
        query.edit_message_text("Tindakan dibatalkan.")

def get_list_vulns_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    update.message.reply_text('⏳ Mengambil daftar vulnerability dari Acunetix...')
    try:
        args = context.args
        severity = args[0] if len(args) > 0 else '2,3,4'
        target_filter = args[1] if len(args) > 1 else ''
        vulns = Acunetix.GetLatestVuln(severity=severity)
        if not vulns:
            update.message.reply_text("Tidak ditemukan vulnerability untuk filter tersebut.")
            return

        sev_labels = {1: '[Low]', 2: '[Medium]', 3: '[High]', 4: '[Critical]'}
        msg = f"🛡️ *Daftar Temuan Vulnerability* (Total: {len(vulns)}):\n\n"
        for v in vulns[:10]:
            s_label = sev_labels.get(v.get('severity'), '[Info]')
            msg += (
                f"*{s_label} - {v.get('vt_name')}*\n"
                f"Target: {v.get('affects_url')}\n"
                f"Detail: `/vuln_detail {v.get('vuln_id')}`\n\n"
            )
        update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    except Exception as e:
        update.message.reply_text(f"Error: {e}")

def convert_severity(severity: int) -> str:
    mapping = {0: '[Info]', 1: '[Low]', 2: '[Medium]', 3: '[High]', 4: '[Critical]'}
    return mapping.get(severity, '[Unknown]')

def vuln_detail_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    vuln_id = context.args[0] if context.args else None
    if not vuln_id:
        update.message.reply_text("Format: `/vuln_detail <vuln_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        url = f"{AcuScan.Acunetix.host}/api/v1/vulnerabilities/{vuln_id}"
        resp = requests.get(url, headers=AcuScan.Acunetix.headers, verify=False, timeout=15)
        if resp.status_code != 200:
            update.message.reply_text(f"Gagal mengambil detail vulnerability `{vuln_id}`")
            return
        data = resp.json()
        sev = convert_severity(data.get('severity', 0))
        details = Acunetix.get_vuln_details(vuln_id)
        msg = (
            f"*{sev} - {data.get('vt_name')}*\n"
            f"Target: {data.get('affects_url')}\n"
            f"CVSS Score: {data.get('cvss_score', '-')}\n"
            f"----------------------\n"
            f"Details:\n{AcuScan.replace_markdown_message(details.get('details', '')[:300])}\n"
            f"----------------------\n"
            f"Request Sample:\n`{details.get('request', '')[:200]}`"
        )
        update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    except Exception as e:
        update.message.reply_text(f"Error: {e}")

def vuln_type_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    v_type = context.args[0] if context.args else None
    if not v_type or not v_type.isdigit():
        update.message.reply_text("Format: `/vuln_type <1-4>` (1: Low, 2: Medium, 3: High, 4: Critical)", parse_mode=ParseMode.MARKDOWN)
        return
    severity_int = int(v_type)
    all_types = Acunetix.GetVulnType()
    filtered = [item for item in all_types if item.get('severity') == severity_int]
    msg = f"Daftar Vuln Types ({convert_severity(severity_int)}):\n\n"
    for item in filtered[:15]:
        msg += f"• {item.get('name')}\n  ID: `{item.get('vt_id')}`\n"
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

def search_by_vuln_type_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    vt_id = context.args[0] if context.args else None
    if not vt_id:
        update.message.reply_text("Format: `/search_by_vuln_type <vt_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    vulns = Acunetix.GetLatestVuln(vt_id=vt_id, severity='0,1,2,3,4')
    if not vulns:
        update.message.reply_text(f"Tidak ada temuan untuk vt_id: `{vt_id}`", parse_mode=ParseMode.MARKDOWN)
        return
    msg = f"Temuan untuk `{vt_id}` ({len(vulns)} hasil):\n\n"
    for item in vulns[:10]:
        msg += f"• {item.get('affects_url')}\n  Vuln ID: `/vuln_detail {item.get('vuln_id')}`\n"
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

def search_vuln_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    query = " ".join(context.args) if context.args else ""
    try:
        url = f"{AcuScan.Acunetix.host}/api/v1/vulnerability_types?q=text_search:*{query}*;"
        res = requests.get(url, headers=AcuScan.Acunetix.headers, verify=False, timeout=15)
        if res.status_code == 200:
            types = res.json().get('vulnerability_types', [])
            msg = f"Hasil pencarian vuln '{query}':\n\n"
            for t in types[:10]:
                msg += f"• {t.get('name')}\n  vt_id: `{t.get('vt_id')}`\n"
            update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        update.message.reply_text(f"Error: {e}")

def notification_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    status_str = context.args[0] if context.args else None
    if not status_str or status_str.lower() not in ('true', 'false'):
        curr = getattr(config, 'NOTIFICATION', False)
        update.message.reply_text(f"Format: `/notification <True/False>`\nStatus saat ini: *{curr}*", parse_mode=ParseMode.MARKDOWN)
        return
    new_status = (status_str.lower() == 'true')
    config.NOTIFICATION = new_status
    update.message.reply_text(f"✅ Notifikasi vulnerability realtime diatur ke: *{new_status}*", parse_mode=ParseMode.MARKDOWN)

def manual_activate_auto_scan_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    threading.Thread(target=AcuScan.get_new_vuln_acunetix, daemon=True).start()
    update.message.reply_text('🚀 Manual activate auto scanner thread started!')

def read_note_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    if os.path.exists(note_file_path):
        with open(note_file_path, "r", encoding="utf-8") as f:
            content = f.read()
        update.message.reply_text(content if content else "Belum ada catatan.")
    else:
        update.message.reply_text("Belum ada catatan.")

def note_command(update: Update, context: CallbackContext):
    update.message.reply_text("Ketikkan catatan Anda:")
    return 1

def save_note(update: Update, context: CallbackContext):
    note = update.message.text
    if note:
        AcuScan.write_logs(f"[Note]: {note}", note_file_path)
        update.message.reply_text("✅ Catatan tersimpan.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

def help_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_authorized(user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    help_text = (
        "📖 *Daftar Perintah Acunetix Telegram Bot:*\n\n"
        "• `/start` - Tes bot online\n"
        "• `/add_target <domain>` - Cari subdomain via subfinder lalu masukkan ke target group Acunetix\n"
        "• `/start_scan <target>` - Mulai scan di Acunetix (URL single atau domain)\n"
        "• `/list_target` - Lihat target yang belum di-scan\n"
        "• `/get_processing_targets` - Lihat target yang sedang di-scan saat ini\n"
        "• `/set_targets <angka>` - Atur batas concurrent target scan\n"
        "• `/print_subdomains <domain>` - Tampilkan list subdomain dari file\n"
        "• `/stop_scan_acunetix <scan_id>` - Hentikan scan Acunetix\n"
        "• `/get_list_vulns` - Lihat temuan vulnerability\n"
        "• `/vuln_detail <vuln_id>` - Lihat detail lengkap vulnerability\n"
        "• `/vuln_type <1-4>` - Lihat tipe vulnerability berdasarkan severity\n"
        "• `/search_by_vuln_type <vt_id>` - Cari target dengan tipe vuln tertentu\n"
        "• `/stop_vuln <vt_id>` - Abaikan notifikasi untuk tipe vuln tertentu\n"
        "• `/notification <True/False>` - Hidupkan/matikan notifikasi real-time\n"
        "• `/manual_activate_auto_scan` - Jalankan ulang background scanner jika sempat terhenti\n"
        "• `/ram` - Tampilkan penggunaan memory RAM server"
    )
    update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

def run_flask_api():
    try:
        from api import app
        app.run(host='0.0.0.0', port=API_PORT)
    except Exception as e:
        print(f"[ERROR] - Flask API error: {e}")

def run_telegram_bot():
    disp.add_handler(CommandHandler("start", start_command))
    disp.add_handler(CommandHandler("help", help_command))
    disp.add_handler(CommandHandler("add_target", add_target_command))
    disp.add_handler(CommandHandler("start_scan", start_scan_command))
    disp.add_handler(CommandHandler("set_targets", set_targets_command))
    disp.add_handler(CommandHandler("list_target", list_target_command))
    disp.add_handler(CommandHandler("print_subdomains", print_subdomains_command))
    disp.add_handler(CommandHandler("stop_vuln", stop_vuln_command))
    disp.add_handler(CommandHandler("auto_abort_scan_true", auto_abort_scan_true_command))
    disp.add_handler(CommandHandler("auto_abort_scan_false", auto_abort_scan_false_command))
    disp.add_handler(CommandHandler("ram", ram_command))
    disp.add_handler(CommandHandler("get_processing_targets", get_processing_targets_command))
    disp.add_handler(CommandHandler("stop_scan_acunetix", stop_scan_acunetix_command))
    disp.add_handler(CommandHandler("get_list_vulns", get_list_vulns_command))
    disp.add_handler(CommandHandler("vuln_detail", vuln_detail_command))
    disp.add_handler(CommandHandler("vuln_type", vuln_type_command))
    disp.add_handler(CommandHandler("search_by_vuln_type", search_by_vuln_type_command))
    disp.add_handler(CommandHandler("read_note", read_note_command))
    disp.add_handler(CommandHandler("manual_activate_auto_scan", manual_activate_auto_scan_command))
    disp.add_handler(CommandHandler("search_vuln", search_vuln_command))
    disp.add_handler(CommandHandler("get_api_token", get_api_token))
    disp.add_handler(CommandHandler("notification", notification_command))
    disp.add_handler(CallbackQueryHandler(button_click_stop_scan))

    note_handler = ConversationHandler(
        entry_points=[CommandHandler("note", note_command)],
        states={
            1: [MessageHandler(Filters.text & ~Filters.command, save_note)]
        },
        fallbacks=[]
    )
    disp.add_handler(note_handler)
    disp.add_error_handler(error_handler)

    print("🤖 Telegram Bot Polling started...")
    updater.start_polling()
    updater.idle()

def main() -> None:
    if getattr(config, 'API_SERVER', False):
        with ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(run_telegram_bot)
            ex.submit(run_flask_api)
    else:
        run_telegram_bot()

if __name__ == "__main__":
    main()
