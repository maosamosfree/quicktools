import os, logging, threading, asyncio, requests, io, base64, tempfile, urllib.parse
from io import BytesIO
from datetime import datetime, timezone
from flask import Flask, request, abort
from telegram import Update, InputFile, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes, ConversationHandler)
from PIL import Image
from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
VIRUSTOTAL_API_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")
REMOVEBG_API_KEY    = os.environ.get("REMOVEBG_API_KEY", "")
MONGODB_URI         = os.environ.get("MONGODB_URI", "")

# ==================== POLLINATIONS AI (TTI) ====================
POLLINATIONS_BASE_URL = "https://image.pollinations.ai/prompt/"

PORT                = int(os.environ.get("PORT", 10000))
ADMIN_KEY           = os.environ.get("ADMIN_KEY", "")

# ==================== MONGODB ====================
mongo_client = None
db = None

def init_mongo():
    global mongo_client, db
    if not MONGODB_URI:
        logger.warning("MONGODB_URI not set — using in-memory fallback.")
        return
    try:
        mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        mongo_client.admin.command("ping")
        db = mongo_client["quicktools"]
        db["users"].create_index("user_id", unique=True)
        db["activities"].create_index([("timestamp", DESCENDING)])
        logger.info("Connected to MongoDB Atlas.")
    except PyMongoError as e:
        logger.error(f"MongoDB failed: {e}")
        db = None

_mem_stats = {"pdf_converted":0,"virus_checked":0,"removebg_done":0,
              "ai_images_generated":0,"virus_threats_found":0,
              "bot_start_time": datetime.now(timezone.utc).isoformat()}
_mem_users = set()
_mem_activities = []
_mem_lock = threading.Lock()

def upsert_user(user):
    doc = {"user_id": user.id, "username": user.username or "",
           "first_name": user.first_name or "",
           "last_activity": datetime.now(timezone.utc).isoformat()}
    if db is not None:
        try:
            db["users"].update_one({"user_id": user.id},
                {"$set": doc, "$setOnInsert": {"join_date": datetime.now(timezone.utc).isoformat()}},
                upsert=True)
        except PyMongoError as e:
            logger.error(f"upsert_user: {e}")
    else:
        with _mem_lock:
            _mem_users.add(user.id)

def increment_stat(key, amount=1):
    if db is not None:
        try:
            db["stats"].update_one({"_id":"global"}, {"$inc":{key:amount}}, upsert=True)
        except PyMongoError as e:
            logger.error(f"increment_stat: {e}")
    else:
        with _mem_lock:
            _mem_stats[key] = _mem_stats.get(key, 0) + amount

def get_stats():
    if db is not None:
        try:
            doc = db["stats"].find_one({"_id":"global"}) or {}
            return {"pdf_converted": doc.get("pdf_converted",0),
                    "virus_checked": doc.get("virus_checked",0),
                    "removebg_done": doc.get("removebg_done",0),
                    "ai_images_generated": doc.get("ai_images_generated",0),
                    "virus_threats_found": doc.get("virus_threats_found",0),
                    "total_users": db["users"].count_documents({}),
                    "bot_start_time": doc.get("bot_start_time", _mem_stats["bot_start_time"])}
        except PyMongoError as e:
            logger.error(f"get_stats: {e}")
    with _mem_lock:
        return {**_mem_stats, "total_users": len(_mem_users)}

def record_activity(action, user, detail=""):
    upsert_user(user)
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
             "action": action, "user_id": user.id,
             "username": user.username or "",
             "user": f"@{user.username}" if user.username else f"#{user.id}",
             "detail": detail}
    if db is not None:
        try:
            db["activities"].insert_one(entry)
            count = db["activities"].count_documents({})
            if count > 500:
                oldest = db["activities"].find().sort("timestamp",1).limit(count-500)
                ids = [d["_id"] for d in oldest]
                db["activities"].delete_many({"_id":{"$in":ids}})
        except PyMongoError as e:
            logger.error(f"record_activity: {e}")
    else:
        with _mem_lock:
            _mem_activities.insert(0, entry)
            del _mem_activities[20:]

def get_recent_activities(limit=20):
    if db is not None:
        try:
            return list(db["activities"].find().sort("timestamp", DESCENDING).limit(limit))
        except PyMongoError as e:
            logger.error(f"get_recent_activities: {e}")
    with _mem_lock:
        return list(_mem_activities[:limit])

# ==================== FLASK ====================
flask_app = Flask(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuickTools KH Admin</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;600&display=swap');
  :root{--bg:#0a0a0f;--surface:#13131a;--border:#1e1e2e;--accent:#f5c518;--accent2:#ff6b35;--green:#22c55e;--red:#ef4444;--blue:#3b82f6;--purple:#a855f7;--text:#e2e8f0;--muted:#64748b;--radius:12px}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;min-height:100vh}
  nav{display:flex;align-items:center;justify-content:space-between;padding:18px 32px;border-bottom:1px solid var(--border);background:var(--surface);position:sticky;top:0;z-index:10}
  .logo{display:flex;align-items:center;gap:10px}
  .logo-text{font-size:17px;font-weight:700}.logo-text span{color:var(--accent)}
  .badges{display:flex;gap:10px;align-items:center}
  .badge-pill{display:flex;align-items:center;gap:6px;border-radius:99px;padding:5px 12px;font-size:12px;font-weight:600}
  .mongo-pill{background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.3);color:var(--purple)}
  .live-pill{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);color:var(--green)}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  main{max-width:1200px;margin:0 auto;padding:32px 24px}
  .uptime-bar{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 20px;margin-bottom:28px;font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--muted)}
  .uptime-bar strong{color:var(--accent)}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;margin-bottom:32px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px 24px;position:relative;overflow:hidden;transition:border-color .2s}
  .card:hover{border-color:var(--accent)}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--card-color,var(--accent))}
  .card-icon{font-size:28px;margin-bottom:12px}
  .card-value{font-size:36px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1;margin-bottom:4px}
  .card-label{font-size:13px;color:var(--muted);font-weight:500}
  .card-sub{font-size:11px;color:var(--muted);margin-top:8px}
  .card-pdf{--card-color:var(--blue)}.card-virus{--card-color:var(--red)}
  .card-bg{--card-color:var(--green)}.card-users{--card-color:var(--accent)}
  .card-ai{--card-color:var(--purple)}.card-threat{--card-color:var(--accent2)}
  .section-title{font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:14px;display:flex;align-items:center;gap:8px}
  .section-title::after{content:'';flex:1;height:1px;background:var(--border)}
  .table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:32px}
  table{width:100%;border-collapse:collapse}
  th{background:var(--bg);padding:12px 16px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
  td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--border);vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(255,255,255,.02)}
  .badge{display:inline-block;padding:3px 9px;border-radius:99px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace}
  .badge-pdf{background:rgba(59,130,246,.15);color:#60a5fa}
  .badge-virus{background:rgba(239,68,68,.15);color:#f87171}
  .badge-bg{background:rgba(34,197,94,.15);color:#4ade80}
  .badge-ai{background:rgba(168,85,247,.15);color:#c084fc}
  .badge-start{background:rgba(245,197,24,.10);color:#f5c518}
  .chip{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--muted)}
  .empty-row td{text-align:center;padding:32px;color:var(--muted);font-size:13px}
  .btn-refresh{display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:#000;border:none;border-radius:8px;padding:8px 16px;font-size:13px;font-weight:700;cursor:pointer;font-family:inherit}
  .top-actions{display:flex;justify-content:flex-end;margin-bottom:20px}
  footer{text-align:center;padding:24px;font-size:12px;color:var(--muted);border-top:1px solid var(--border)}
</style>
</head>
<body>
<nav>
  <div class="logo"><span style="font-size:22px">⚡</span><span class="logo-text">QuickTools <span>KH</span> — Admin</span></div>
  <div class="badges">
    <div class="badge-pill mongo-pill">🍃 MongoDB Atlas</div>
    <div class="badge-pill live-pill"><div class="dot"></div> Live</div>
  </div>
</nav>
<main>
  <div class="uptime-bar">🕐 Started: <strong>{{START_TIME}}</strong> &nbsp;·&nbsp; Refreshed: <strong id="lr">—</strong></div>
  <div class="cards">
    <div class="card card-users"><div class="card-icon">👥</div><div class="card-value">{{USER_COUNT}}</div><div class="card-label">Total Users</div><div class="card-sub">All time unique</div></div>
    <div class="card card-pdf"><div class="card-icon">📄</div><div class="card-value">{{PDF_COUNT}}</div><div class="card-label">PDFs Generated</div><div class="card-sub">Total conversions</div></div>
    <div class="card card-virus"><div class="card-icon">🔍</div><div class="card-value">{{VIRUS_COUNT}}</div><div class="card-label">Virus Scans</div><div class="card-sub">{{THREAT_COUNT}} threats found</div></div>
    <div class="card card-bg"><div class="card-icon">🖼️</div><div class="card-value">{{BG_COUNT}}</div><div class="card-label">RemoveBG</div><div class="card-sub">via remove.bg API</div></div>
    <div class="card card-ai"><div class="card-icon">🎨</div><div class="card-value">{{AI_COUNT}}</div><div class="card-label">AI Images</div><div class="card-sub">via Pollinations AI</div></div>
    <div class="card card-threat"><div class="card-icon">⚡</div><div class="card-value">{{TOTAL_ACTIONS}}</div><div class="card-label">Total Actions</div><div class="card-sub">All combined</div></div>
  </div>
  <div class="top-actions"><button class="btn-refresh" onclick="location.reload()">↻ Refresh</button></div>
  <div class="section-title">Recent Activity</div>
  <div class="table-wrap"><table>
    <thead><tr><th>Time</th><th>Action</th><th>User</th><th>Detail</th></tr></thead>
    <tbody>{{ACTIVITY_ROWS}}</tbody>
  </table></div>
</main>
<footer>⚡ QuickTools KH · MongoDB Atlas · Flask on Render</footer>
<script>
  document.getElementById('lr').textContent = new Date().toLocaleTimeString();
  setTimeout(()=>location.reload(), 30000);
</script>
</body></html>"""

def build_dashboard():
    s = get_stats()
    pdf = s.get("pdf_converted",0); virus = s.get("virus_checked",0)
    bg = s.get("removebg_done",0); ai = s.get("ai_images_generated",0)
    users = s.get("total_users",0); threats = s.get("virus_threats_found",0)
    total = pdf + virus + bg + ai
    start = str(s.get("bot_start_time",""))[:19].replace("T"," ") + " UTC"
    rows = get_recent_activities(20)
    badge_map = {"PDF":"badge-pdf","VIRUS":"badge-virus","REMOVEBG":"badge-bg","TTI":"badge-ai","START":"badge-start"}
    if rows:
        row_html = ""
        for r in rows:
            bc = badge_map.get(r.get("action",""), "badge-start")
            row_html += f"""<tr>
              <td><span class="chip">{r.get('time','')}</span></td>
              <td><span class="badge {bc}">{r.get('action','')}</span></td>
              <td><span class="chip">{r.get('user','')}</span></td>
              <td>{r.get('detail','')}</td></tr>"""
    else:
        row_html = '<tr class="empty-row"><td colspan="4">No activity yet 👀</td></tr>'
    html = DASHBOARD_HTML
    for k,v in [("{{PDF_COUNT}}",str(pdf)),("{{VIRUS_COUNT}}",str(virus)),
                ("{{BG_COUNT}}",str(bg)),("{{AI_COUNT}}",str(ai)),
                ("{{USER_COUNT}}",str(users)),("{{THREAT_COUNT}}",str(threats)),
                ("{{TOTAL_ACTIONS}}",str(total)),("{{START_TIME}}",start),
                ("{{ACTIVITY_ROWS}}",row_html)]:
        html = html.replace(k, v)
    return html

@flask_app.route("/")
def dashboard():
    if ADMIN_KEY and request.args.get("key","") != ADMIN_KEY:
        abort(403)
    return build_dashboard(), 200, {"Content-Type":"text/html; charset=utf-8"}

@flask_app.route("/health")
def health():
    return "OK", 200

@flask_app.route("/api/stats")
def api_stats():
    if ADMIN_KEY and request.args.get("key","") != ADMIN_KEY:
        abort(403)
    s = get_stats()
    return {"pdf_converted":s.get("pdf_converted",0),"virus_checked":s.get("virus_checked",0),
            "removebg_done":s.get("removebg_done",0),"ai_images_generated":s.get("ai_images_generated",0),
            "total_users":s.get("total_users",0),"virus_threats_found":s.get("virus_threats_found",0)}

# ==================== STATES ====================
COLLECTING_PHOTOS = 1
AWAITING_FILE = 2
AWAITING_PHOTO_BG = 3
TTI_AWAITING_PROMPT = 10

user_photos: dict[int, list[bytes]] = {}
user_tti_style: dict[int, str] = {}

TTI_STYLES = {
    "realistic":   ("📷 Realistic",  "ultra realistic photography, professional lighting, highly detailed, 8k"),
    "anime":       ("🎨 Anime",      "anime style, studio quality, vibrant colors"),
    "digital_art": ("🖌️ Digital Art","digital painting, concept art, masterpiece"),
    "fantasy":     ("🏰 Fantasy",    "epic fantasy artwork, cinematic lighting"),
    "scifi":       ("🚀 Sci-Fi",     "futuristic, cyberpunk, science fiction"),
}

# ==================== /start /help /cancel ====================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    record_activity("START", update.effective_user, "Started bot")
    await update.message.reply_text(
        "👋 សូមស្វាគមន៍មកកាន់ ⚡ QuickTools KH!\n\n"
        "📄 /pdf — បំប្លែងរូបភាពទៅជា PDF\n"
        "🔍 /check — ពិនិត្យមើលមេរោគ\n"
        "🖼️ /removebg — លុបផ្ទៃខាងក្រោយរូបភាព\n"
        "🎨 /tti — Text To Image (AI)\n"
        "❓ /help — ព័ត៌មានបន្ថែម")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 *ជំនួយការបច្ចេកទេស*\n\n"
        "1️⃣ /pdf — ផ្ញើរូបភាព រួចវាយ /done\n"
        "2️⃣ /check — ផ្ញើឯកសារដែលសង្ស័យ\n"
        "3️⃣ /removebg — ផ្ញើរូបភាព លុប Background\n"
        "4️⃣ /tti — ជ្រើសស្ទីល ហើយផ្ញើ prompt\n"
        "5️⃣ /cancel — បោះបង់", parse_mode="Markdown")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    user_photos.pop(user_id, None)
    user_tti_style.pop(user_id, None)
    await update.message.reply_text("❌ បានបោះបង់រួចរាល់។")
    return ConversationHandler.END

# ==================== /pdf ====================
async def start_pdf(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_photos[update.effective_user.id] = []
    await update.message.reply_text(
        "📸 សូមផ្ញើរូបភាព!\n• ផ្ញើរូបច្រើនបានតាមចិត្ត\n"
        "• វាយ /done ដើម្បីបំប្លែងទៅ PDF\n• វាយ /cancel ដើម្បីបោះបង់")
    return COLLECTING_PHOTOS

async def receive_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    uid = update.effective_user.id
    if uid not in user_photos: user_photos[uid] = []
    photo = update.message.photo[-1]
    file = await context.bot.get_file(photo.file_id)
    user_photos[uid].append(bytes(await file.download_as_bytearray()))
    count = len(user_photos[uid])
    await update.message.reply_text(f"✅ បានទទួលរូបទី {count}\n• ផ្ញើបន្ថែម ឬ /done")
    return COLLECTING_PHOTOS

async def receive_document_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    uid = update.effective_user.id
    if uid not in user_photos: user_photos[uid] = []
    doc = update.message.document
    if doc.mime_type and doc.mime_type.startswith("image/"):
        file = await context.bot.get_file(doc.file_id)
        user_photos[uid].append(bytes(await file.download_as_bytearray()))
        await update.message.reply_text(f"✅ បានទទួលរូបទី {len(user_photos[uid])}\n• ផ្ញើបន្ថែម ឬ /done")
    else:
        await update.message.reply_text("❌ សូមផ្ញើតែរូបភាព!")
    return COLLECTING_PHOTOS

async def convert_to_pdf(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    uid = update.effective_user.id
    if uid not in user_photos or not user_photos[uid]:
        await update.message.reply_text("❌ មិនទាន់មានរូបភាពទេ!")
        return COLLECTING_PHOTOS
    photos = user_photos[uid]; count = len(photos)
    status_msg = await update.message.reply_text(f"⏳ កំពុងបំប្លែង {count} រូប...")
    try:
        images = []
        for pb in photos:
            img = Image.open(io.BytesIO(pb))
            if img.mode != "RGB": img = img.convert("RGB")
            images.append(img)
        buf = io.BytesIO()
        images[0].save(buf, format="PDF", save_all=True, append_images=images[1:], resolution=150)
        buf.seek(0)
        await status_msg.delete()
        await update.message.reply_document(
            document=InputFile(buf, filename="converted.pdf"),
            caption=f"✅ PDF បំប្លែងជោគជ័យ!\n📄 ចំនួនទំព័រ: {count}")
        increment_stat("pdf_converted")
        record_activity("PDF", update.effective_user, f"{count} page(s)")
    except Exception as e:
        logger.error(f"PDF error: {e}")
        await update.message.reply_text(f"❌ មានបញ្ហា: {str(e)}")
    finally:
        user_photos.pop(uid, None)
    return ConversationHandler.END

# ==================== /check ====================
async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("🔍 សូមផ្ញើឯកសារ (File/Document) ដើម្បីពិនិត្យ។")
    return AWAITING_FILE

async def handle_virus_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    document = update.message.document
    user = update.effective_user
    if not document:
        await update.message.reply_text("❌ សូមផ្ញើជាឯកសារ (Document)។")
        return ConversationHandler.END
    file_name = document.file_name.lower()
    file_size_mb = document.file_size / (1024 * 1024)
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    if file_size_mb > 20:
        status_msg = await update.message.reply_text(
            f"📦 ឯកសារធំ ({file_size_mb:.2f} MB)...\n🔍 កំពុងឆែក Database...")
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/search?query={document.file_name}", headers=headers)
            if r.status_code == 200:
                data = r.json()
                if data.get('data') and len(data['data']) > 0:
                    mal = data['data'][0]['attributes'].get('last_analysis_stats',{}).get('malicious',0)
                    if mal > 0:
                        increment_stat("virus_threats_found")
                        await status_msg.edit_text(f"🚨 រកឃើញមេរោគ! ប្រព័ន្ធ {mal} បានបញ្ជាក់!")
                        record_activity("VIRUS", user, f"THREAT: {document.file_name}")
                        increment_stat("virus_checked")
                        return ConversationHandler.END
            if file_name.endswith(('.exe','.scr','.pif','.bat','.cmd','.msi','.vbs')):
                increment_stat("virus_threats_found")
                await status_msg.edit_text("🚨 ការព្រមាន! ឯកសារ .exe ធំ — គួរប្រុងប្រយ័ត្ន!")
                record_activity("VIRUS", user, f"SUSPICIOUS: {document.file_name}")
            else:
                await status_msg.edit_text(f"ℹ️ {file_size_mb:.2f}MB — គ្មានប្រវត្តិអាក្រក់ក្នុង DB។")
                record_activity("VIRUS", user, f"CLEAN: {document.file_name}")
        except Exception:
            await status_msg.edit_text("❌ មានបញ្ហាក្នុងការឆែក Database។")
        increment_stat("virus_checked")
        return ConversationHandler.END
    status_msg = await update.message.reply_text("⏳ កំពុងទាញយកឯកសារ...")
    try:
        tg_file = await context.bot.get_file(document.file_id)
        file_bytes = bytes(await tg_file.download_as_bytearray())
        r = requests.post("https://www.virustotal.com/api/v3/files", headers=headers,
                          files={"file": (document.file_name, file_bytes)})
        if r.status_code == 200:
            analysis_id = r.json()['data']['id']
            await asyncio.sleep(2)
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            mal = report['data']['attributes']['stats'].get('malicious', 0)
            if mal > 0:
                increment_stat("virus_threats_found")
                await status_msg.edit_text(f"🚨 រកឃើញមេរោគ! ប្រព័ន្ធ {mal} បានរាយការណ៍!")
                record_activity("VIRUS", user, f"THREAT: {document.file_name}")
            else:
                await status_msg.edit_text("✅ ឯកសារមានសុវត្ថិភាព!")
                record_activity("VIRUS", user, f"CLEAN: {document.file_name}")
        else:
            await status_msg.edit_text("❌ មិនអាចភ្ជាប់ VirusTotal បានទេ។")
    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        await status_msg.edit_text("❌ កើតមានកំហុសក្នុងការវិភាគ។")
    increment_stat("virus_checked")
    return ConversationHandler.END

# ==================== /removebg ====================
async def removebg_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("🖼️ សូមផ្ញើរូបភាពដែលចង់លុប Background។")
    return AWAITING_PHOTO_BG

async def handle_removebg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user = update.effective_user
    if update.message.photo:
        photo_file = await update.message.photo[-1].get_file()
    elif update.message.document and update.message.document.mime_type.startswith("image/"):
        photo_file = await update.message.document.get_file()
    else:
        await update.message.reply_text("❌ សូមផ្ញើតែរូបភាព។")
        return ConversationHandler.END
    status_msg = await update.message.reply_text("⏳ កំពុងកាត់ Background... សូមរង់ចាំ។")
    try:
        img_bytes = bytes(await photo_file.download_as_bytearray())
        if not REMOVEBG_API_KEY:
            await status_msg.edit_text("❌ គ្មាន REMOVEBG_API_KEY!")
            return ConversationHandler.END
        r = requests.post("https://api.remove.bg/v1.0/removebg",
            files={"image_file": ("photo.jpg", img_bytes, "image/jpeg")},
            data={"size": "auto"}, headers={"X-Api-Key": REMOVEBG_API_KEY}, timeout=30)
        if r.status_code == 200:
            buf = BytesIO(r.content); buf.seek(0)
            await status_msg.delete()
            await context.bot.send_document(chat_id=update.message.chat_id,
                document=InputFile(buf, filename="removed_bg.png"),
                caption="✅ លុប Background ជោគជ័យ!")
            increment_stat("removebg_done")
            record_activity("REMOVEBG", user, "Success")
        else:
            err = r.json().get("errors",[{}])[0].get("title", r.text[:100])
            await status_msg.edit_text(f"❌ remove.bg Error: {err}")
            record_activity("REMOVEBG", user, f"Failed: {err}")
    except Exception as e:
        logger.error(f"RemoveBG error: {e}", exc_info=True)
        await status_msg.edit_text(f"❌ មានបញ្ហា: {str(e)[:200]}")
    return ConversationHandler.END

# ==================== /tti ====================
async def tti_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    record_activity("TTI", update.effective_user, "Started TTI")
    keyboard = [
        [InlineKeyboardButton("📷 Realistic", callback_data="tti_realistic"),
         InlineKeyboardButton("🎨 Anime",     callback_data="tti_anime")],
        [InlineKeyboardButton("🖌️ Digital Art", callback_data="tti_digital_art"),
         InlineKeyboardButton("🏰 Fantasy",    callback_data="tti_fantasy")],
        [InlineKeyboardButton("🚀 Sci-Fi",    callback_data="tti_scifi")],
    ]
    await update.message.reply_text("🎨 *Text To Image*\nChoose a style:",
        reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
    return TTI_AWAITING_PROMPT

async def tti_style_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    style_key = query.data.replace("tti_", "")
    if style_key not in TTI_STYLES:
        await query.edit_message_text("❌ Invalid style. Use /tti again.")
        return ConversationHandler.END
    user_tti_style[update.effective_user.id] = style_key
    style_label, _ = TTI_STYLES[style_key]
    await query.edit_message_text(
        f"✅ Style: *{style_label}*\n\nNow send your prompt.\nExample: `A Khmer warrior riding a dragon`",
        parse_mode="Markdown")
    return TTI_AWAITING_PROMPT

async def tti_receive_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user = update.effective_user
    prompt_text = update.message.text.strip()
    if not prompt_text:
        await update.message.reply_text("❌ Please send a text prompt.")
        return TTI_AWAITING_PROMPT
    style_key = user_tti_style.get(user.id, "realistic")
    style_label, style_modifier = TTI_STYLES.get(style_key, TTI_STYLES["realistic"])
    status_msg = await update.message.reply_text("⏳ Generating image…")
    full_prompt = f"{prompt_text}, {style_modifier}"
    temp_path = None
    try:
        encoded_prompt = urllib.parse.quote(full_prompt)
        image_url = f"{POLLINATIONS_BASE_URL}{encoded_prompt}"

        r = await asyncio.to_thread(requests.get, image_url, timeout=60)
        if r.status_code != 200 or not r.content:
            logger.error(f"Pollinations error {r.status_code}: {r.text[:300] if r.text else ''}")
            await status_msg.edit_text("❌ Image generation failed.\nPlease try again later.")
            return ConversationHandler.END

        # Store image temporarily on disk
        fd, temp_path = tempfile.mkstemp(suffix=".png")
        os.close(fd)
        with open(temp_path, "wb") as f:
            f.write(r.content)

        await status_msg.delete()
        with open(temp_path, "rb") as f:
            await update.message.reply_photo(
                photo=InputFile(f, filename="generated.png"),
                caption=f"🎨 *{style_label}*\n📝 _{prompt_text}_",
                parse_mode="Markdown")
        increment_stat("ai_images_generated")
        record_activity("TTI", user, f"{style_label}: {prompt_text[:60]}")
    except requests.exceptions.Timeout:
        await status_msg.edit_text("❌ Image generation failed.\nPlease try again later.")
    except Exception as e:
        logger.error(f"TTI error: {e}", exc_info=True)
        await status_msg.edit_text("❌ Image generation failed.\nPlease try again later.")
    finally:
        user_tti_style.pop(user.id, None)
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
    return ConversationHandler.END

# ==================== RUN ====================
def run_flask():
    flask_app.run(host="0.0.0.0", port=PORT)

async def run_bot():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN not set!")
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("pdf", start_pdf),
                      CommandHandler("check", check_command),
                      CommandHandler("removebg", removebg_command)],
        states={
            COLLECTING_PHOTOS: [
                MessageHandler(filters.PHOTO, receive_photo),
                MessageHandler(filters.Document.IMAGE, receive_document_photo),
                CommandHandler("done", convert_to_pdf)],
            AWAITING_FILE: [MessageHandler(filters.Document.ALL, handle_virus_check)],
            AWAITING_PHOTO_BG: [MessageHandler(filters.PHOTO | filters.Document.IMAGE, handle_removebg)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        allow_reentry=True,
    )
    tti_handler = ConversationHandler(
        entry_points=[CommandHandler("tti", tti_command)],
        states={
            TTI_AWAITING_PROMPT: [
                CallbackQueryHandler(tti_style_callback, pattern=r"^tti_"),
                MessageHandler(filters.TEXT & ~filters.COMMAND, tti_receive_prompt),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        allow_reentry=True,
    )
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(conv_handler)
    app.add_handler(tti_handler)
    logger.info("Bot starting...")
    await app.initialize()
    await app.start()
    await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
    logger.info("Bot is running.")
    await asyncio.Event().wait()

def main():
    init_mongo()
    if db is not None:
        try:
            db["stats"].update_one({"_id":"global"},
                {"$setOnInsert":{"bot_start_time": datetime.now(timezone.utc).isoformat()}},
                upsert=True)
        except PyMongoError:
            pass
    threading.Thread(target=run_flask, daemon=True).start()
    logger.info(f"Flask dashboard on port {PORT}")
    asyncio.run(run_bot())

if __name__ == "__main__":
    main()
