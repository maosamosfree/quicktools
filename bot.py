import os
import subprocess
from threading import Thread
from flask import Flask
from telegram import Update
from telegram.ext import Application, MessageHandler, ContextTypes, filters

BOT_TOKEN = os.getenv("BOT_TOKEN")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text

    mp3_file = "speech.mp3"
    ogg_file = "speech.ogg"

    try:
        subprocess.run([
            "edge-tts",
            "--voice", "km-KH-PisethNeural",
            "--text", text,
            "--write-media", mp3_file
        ], check=True)

        subprocess.run([
            "ffmpeg",
            "-y",
            "-i", mp3_file,
            "-c:a", "libopus",
            "-b:a", "32k",
            "-ar", "48000",
            "-ac", "1",
            ogg_file
        ], check=True)

        with open(ogg_file, "rb") as voice:
            await update.message.reply_voice(voice=voice)

    except Exception as e:
        await update.message.reply_text(f"Error: {e}")

    finally:
        for f in [mp3_file, ogg_file]:
            if os.path.exists(f):
                os.remove(f)

# Telegram Bot
def run_bot():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
    )

    print("Bot started...")
    app.run_polling()

# Web Server for Render
web_app = Flask(__name__)

@web_app.route("/")
def home():
    return "Khmer TTS Bot Running"

def run_web():
    port = int(os.environ.get("PORT", 10000))
    web_app.run(host="0.0.0.0", port=port)

if __name__ == "__main__":
    Thread(target=run_web).start()
    run_bot()
