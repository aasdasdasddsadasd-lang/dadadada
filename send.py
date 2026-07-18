#!/usr/bin/env python3
import os
import sys
import urllib.request
import urllib.parse
import json

BOT_TOKEN = os.getenv("BOT_TOKEN")


def main():
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN не найден в переменных окружения")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Использование: python3 send.py <user_id> <текст сообщения>")
        sys.exit(1)

    user_id = sys.argv[1]
    text = " ".join(sys.argv[2:])

    if not user_id.lstrip("-").isdigit():
        print("❌ user_id должен быть числом")
        sys.exit(1)

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": user_id, "text": text}).encode()

    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
    except Exception as e:
        print(f"❌ Сетевая ошибка: {e}")
        sys.exit(1)

    if body.get("ok"):
        chat = body["result"].get("chat", {})
        username = chat.get("username")
        full_name = " ".join(
            filter(None, [chat.get("first_name"), chat.get("last_name")])
        )
        who = f"@{username}" if username else (full_name or user_id)
        print(f"✅ Отправлено пользователю: {who} ({user_id})")
    else:
        print(f"❌ Ошибка Telegram API: {body.get('description')}")
        sys.exit(1)


if __name__ == "__main__":
    main()