import os
import sys
import urllib.request
import urllib.parse
import json

BOT_TOKEN = os.getenv("BOT_TOKEN")


def main():
    if not BOT_TOKEN:
        print("BOT_TOKEN не найден в переменных")

    if len(sys.argv) < 3:
        print("use: python3 send.py <user_id> <text>") 
        sys.exit(1)

    user_id = sys.argv[1]
    text = " ".join(sys.argv[2:])

    if not user_id.lstrip("-").isdigit():
        print("user_id должен быть числом.")
        sys.exit(1)

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": user_id, "text": text}).encode()

    req = urllib.request.Request(url,data=data)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
    except Exception as e:
        print(f"❌ Сетевая ошибка: {e}")
        sys.exit(1)     

    if body.get("ok"):
        print(f"Отправлено пользователю {user_id}")
    else:
        print(f"Ошибка тг апи: {body.get('desctiprion')}")
    sys.exit(1)


if __name__ == "__main__":
    main()               