import asyncio
import ipaddress
import os
import socket
import requests

from aiogram import Bot, Dispatcher
from aiogram.types import Message
from aiogram.filters import CommandStart

BOT_TOKEN = os.getenv("BOT_TOKEN")

PROXYCHECK_KEY = os.getenv("PROXYCHECK_KEY")

bot = Bot(BOT_TOKEN)
dp = Dispatcher()


DATACENTER = [
    "amazon",
    "aws",
    "google",
    "azure",
    "ovh",
    "hetzner",
    "digitalocean",
    "linode",
    "vultr",
    "contabo",
    "m247",
    "cloud",
    "hosting",
    "server"
]

MOBILE = [
    "mts",
    "tele2",
    "megafon",
    "beeline",
    "yota"
]

HOME = [
    "rostelecom",
    "dom.ru",
    "er-telecom",
    "ttk",
    "ufanet",
    "mediacom"
]

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except:
        return False


def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "не определено"


def geo_lookup(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?lang=en",
            timeout=10
        )

        data = r.json()

        if data["status"] != "success":
            return None

        return data

    except:
        return None


def proxy_check(ip):

    try:

        url = (
            f"https://proxycheck.io/v2/{ip}"
            f"?key={PROXYCHECK_KEY}"
            f"&vpn=1"
            f"&asn=1"
            f"&risk=1"
        )

        r = requests.get(url, timeout=15)

        data = r.json()

        info = data.get(ip, {})

        return {
            "proxy": info.get("proxy") == "yes",
            "type": info.get("type", "Unknown"),
            "risk": info.get("risk", "0"),
            "provider": info.get("provider", "Unknown")
        }

    except:

        return {
            "proxy": False,
            "type": "Unknown",
            "risk": "0",
            "provider": "Unknown"
        }


def detect_connection_type(isp, org, reverse):

    text = f"{isp} {org} {reverse}".lower()

    for item in DATACENTER:
        if item in text:
            return "🖥 VPS / Datacenter"

    for item in MOBILE:
        if item in text:
            return "📱 Мобильный интернет"

    for item in HOME:
        if item in text:
            return "🏠 Вероятно домашний IP"

    return "❓ Не определено"


@dp.message(CommandStart())
async def start(message: Message):

    await message.answer(
        "Отправьте IP адрес.\n\n"
        "Пример:\n"
        "<code>8.8.8.8</code>",
        parse_mode="HTML"
    )


@dp.message()
async def lookup(message: Message):

    ip = message.text.strip()

    if not is_ip(ip):
        await message.answer(
            "❌ Некорректный IP адрес."
        )
        return

    geo = geo_lookup(ip)

    if not geo:
        await message.answer(
            "❌ Информация не найдена."
        )
        return

    reverse = reverse_lookup(ip)

    vpn = proxy_check(ip)

    if vpn["proxy"]:

        connection_type = f"🛡 {vpn['type']}"

    else:

        connection_type = detect_connection_type(
            geo.get("isp", ""),
            geo.get("org", ""),
            reverse
        )

    text = f"""
<b>Информация по IP:</b> <code>{ip}</code>

<b>Страна:</b> <code>{geo.get('country', '-')}</code>
<b>Город:</b> <code>{geo.get('city', '-')}</code>
<b>Регион:</b> <code>{geo.get('regionName', '-')}</code>
<b>Индекс:</b> <code>{geo.get('zip', '-')}</code>
<b>Часовой пояс:</b> <code>{geo.get('timezone', '-')}</code>
<b>Координаты:</b> <code>{geo.get('lat')}, {geo.get('lon')}</code>

<b>Провайдер:</b> <code>{geo.get('isp', '-')}</code>
<b>Организация:</b> <code>{geo.get('org', '-')}</code>
<b>ASN:</b> <code>{geo.get('as', '-')}</code>
<b>Reverse DNS:</b> <code>{reverse}</code>

    ━━━━━━━━━━━━━━

<b>Тип подключения:</b> <code>{connection_type}</code>
<b>VPN/Proxy:</b> <code>{"Да" if vpn["proxy"] else "Нет"}</code>
<b>Тип VPN:</b> <code>{vpn["type"]}</code>
<b>Провайдер VPN:</b> <code>{vpn["provider"]}</code>
<b>Risk Score:</b> <code>{vpn["risk"]}/100</code>
    """

    await message.answer(
        text,
        parse_mode="HTML"
    )

async def main():
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())