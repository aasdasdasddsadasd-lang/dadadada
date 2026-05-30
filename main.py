import asyncio
import ipaddress
import os
import socket
import math
import aiohttp

from aiogram import Bot, Dispatcher
from aiogram.types import Message
from aiogram.filters import CommandStart

BOT_TOKEN = os.getenv("BOT_TOKEN")
PROXYCHECK_KEY = os.getenv("PROXYCHECK_KEY")

bot = Bot(BOT_TOKEN)
dp = Dispatcher()


DATACENTER = [
    "amazon", "aws", "google", "azure", "ovh",
    "hetzner", "digitalocean", "linode",
    "vultr", "contabo", "m247", "cloud",
    "hosting", "server"
]

MOBILE = ["mts", "tele2", "megafon", "beeline", "yota"]

HOME = ["rostelecom", "dom.ru", "er-telecom", "ttk", "ufanet", "mediacom"]


# ---------- utils ----------

def is_ip(value: str):
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


def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)

    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (math.sin(d_phi/2)**2 +
         math.cos(phi1) * math.cos(phi2) *
         math.sin(d_lambda/2)**2)

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return round(R * c, 2)



async def geo_lookup(session, ip):
    try:
        url = f"http://ip-api.com/json/{ip}?lang=en"
        async with session.get(url, timeout=10) as r:
            data = await r.json()

        if data.get("status") != "success":
            return None

        return data

    except:
        return None


async def proxy_check(session, ip):
    try:
        url = (
            f"https://proxycheck.io/v2/{ip}"
            f"?key={PROXYCHECK_KEY}"
            f"&vpn=1&asn=1&risk=1"
        )

        async with session.get(url, timeout=15) as r:
            data = await r.json()

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


@dp.message(CommandStart())
async def start(message: Message):
    await message.answer(
        "Отправьте IP адрес или используйте /distance\n\n"
        "<code>8.8.8.8</code>",
        parse_mode="HTML"
    )


@dp.message()
async def lookup(message: Message):

    ip = message.text.strip()

    if not is_ip(ip):
        await message.answer("❌ Некорректный IP")
        return

    async with aiohttp.ClientSession() as session:

        geo = await geo_lookup(session, ip)
        if not geo:
            await message.answer("❌ Не удалось получить данные")
            return

        vpn = await proxy_check(session, ip)

        reverse = reverse_lookup(ip)

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
<b>Провайдер:</b> <code>{geo.get('isp', '-')}</code>
<b>ASN:</b> <code>{geo.get('as', '-')}</code>

<b>Reverse:</b> <code>{reverse}</code>

━━━━━━━━━━━━━━

<b>VPN/Proxy:</b> <code>{"Да" if vpn["proxy"] else "Нет"}</code>
<b>Тип:</b> <code>{vpn["type"]}</code>
<b>Risk:</b> <code>{vpn["risk"]}/100</code>
"""

        await message.answer(text, parse_mode="HTML")


@dp.message(lambda m: m.text and m.text.startswith("/distance"))
async def distance_cmd(message: Message):

    parts = message.text.split()

    if len(parts) != 3:
        await message.answer("❌ /distance ip1 ip2")
        return

    ip1, ip2 = parts[1], parts[2]

    if not is_ip(ip1) or not is_ip(ip2):
        await message.answer("❌ Неверные IP")
        return

    async with aiohttp.ClientSession() as session:

        geo1, geo2 = await asyncio.gather(
            geo_lookup(session, ip1),
            geo_lookup(session, ip2)
        )

        vpn1, vpn2 = await asyncio.gather(
            proxy_check(session, ip1),
            proxy_check(session, ip2)
        )

        if not geo1 or not geo2:
            await message.answer("❌ Geo не найдено")
            return

        lat1, lon1 = geo1["lat"], geo1["lon"]
        lat2, lon2 = geo2["lat"], geo2["lon"]

        distance = calculate_distance(lat1, lon1, lat2, lon2)

        text = f"""
<b>📍 IP #1</b> <code>{ip1}</code>
Город: <code>{geo1.get('city','-')}</code>
Провайдер: <code>{geo1.get('isp','-')}</code>
VPN: <code>{"Да" if vpn1["proxy"] else "Нет"}</code>

━━━━━━━━━━━━━━

<b>📍 IP #2</b> <code>{ip2}</code>
Город: <code>{geo2.get('city','-')}</code>
Провайдер: <code>{geo2.get('isp','-')}</code>
VPN: <code>{"Да" if vpn2["proxy"] else "Нет"}</code>

━━━━━━━━━━━━━━

<b>📏 Расстояние:</b> <code>{distance} км</code>
"""

        await message.answer(text, parse_mode="HTML")


async def main():
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())