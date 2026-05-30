import asyncio
import ipaddress
import os
import socket
import math
import aiohttp

from aiogram import Bot, Dispatcher
from aiogram.types import Message
from aiogram.filters import Command, CommandStart

BOT_TOKEN = os.getenv("BOT_TOKEN")
PROXYCHECK_KEY = os.getenv("PROXYCHECK_KEY")

bot = Bot(BOT_TOKEN)
dp = Dispatcher()


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


def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)

    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2) ** 2 +
        math.cos(phi1) *
        math.cos(phi2) *
        math.sin(d_lambda / 2) ** 2
    )

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return round(R * c, 2)

def detect_connection_type(isp, org, reverse):

    text = f"{isp} {org} {reverse}".lower()

    DATACENTER = [
        "amazon", "aws", "google", "azure", "ovh",
        "hetzner", "digitalocean", "linode",
        "vultr", "contabo", "m247", "cloud",
        "hosting", "server"
    ]

    MOBILE = ["mts", "tele2", "megafon", "beeline", "yota"]

    HOME = ["rostelecom", "dom.ru", "er-telecom", "ttk", "ufanet", "mediacom"]

    for item in DATACENTER:
        if item in text:
            return "🖥 VPS / Datacenter"

    for item in MOBILE:
        if item in text:
            return "📱 Мобильный интернет"

    for item in HOME:
        if item in text:
            return "🏠 Домашний интернет"

    return "❓ Не определено"

# ---------- API LAYER ----------

async def geo_ipapi(session, ip):
    try:
        url = f"http://ip-api.com/json/{ip}?lang=en"
        async with session.get(url, timeout=10) as r:
            data = await r.json()
        if data.get("status") != "success":
            return None
        return data
    except:
        return None


async def geo_ipwho(session, ip):
    try:
        url = f"https://ipwho.is/{ip}"
        async with session.get(url, timeout=10) as r:
            data = await r.json()
        if not data.get("success"):
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


# ---------- MERGE ENGINE ----------

def merge_geo(ipapi, ipwho):
    data = {}

    # ip-api (base)
    if ipapi:
        data.update({
            "country": ipapi.get("country"),
            "city": ipapi.get("city"),
            "region": ipapi.get("regionName"),
            "zip": ipapi.get("zip"),
            "timezone": ipapi.get("timezone"),
            "lat": ipapi.get("lat"),
            "lon": ipapi.get("lon"),
            "isp": ipapi.get("isp"),
            "org": ipapi.get("org"),
            "as": ipapi.get("as"),
        })

    # ipwho enrichment (more detailed ISP/org/reverse)
    if ipwho:
        data.update({
            "isp": ipwho.get("connection", {}).get("isp", data.get("isp")),
            "org": ipwho.get("connection", {}).get("org", data.get("org")),
            "asn": ipwho.get("connection", {}).get("asn", data.get("as")),
            "reverse": ipwho.get("connection", {}).get("domain", None),
        })

    return data


# ---------- BOT ----------

@dp.message(CommandStart())
async def start(message: Message):
    await message.answer(
        "📡 IP Analyzer\n\n"
        "<code>/distance ip1 ip2</code>\n"
        "или просто IP",
        parse_mode="HTML"
    )


@dp.message(lambda m: m.text and not m.text.startswith("/"))
async def lookup(message: Message):

    ip = message.text.strip()

    if not is_ip(ip):
        await message.answer("❌ Некорректный IP")
        return

    async with aiohttp.ClientSession() as session:

        ipapi, ipwho = await asyncio.gather(
            geo_ipapi(session, ip),
            geo_ipwho(session, ip)
        )

        geo = merge_geo(ipapi, ipwho)
        vpn = await proxy_check(session, ip)
        reverse = reverse_lookup(ip)

        connection_type = detect_connection_type(
            geo.get("isp", ""),
            geo.get("org", ""),
            reverse
        )

        text = f"""
<b>📍 IP:</b> <code>{ip}</code>

<b>Страна:</b> <code>{geo.get('country','-')}</code>
<b>Город:</b> <code>{geo.get('city','-')}</code>
<b>Регион:</b> <code>{geo.get('region','-')}</code>
<b>ZIP:</b> <code>{geo.get('zip','-')}</code>
<b>Timezone:</b> <code>{geo.get('timezone','-')}</code>

<b>Координаты:</b> <code>{geo.get('lat')}, {geo.get('lon')}</code>

━━━━━━━━━━━━━━

<b>Провайдер:</b> <code>{geo.get('isp','-')}</code>
<b>Организация:</b> <code>{geo.get('org','-')}</code>
<b>ASN:</b> <code>{geo.get('asn', geo.get('as','-'))}</code>

<b>Reverse DNS:</b> <code>{geo.get('reverse', reverse)}</code>

━━━━━━━━━━━━━━

<b>VPN/Proxy:</b> <code>{"Да" if vpn["proxy"] else "Нет"}</code>
<b>Тип подключения:</b> <code>{connection_type}</code>
<b>Тип:</b> <code>{vpn["type"]}</code>
<b>Risk:</b> <code>{vpn["risk"]}/100</code>
"""

        await message.answer(text, parse_mode="HTML")


@dp.message(Command("distance"))
async def distance_cmd(message: Message):

    parts = message.text.split()

    if len(parts) != 3:
        await message.answer("❌ /distance ip1 ip2")
        return

    ip1, ip2 = parts[1], parts[2]

    if not is_ip(ip1) or not is_ip(ip2):
        await message.answer("❌ Некорректный IP")
        return

    async with aiohttp.ClientSession() as session:

        ipapi1, ipwho1, ipapi2, ipwho2, vpn1, vpn2 = await asyncio.gather(
            geo_ipapi(session, ip1),
            geo_ipwho(session, ip1),
            geo_ipapi(session, ip2),
            geo_ipwho(session, ip2),
            proxy_check(session, ip1),
            proxy_check(session, ip2)
        )

        geo1 = merge_geo(ipapi1, ipwho1)
        geo2 = merge_geo(ipapi2, ipwho2)

        if not geo1 or not geo2:
            await message.answer("❌ Geo не найдено")
            return

        distance = calculate_distance(
            geo1["lat"], geo1["lon"],
            geo2["lat"], geo2["lon"]
        )

        text = f"""
<b>📍 IP #1</b> <code>{ip1}</code>
<b>Город:</b> <code>{geo1.get('city','-')}</code>
<b>Провайдер:</b> <code>{geo1.get('isp','-')}</code>
<b>Org:</b> <code>{geo1.get('org','-')}</code>
<b>ASN:</b> <code>{geo1.get('asn','-')}</code>

<b>VPN:</b> <code>{"Да" if vpn1["proxy"] else "Нет"}</code>

━━━━━━━━━━━━━━

<b>📍 IP #2</b> <code>{ip2}</code>
<b>Город:</b> <code>{geo2.get('city','-')}</code>
<b>Провайдер:</b> <code>{geo2.get('isp','-')}</code>
<b>Org:</b> <code>{geo2.get('org','-')}</code>
<b>ASN:</b> <code>{geo2.get('asn','-')}</code>

<b>VPN:</b> <code>{"Да" if vpn2["proxy"] else "Нет"}</code>

━━━━━━━━━━━━━━

<b>📏 Расстояние:</b> <code>{distance} км</code>
"""

        await message.answer(text, parse_mode="HTML")


async def main():
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())