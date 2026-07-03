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
IP2LOCATION_KEY = os.getenv("IP2LOCATION_KEY")

bot = Bot(BOT_TOKEN)
dp = Dispatcher()




def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def reverse_lookup_async(ip: str) -> str:
    try:
        result = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return result[0]
    except Exception:
        return "не определено"


def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371

    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    d_phi = math.radians(float(lat2) - float(lat1))
    d_lambda = math.radians(float(lon2) - float(lon1))

    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return round(R * c, 2)


def detect_connection_type(isp: str, org: str, reverse: str) -> str:
    text = f"{isp} {org} {reverse}".lower()

    DATACENTER = [
        "amazon", "aws", "google", "azure", "ovh",
        "hetzner", "digitalocean", "linode", "vultr",
        "contabo", "m247", "cloud", "hosting", "server",
        "oracle", "alibaba", "leaseweb", "scaleway"
    ]

    MOBILE = [
        "mts", "tele2", "megafon", "beeline", "yota",
        "vodafone", "t-mobile", "orange", "airtel", "verizon", "at&t"
    ]

    HOME = [
        "rostelecom", "dom.ru", "er-telecom", "ttk", "ufanet", "mediacom",
        "comcast", "spectrum", "cox", "bt", "virgin media"
    ]

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




async def geo_ip2location(session: aiohttp.ClientSession, ip: str):
    """
    IP2Location.io geolocation lookup.
    Работает и с API key, и без него (keyless), если IP2LOCATION_KEY пустой.
    """
    try:
        url = "https://api.ip2location.io/"
        params = {
            "ip": ip,
            "format": "json",
        }

        # если есть ключ — используем free plan / paid plan
        if IP2LOCATION_KEY:
            params["key"] = IP2LOCATION_KEY

        async with session.get(url, params=params, timeout=10) as r:
            data = await r.json()

        # API может вернуть error object
        if not data or data.get("error"):
            return None

        return {
            "ip": data.get("ip"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "city": data.get("city_name"),
            "region": data.get("region_name"),
            "zip": data.get("zip_code"),
            "timezone": data.get("time_zone"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "asn": str(data.get("asn")) if data.get("asn") is not None else None,
            "as": data.get("as"),
            "isp": data.get("isp") or data.get("as"),
            "org": data.get("as"),
            "reverse": data.get("domain"),
            "is_proxy": data.get("is_proxy", False),
        }

    except Exception:
        return None


async def proxy_check(session: aiohttp.ClientSession, ip: str):
    if not PROXYCHECK_KEY:
        return {
            "proxy": False,
            "type": "Unknown",
            "risk": "0",
            "provider": "Unknown"
        }

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
            "risk": str(info.get("risk", "0")),
            "provider": info.get("provider", "Unknown")
        }

    except Exception:
        return {
            "proxy": False,
            "type": "Unknown",
            "risk": "0",
            "provider": "Unknown"
        }




def format_lookup_text(ip: str, geo: dict, vpn: dict, reverse: str, connection_type: str) -> str:
    return f"""
<b>📍 IP:</b> <code>{ip}</code>

<b>Страна:</b> <code>{geo.get('country', '-')}</code>
<b>Город:</b> <code>{geo.get('city', '-')}</code>
<b>Регион:</b> <code>{geo.get('region', '-')}</code>
<b>ZIP:</b> <code>{geo.get('zip', '-')}</code>
<b>Timezone:</b> <code>{geo.get('timezone', '-')}</code>

<b>Координаты:</b> <code>{geo.get('lat', '-')}, {geo.get('lon', '-')}</code>

━━━━━━━━━━━━━━

<b>Провайдер:</b> <code>{geo.get('isp', '-')}</code>
<b>Организация:</b> <code>{geo.get('org', '-')}</code>
<b>ASN:</b> <code>{geo.get('asn', '-')}</code>
<b>AS:</b> <code>{geo.get('as', '-')}</code>

<b>Reverse DNS:</b> <code>{geo.get('reverse') or reverse}</code>

━━━━━━━━━━━━━━

<b>VPN/Proxy:</b> <code>{"Да" if vpn["proxy"] else "Нет"}</code>
<b>Тип подключения:</b> <code>{connection_type}</code>
<b>Тип:</b> <code>{vpn["type"]}</code>
<b>Risk:</b> <code>{vpn["risk"]}/100</code>
<b>Proxy Provider:</b> <code>{vpn["provider"]}</code>
""".strip()


def format_distance_text(
    ip1: str,
    geo1: dict,
    vpn1: dict,
    connection_type1: str,
    ip2: str,
    geo2: dict,
    vpn2: dict,
    connection_type2: str,
    distance: float
) -> str:
    return f"""
<b>📍 IP #1</b> <code>{ip1}</code>
<b>Страна:</b> <code>{geo1.get('country', '-')}</code>
<b>Город:</b> <code>{geo1.get('city', '-')}</code>
<b>Провайдер:</b> <code>{geo1.get('isp', '-')}</code>
<b>Org:</b> <code>{geo1.get('org', '-')}</code>
<b>ASN:</b> <code>{geo1.get('asn', '-')}</code>

<b>VPN:</b> <code>{"Да" if vpn1["proxy"] else "Нет"}</code>
<b>Тип подключения:</b> <code>{connection_type1}</code>

━━━━━━━━━━━━━━

<b>📍 IP #2</b> <code>{ip2}</code>
<b>Страна:</b> <code>{geo2.get('country', '-')}</code>
<b>Город:</b> <code>{geo2.get('city', '-')}</code>
<b>Провайдер:</b> <code>{geo2.get('isp', '-')}</code>
<b>Org:</b> <code>{geo2.get('org', '-')}</code>
<b>ASN:</b> <code>{geo2.get('asn', '-')}</code>

<b>VPN:</b> <code>{"Да" if vpn2["proxy"] else "Нет"}</code>
<b>Тип подключения:</b> <code>{connection_type2}</code>

━━━━━━━━━━━━━━

<b>📏 Расстояние:</b> <code>{distance} км</code>
""".strip()




@dp.message(CommandStart())
async def start(message: Message):
    await message.answer(
        "📡 <b>IP Analyzer</b>\n\n"
        "Отправь IP адрес, чтобы получить информацию о нём.\n"
        "Для сравнения используй:\n"
        "<code>/distance ip1 ip2</code>",
        parse_mode="HTML"
    )


@dp.message(lambda m: m.text and not m.text.startswith("/"))
async def lookup(message: Message):
    ip = message.text.strip()

    if not is_ip(ip):
        await message.answer("❌ Некорректный IP")
        return

    async with aiohttp.ClientSession() as session:
        geo, vpn, reverse = await asyncio.gather(
            geo_ip2location(session, ip),
            proxy_check(session, ip),
            reverse_lookup_async(ip)
        )

        if not geo:
            await message.answer("❌ Не удалось получить геоданные по IP")
            return

        connection_type = detect_connection_type(
            geo.get("isp", ""),
            geo.get("org", ""),
            reverse
        )

        text = format_lookup_text(ip, geo, vpn, reverse, connection_type)
        await message.answer(text, parse_mode="HTML")


@dp.message(Command("distance"))
async def distance_cmd(message: Message):
    parts = message.text.split()

    if len(parts) != 3:
        await message.answer("❌ Использование: <code>/distance ip1 ip2</code>", parse_mode="HTML")
        return

    ip1, ip2 = parts[1], parts[2]

    if not is_ip(ip1) or not is_ip(ip2):
        await message.answer("❌ Некорректный IP")
        return

    async with aiohttp.ClientSession() as session:
        geo1, geo2, vpn1, vpn2, reverse1, reverse2 = await asyncio.gather(
            geo_ip2location(session, ip1),
            geo_ip2location(session, ip2),
            proxy_check(session, ip1),
            proxy_check(session, ip2),
            reverse_lookup_async(ip1),
            reverse_lookup_async(ip2),
        )

        if not geo1 or not geo2:
            await message.answer("❌ Не удалось получить геоданные для одного из IP")
            return

        if geo1.get("lat") is None or geo1.get("lon") is None or geo2.get("lat") is None or geo2.get("lon") is None:
            await message.answer("❌ Не удалось вычислить расстояние: нет координат")
            return

        connection_type1 = detect_connection_type(
            geo1.get("isp", ""),
            geo1.get("org", ""),
            reverse1
        )

        connection_type2 = detect_connection_type(
            geo2.get("isp", ""),
            geo2.get("org", ""),
            reverse2
        )

        distance = calculate_distance(
            geo1["lat"], geo1["lon"],
            geo2["lat"], geo2["lon"]
        )

        text = format_distance_text(
            ip1, geo1, vpn1, connection_type1,
            ip2, geo2, vpn2, connection_type2,
            distance
        )

        await message.answer(text, parse_mode="HTML")


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN не найден в переменных окружения")

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
