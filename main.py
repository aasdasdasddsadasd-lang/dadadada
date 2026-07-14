import asyncio
import html
import ipaddress
import logging
import math
import os
import socket
import time
from typing import Optional

import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command, CommandStart
from aiogram.types import ErrorEvent, Message



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
log = logging.getLogger("ip_analyzer_bot")


BOT_TOKEN = os.getenv("BOT_TOKEN")
PROXYCHECK_KEY = os.getenv("PROXYCHECK_KEY")
IP2LOCATION_KEY = os.getenv("IP2LOCATION_KEY")

DNS_TIMEOUT = 5
HTTP_TIMEOUT = 10
CACHE_TTL = 15 * 60
RATE_LIMIT_SECONDS = 3

bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
dp = Dispatcher()


_cache: dict[str, tuple[float, dict]] = {}


def cache_get(key: str) -> Optional[dict]:
    item = _cache.get(key)
    if not item:
        return None
    ts, value = item
    if time.monotonic() - ts > CACHE_TTL:
        _cache.pop(key, None)
        return None
    return value


def cache_set(key: str, value: dict) -> None:
    _cache[key] = (time.monotonic(), value)


_last_call: dict[int, float] = {}


def is_rate_limited(user_id: int) -> bool:
    now = time.monotonic()
    last = _last_call.get(user_id, 0)
    if now - last < RATE_LIMIT_SECONDS:
        return True
    _last_call[user_id] = now
    return False



def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def esc(value) -> str:
    if value is None:
        return "-"
    return html.escape(str(value))


async def reverse_lookup_async(ip: str) -> str:
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip),
            timeout=DNS_TIMEOUT,
        )
        return result[0]
    except asyncio.TimeoutError:
        log.warning("reverse DNS timeout for %s", ip)
        return "не определено"
    except Exception as e:
        log.debug("reverse DNS failed for %s: %s", ip, e)
        return "не определено"


def calculate_distance(lat1, lon1, lat2, lon2) -> float:
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


async def geo_ip2location(session: aiohttp.ClientSession, ip: str) -> Optional[dict]:
    try:
        url = "https://api.ip2location.io/"
        params = {"ip": ip, "format": "json"}
        if IP2LOCATION_KEY:
            params["key"] = IP2LOCATION_KEY

        async with session.get(
            url, params=params, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        ) as r:
            if r.status != 200:
                body = await r.text()
                log.warning("ip2location HTTP %s for %s: %s", r.status, ip, body[:300])
                return None
            try:
                data = await r.json(content_type=None)
            except Exception as e:
                log.warning("ip2location: bad JSON for %s: %s", ip, e)
                return None

        if not data or data.get("error"):
            log.warning("ip2location returned error for %s: %s", ip, data.get("error") if data else "empty body")
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

    except asyncio.TimeoutError:
        log.warning("ip2location timeout for %s", ip)
        return None
    except aiohttp.ClientError as e:
        log.warning("ip2location network error for %s: %s", ip, e)
        return None
    except Exception:
        log.exception("ip2location unexpected error for %s", ip)
        return None


async def proxy_check(session: aiohttp.ClientSession, ip: str) -> dict:
    default = {"proxy": False, "type": "Unknown", "risk": "0", "provider": "Unknown"}

    if not PROXYCHECK_KEY:
        return default

    try:
        url = f"https://proxycheck.io/v2/{ip}"
        params = {"key": PROXYCHECK_KEY, "vpn": 1, "asn": 1, "risk": 1}

        async with session.get(
            url, params=params, timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status != 200:
                body = await r.text()
                log.warning("proxycheck HTTP %s for %s: %s", r.status, ip, body[:300])
                return default
            try:
                data = await r.json(content_type=None)
            except Exception as e:
                log.warning("proxycheck: bad JSON for %s: %s", ip, e)
                return default

        if data.get("status") == "error":
            log.warning("proxycheck API error for %s: %s", ip, data.get("message"))
            return default

        info = data.get(ip, {})
        return {
            "proxy": info.get("proxy") == "yes",
            "type": info.get("type", "Unknown"),
            "risk": str(info.get("risk", "0")),
            "provider": info.get("provider", "Unknown"),
        }

    except asyncio.TimeoutError:
        log.warning("proxycheck timeout for %s", ip)
        return default
    except aiohttp.ClientError as e:
        log.warning("proxycheck network error for %s: %s", ip, e)
        return default
    except Exception:
        log.exception("proxycheck unexpected error for %s", ip)
        return default


async def gather_ip_data(session: aiohttp.ClientSession, ip: str) -> Optional[dict]:
    cached = cache_get(ip)
    if cached:
        return cached

    geo, vpn, reverse = await asyncio.gather(
        geo_ip2location(session, ip),
        proxy_check(session, ip),
        reverse_lookup_async(ip),
    )

    if not geo:
        return None

    connection_type = detect_connection_type(
        geo.get("isp", ""), geo.get("org", ""), reverse
    )

    result = {
        "geo": geo,
        "vpn": vpn,
        "reverse": reverse,
        "connection_type": connection_type,
    }
    cache_set(ip, result)
    return result


def format_lookup_text(ip: str, geo: dict, vpn: dict, reverse: str, connection_type: str) -> str:
    is_proxy_field = geo.get("is_proxy")
    is_proxy_str = "Да" if is_proxy_field else ("Нет" if is_proxy_field is not None else "-")

    return f"""
<b>📍 IP:</b> <code>{esc(ip)}</code>

<b>Страна:</b> <code>{esc(geo.get('country'))}</code>
<b>Город:</b> <code>{esc(geo.get('city'))}</code>
<b>Регион:</b> <code>{esc(geo.get('region'))}</code>
<b>ZIP:</b> <code>{esc(geo.get('zip'))}</code>
<b>Timezone:</b> <code>{esc(geo.get('timezone'))}</code>

<b>Координаты:</b> <code>{esc(geo.get('lat'))}, {esc(geo.get('lon'))}</code>

━━━━━━━━━━━━━━

<b>Провайдер:</b> <code>{esc(geo.get('isp'))}</code>
<b>Организация:</b> <code>{esc(geo.get('org'))}</code>
<b>ASN:</b> <code>{esc(geo.get('asn'))}</code>
<b>AS:</b> <code>{esc(geo.get('as'))}</code>

<b>Reverse DNS:</b> <code>{esc(geo.get('reverse') or reverse)}</code>

━━━━━━━━━━━━━━

<b>VPN/Proxy (proxycheck):</b> <code>{"Да" if vpn["proxy"] else "Нет"}</code>
<b>VPN/Proxy (ip2location):</b> <code>{is_proxy_str}</code>
<b>Тип подключения:</b> <code>{esc(connection_type)}</code>
<b>Тип:</b> <code>{esc(vpn["type"])}</code>
<b>Risk:</b> <code>{esc(vpn["risk"])}/100</code>
<b>Proxy Provider:</b> <code>{esc(vpn["provider"])}</code>
""".strip()


def format_distance_text(
    ip1: str, geo1: dict, vpn1: dict, connection_type1: str,
    ip2: str, geo2: dict, vpn2: dict, connection_type2: str,
    distance: float,
) -> str:
    return f"""
<b>📍 IP #1</b> <code>{esc(ip1)}</code>
<b>Страна:</b> <code>{esc(geo1.get('country'))}</code>
<b>Город:</b> <code>{esc(geo1.get('city'))}</code>
<b>Провайдер:</b> <code>{esc(geo1.get('isp'))}</code>
<b>Org:</b> <code>{esc(geo1.get('org'))}</code>
<b>ASN:</b> <code>{esc(geo1.get('asn'))}</code>

<b>VPN:</b> <code>{"Да" if vpn1["proxy"] else "Нет"}</code>
<b>Тип подключения:</b> <code>{esc(connection_type1)}</code>

━━━━━━━━━━━━━━

<b>📍 IP #2</b> <code>{esc(ip2)}</code>
<b>Страна:</b> <code>{esc(geo2.get('country'))}</code>
<b>Город:</b> <code>{esc(geo2.get('city'))}</code>
<b>Провайдер:</b> <code>{esc(geo2.get('isp'))}</code>
<b>Org:</b> <code>{esc(geo2.get('org'))}</code>
<b>ASN:</b> <code>{esc(geo2.get('asn'))}</code>

<b>VPN:</b> <code>{"Да" if vpn2["proxy"] else "Нет"}</code>
<b>Тип подключения:</b> <code>{esc(connection_type2)}</code>

━━━━━━━━━━━━━━

<b>📏 Между н.п:</b> <code>{esc(distance)} км</code>
""".strip()



@dp.message(CommandStart())
async def start(message: Message):
    await message.answer(
        "📡 <b>IP Analyzer</b>\n\n"
        "Отправь IP адрес, чтобы получить информацию о нём.\n"
        "Для сравнения используй:\n"
        "<code>/distance ip1 ip2</code>"
    )


@dp.message(lambda m: m.text and not m.text.startswith("/") and m.chat.type == "private")
async def lookup(message: Message):
    if is_rate_limited(message.from_user.id):
        await message.answer("⏳ Слишком часто. Подожди пару секунд и попробуй снова.")
        return

    ip = message.text.strip()

    if not is_ip(ip):
        await message.answer("❌ Некорректный IP")
        return

    if not is_public_ip(ip):
        await message.answer("❌ Это приватный/зарезервированный IP — по нему нет геоданных")
        return

    session: aiohttp.ClientSession = dp["session"]

    data = await gather_ip_data(session, ip)
    if not data:
        await message.answer("❌ Не удалось получить геоданные по IP (сервис недоступен или лимит запросов исчерпан)")
        return

    text = format_lookup_text(ip, data["geo"], data["vpn"], data["reverse"], data["connection_type"])
    await message.answer(text)


@dp.message(Command("distance"))
async def distance_cmd(message: Message):
    if is_rate_limited(message.from_user.id):
        await message.answer("⏳ Слишком часто. Подожди пару секунд и попробуй снова.")
        return

    parts = message.text.split()

    if len(parts) != 3:
        await message.answer("❌ Использование: <code>/distance ip1 ip2</code>")
        return

    ip1, ip2 = parts[1], parts[2]

    if not is_ip(ip1) or not is_ip(ip2):
        await message.answer("❌ Некорректный IP")
        return

    if not is_public_ip(ip1) or not is_public_ip(ip2):
        await message.answer("❌ Один из IP приватный/зарезервированный — по нему нет геоданных")
        return

    session: aiohttp.ClientSession = dp["session"]

    data1, data2 = await asyncio.gather(
        gather_ip_data(session, ip1),
        gather_ip_data(session, ip2),
    )

    if not data1 or not data2:
        await message.answer("❌ Не удалось получить геоданные для одного из IP")
        return

    geo1, geo2 = data1["geo"], data2["geo"]

    if geo1.get("lat") is None or geo1.get("lon") is None or geo2.get("lat") is None or geo2.get("lon") is None:
        await message.answer("❌ Не удалось вычислить расстояние: нет координат")
        return

    distance = calculate_distance(geo1["lat"], geo1["lon"], geo2["lat"], geo2["lon"])

    text = format_distance_text(
        ip1, geo1, data1["vpn"], data1["connection_type"],
        ip2, geo2, data2["vpn"], data2["connection_type"],
        distance,
    )
    await message.answer(text)

@dp.errors()
async def error_handler(event: ErrorEvent):
    log.exception("Unhandled error while processing update", exc_info=event.exception)
    try:
        if event.update.message:
            await event.update.message.answer(
                "⚠️ Произошла внутренняя ошибка. Уже разбираемся, попробуй чуть позже."
            )
    except Exception:
        log.exception("Failed to notify user about the error")
    return True



async def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN не найден в переменных окружения")

    async with aiohttp.ClientSession() as session:
        dp["session"] = session
        log.info("Bot started")
        try:
            await dp.start_polling(bot)
        finally:
            log.info("Bot stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped by user")