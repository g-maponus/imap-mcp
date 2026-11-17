"""Read-only CalDAV client for imap-mcp (iCloud, Fastmail, Baïkal, any RFC 4791 server).

Read-only by construction, not by configuration: the only HTTP methods this module can send
are PROPFIND and REPORT (_dav refuses anything else), so even a bug or a prompt-injected tool
call cannot create, change or delete an event. Credentials are only ever sent to the configured
server's host (iCloud hands out a per-user pXX-caldav.icloud.com home, so a sibling host under
the same registered domain is accepted; anything else is refused).
"""
import datetime as dt
import os
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo

import httpx
import icalendar
import recurring_ical_events

NS = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:caldav", "ic": "http://apple.com/ns/ical/"}
READ_METHODS = ("PROPFIND", "REPORT")


def _local_tz() -> ZoneInfo:
    """IMAP_MCP_TZ or TZ (e.g. America/Toronto), else the system zone, else UTC."""
    name = os.environ.get("IMAP_MCP_TZ") or os.environ.get("TZ", "").lstrip(":")
    if not name:
        real = os.path.realpath("/etc/localtime")              # macOS + most Linux
        name = real.split("zoneinfo/", 1)[1] if "zoneinfo/" in real else "UTC"
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo("UTC")


LOCAL_TZ = _local_tz()
MAX_DESCRIPTION = 20_000


class AuthError(Exception):
    pass


def _xml(body: str) -> bytes:
    return ('<?xml version="1.0" encoding="utf-8"?>' + body).encode()


def _utc(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _iso(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, dt.datetime):
        return (v if v.tzinfo else v.replace(tzinfo=LOCAL_TZ)).astimezone(LOCAL_TZ).isoformat()
    return v.isoformat()


def _sort_key(v) -> dt.datetime:
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=LOCAL_TZ)
    return dt.datetime.combine(v, dt.time(), LOCAL_TZ)


def _domain(host: str) -> str:
    return ".".join(host.split(".")[-2:])


class CalDAV:
    def __init__(self, url: str, username: str, password: str):
        self.base = url if url.endswith("/") else url + "/"
        self.host = urlsplit(self.base).hostname
        self.http = httpx.Client(auth=(username, password), timeout=30, follow_redirects=True,
                                 headers={"User-Agent": "imap-mcp-caldav"})
        self._home = None

    def _allowed(self, url: str) -> str:
        h = urlsplit(url).hostname or ""
        if h != self.host and not ("." in self.host and h.endswith("." + _domain(self.host))):
            raise ValueError(f"refusing to send credentials to {h} (configured server is {self.host})")
        return url

    def _dav(self, method: str, url: str, body: bytes, depth: str) -> tuple[ET.Element, str]:
        if method not in READ_METHODS:
            raise PermissionError(f"{method} refused — this client is read-only")
        r = self.http.request(method, self._allowed(url), content=body,
                              headers={"Depth": depth, "Content-Type": "application/xml; charset=utf-8"})
        if r.status_code == 401:
            raise AuthError("CalDAV login refused (401) — check the account's password file")
        if r.status_code != 207:
            raise RuntimeError(f"CalDAV {method} returned HTTP {r.status_code}")
        return ET.fromstring(r.content), str(r.url)

    def _href(self, root: ET.Element, prop: str, base: str) -> str:
        el = root.find(f".//{prop}/d:href", NS)
        if el is None or not (el.text or "").strip():
            raise RuntimeError(f"server did not return {prop}")
        return urljoin(base, el.text.strip())

    def home(self) -> str:
        if not self._home:
            q = _xml('<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>')
            root, url = self._dav("PROPFIND", self.base, q, "0")
            principal = self._href(root, "d:current-user-principal", url)
            q = _xml('<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
                     '<d:prop><c:calendar-home-set/></d:prop></d:propfind>')
            root, url = self._dav("PROPFIND", principal, q, "0")
            self._home = self._allowed(self._href(root, "c:calendar-home-set", url))
        return self._home

    def calendars(self) -> list[dict]:
        q = _xml('<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" '
                 'xmlns:ic="http://apple.com/ns/ical/"><d:prop><d:resourcetype/><d:displayname/>'
                 '<c:supported-calendar-component-set/><ic:calendar-color/><c:calendar-description/>'
                 '</d:prop></d:propfind>')
        root, url = self._dav("PROPFIND", self.home(), q, "1")
        out = []
        for resp in root.findall("d:response", NS):
            if resp.find(".//d:resourcetype/c:calendar", NS) is None:
                continue
            href = urljoin(url, resp.findtext("d:href", "", NS).strip())
            comps = [c.get("name") for c in resp.findall(".//c:supported-calendar-component-set/c:comp", NS)]
            if comps and "VEVENT" not in comps:
                continue                                  # reminders lists etc.
            out.append({"calendar": href.rstrip("/").rsplit("/", 1)[-1],
                        "name": (resp.findtext(".//d:displayname", "", NS) or "").strip(),
                        "description": (resp.findtext(".//c:calendar-description", "", NS) or "").strip(),
                        "color": (resp.findtext(".//ic:calendar-color", "", NS) or "").strip(),
                        "href": href})
        return out

    def _calendar_href(self, cal_id: str) -> str:
        for c in self.calendars():
            if cal_id in (c["calendar"], c["name"]):
                return c["href"]
        raise ValueError(f"no calendar {cal_id!r} — use list_calendars")

    def _objects(self, href: str, body: bytes) -> list[tuple[str, icalendar.Calendar]]:
        root, url = self._dav("REPORT", href, body, "1")
        out = []
        for resp in root.findall("d:response", NS):
            data = resp.findtext(".//c:calendar-data", None, NS)
            if data:
                out.append((urljoin(url, resp.findtext("d:href", "", NS).strip()),
                            icalendar.Calendar.from_ical(data)))
        return out

    def events(self, start: dt.datetime, end: dt.datetime, calendar: str | None = None) -> list[dict]:
        cals = self.calendars()
        if calendar:
            cals = [c for c in cals if calendar in (c["calendar"], c["name"])]
            if not cals:
                raise ValueError(f"no calendar {calendar!r} — use list_calendars")
        q = _xml('<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
                 '<d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR">'
                 f'<c:comp-filter name="VEVENT"><c:time-range start="{_utc(start)}" end="{_utc(end)}"/>'
                 '</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>')
        out = []
        for c in cals:
            for href, ical in self._objects(c["href"], q):
                for ev in recurring_ical_events.of(ical).between(start, end):
                    s, e = ev.get("DTSTART"), ev.get("DTEND")
                    s = s.dt if s else None
                    e = e.dt if e else None
                    out.append({"calendar": c["name"] or c["calendar"], "href": href,
                                "uid": str(ev.get("UID", "")), "summary": str(ev.get("SUMMARY", "")),
                                "start": _iso(s), "end": _iso(e),
                                "all_day": s is not None and not isinstance(s, dt.datetime),
                                "location": str(ev.get("LOCATION", "")),
                                "status": str(ev.get("STATUS", "")),
                                "recurring": bool(ical.walk("VEVENT")[0].get("RRULE")) or "RECURRENCE-ID" in ev,
                                "_key": _sort_key(s) if s else _sort_key(start),
                                "_text": " ".join(str(ev.get(k, "")) for k in ("SUMMARY", "LOCATION", "DESCRIPTION"))})
        out.sort(key=lambda x: x["_key"])
        return out

    def event(self, href: str) -> dict:
        home = urlsplit(self.home())
        url = urljoin(self.home(), href)
        u = urlsplit(url)
        if u.hostname != home.hostname or not u.path.startswith(home.path):
            raise ValueError("href is outside this account's calendars")
        q = _xml('<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
                 f'<d:prop><d:getetag/><c:calendar-data/></d:prop><d:href>{urlsplit(url).path}</d:href>'
                 '</c:calendar-multiget>')
        objs = self._objects(url.rsplit("/", 1)[0] + "/", q)
        if not objs:
            raise ValueError("event not found (deleted, or href mistyped)")
        ical = objs[0][1]
        evs = ical.walk("VEVENT")
        master = next((e for e in evs if "RECURRENCE-ID" not in e), evs[0])

        def people(v):
            vs = v if isinstance(v, list) else ([v] if v else [])
            return [{"email": str(p).removeprefix("mailto:").removeprefix("MAILTO:"),
                     "name": str(p.params.get("CN", "")), "status": str(p.params.get("PARTSTAT", ""))}
                    for p in vs]

        s, e = master.get("DTSTART"), master.get("DTEND")
        desc = str(master.get("DESCRIPTION", ""))
        return {"href": url, "uid": str(master.get("UID", "")), "summary": str(master.get("SUMMARY", "")),
                "start": _iso(s.dt) if s else None, "end": _iso(e.dt) if e else None,
                "all_day": s is not None and not isinstance(s.dt, dt.datetime),
                "location": str(master.get("LOCATION", "")), "status": str(master.get("STATUS", "")),
                "description": desc[:MAX_DESCRIPTION], "description_truncated": len(desc) > MAX_DESCRIPTION,
                "url": str(master.get("URL", "")),
                "recurrence": master["RRULE"].to_ical().decode() if master.get("RRULE") else None,
                "modified_occurrences": len(evs) - 1,
                "organizer": (people(master.get("ORGANIZER")) or [None])[0],
                "attendees": people(master.get("ATTENDEE")),
                "categories": [str(c) for cat in (master.get("CATEGORIES") if isinstance(master.get("CATEGORIES"), list)
                               else [master.get("CATEGORIES")] if master.get("CATEGORIES") else [])
                               for c in cat.cats],
                "alarms": len(master.walk("VALARM"))}
