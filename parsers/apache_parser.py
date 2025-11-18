from utils.regex_patterns import APACHE_COMMON, SQLI_INDICATOR

def parse_apache_log(lines):
    """
    تعيد قائمة dicts: ip, time, code, req, suspicious(bool), raw
    """
    events = []
    for ln in lines:
        m = APACHE_COMMON.search(ln)
        if m:
            ip = m.group("ip")
            code = int(m.group("code"))
            req = m.group("req")
            suspicious = bool(SQLI_INDICATOR.search(req))
            events.append({
                "ip": ip,
                "time": m.group("time"),
                "type": f"apache_{code}",
                "code": code,
                "req": req,
                "suspicious": suspicious,
                "raw": ln
            })
    return events
