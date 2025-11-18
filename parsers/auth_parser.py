from utils.regex_patterns import SSH_FAIL, SSH_SUCCESS
import datetime

def _parse_time(timestr):
    # تحويل الجزء الزمني الموجود في auth.log لستامب (تقريبي - لا يتعامل مع السنة)
    try:
        dt = datetime.datetime.strptime(timestr, "%b %d %H:%M:%S")
        # نضيف السنة الحالية لتسهيل التعامل
        dt = dt.replace(year=datetime.datetime.utcnow().year)
        return dt.isoformat()
    except Exception:
        return timestr

def parse_auth_log(lines):
    """
    تُعيد قائمة dicts فيها keys: ip, time, type, user, raw
    """
    events = []
    for ln in lines:
        m = SSH_FAIL.search(ln)
        if m:
            ip = m.group('ip') or m.group('ip2')
            user = m.group('user') or m.group('inv_user')
            events.append({
                "ip": ip,
                "time": _parse_time(m.group('time')),
                "type": "ssh_fail",
                "user": user,
                "raw": ln
            })
            continue
        m2 = SSH_SUCCESS.search(ln)
        if m2:
            ip = m2.group('ip')
            events.append({
                "ip": ip,
                "time": _parse_time(m2.group('time')),
                "type": "ssh_success",
                "user": None,
                "raw": ln
            })
    return events
