from collections import defaultdict
from datetime import datetime, timedelta
import dateutil.parser

def _parse_time_iso(s):
    # يحاول قراءة ISO أو يترك النص
    try:
        return dateutil.parser.isoparse(s)
    except Exception:
        # fallback: لا وقت، نعتبر الآن
        return datetime.utcnow()

def detect_brute_force(events, window_seconds=120, threshold=10):
    """
    events: قائمة dict تحتوي على keys: ip, time, type
    window_seconds: النافذة الزمنية
    threshold: كم محاولة تعتبر brute force
    تُعيد قائمة من findings: {ip, start, end, attempts, sample_events}
    """
    ip_times = defaultdict(list)
    for e in events:
        ip = e.get("ip")
        if not ip:
            continue
        t = _parse_time_iso(e.get("time"))
        ip_times[ip].append((t, e))

    findings = []
    for ip, times in ip_times.items():
        times.sort(key=lambda x: x[0])
        # sliding window
        left = 0
        for right in range(len(times)):
            while (times[right][0] - times[left][0]).total_seconds() > window_seconds:
                left += 1
            window_count = right - left + 1
            if window_count >= threshold:
                start = times[left][0].isoformat()
                end = times[right][0].isoformat()
                sample_events = [evt for (_, evt) in times[left:right+1]]
                findings.append({
                    "ip": ip,
                    "start": start,
                    "end": end,
                    "attempts": window_count,
                    "sample_events": sample_events[:10]
                })
                # Move left to avoid duplicate overlapping reports
                left = right + 1
                break
    return findings
