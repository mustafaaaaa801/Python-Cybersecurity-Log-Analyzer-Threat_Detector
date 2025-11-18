class TIChecker:
    def __init__(self, blocklist_ips=None):
        # blocklist_ips: قائمة عناوين IP كـ str
        self.blocklist = set(blocklist_ips or [])

    def check_ips(self, ips_iterable):
        """
        يقارن ويعيد مجموعة IPs المتطابقة
        """
        return set(ip for ip in ips_iterable if ip in self.blocklist)
