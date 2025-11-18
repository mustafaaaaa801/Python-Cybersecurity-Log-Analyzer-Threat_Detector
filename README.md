PCLATD - Python Cybersecurity Log Analyzer & Threat Detector

تشغيل سريع:
1. ثبت المتطلبات:
   pip install pandas matplotlib python-dateutil

2. شغّل:
   python3 main.py --auth sample_logs/auth.log --apache sample_logs/access.log --blocklist sample_logs/blocklist.txt

النتيجة: ملف JSON في مجلد reports وملف صورة dashboard.
شغل مود ال real time monitor :
python main.py --auth sample_logs/auth.log --apache sample_logs/access.log --blocklist sample_logs/blocklist.txt --realtime