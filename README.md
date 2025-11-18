PCLATD - Python Cybersecurity Log Analyzer & Threat Detector

Quick Start:

Install dependencies:

pip install pandas matplotlib python-dateutil


Run normal analysis:

python3 main.py --auth sample_logs/auth.log --apache sample_logs/access.log --blocklist sample_logs/blocklist.txt


Output: JSON report file in reports/ and a dashboard image.

Run in real-time monitoring mode:

python main.py --auth sample_logs/auth.log --apache sample_logs/access.log --blocklist sample_logs/blocklist.txt --realtime


Project Structure:

pclatd/
    main.py
    parsers/
        __init__.py
        auth_parser.py
        apache_parser.py
    detectors/
        __init__.py
        brute_force.py
        ti_checker.py
    reports/
        __init__.py
        reporter.py
        dashboard.py
    utils/
        __init__.py
        regex_patterns.py
        file_loader.py
    sample_logs/
        auth.log
        access.log
    README.md
for any proplem you can send msg mustafazamzamkazak@gmail.com
