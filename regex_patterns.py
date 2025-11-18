# مجموعة بترنات مفيدة لتحليل auth.log و apache access
import re

SSH_FAIL = re.compile(r'(?P<time>^[A-Za-z]{3}\s+\d+\s[\d:]+)\s(?P<host>[\w\-\._]+)\s(?:sshd|ssh):\s(?:Failed password for (?P<user>[\w\-\/]+) from (?P<ip>\d+\.\d+\.\d+\.\d+)|Invalid user (?P<inv_user>[\w\-]+) from (?P<ip2>\d+\.\d+\.\d+\.\d+))')
SSH_SUCCESS = re.compile(r'(?P<time>^[A-Za-z]{3}\s+\d+\s[\d:]+).*sshd: Accepted .* from (?P<ip>\d+\.\d+\.\d+\.\d+)')
APACHE_COMMON = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(?P<time>[^\]]+)\]\s"(?P<req>[^"]+)"\s(?P<code>\d{3})\s(?P<size>\d+|-)')
SQLI_INDICATOR = re.compile(r'(\%27)|(\')|(\-\-)|(\%23)|(#)|(\%3D.*\%27)|(\bor\b)|(\band\b)', re.IGNORECASE)
