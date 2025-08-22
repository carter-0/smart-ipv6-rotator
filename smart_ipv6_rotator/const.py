import logging

from pyroute2 import IPDB, IPRoute, IPBatch

ICANHAZIP_IPV6_ADDRESS = "2606:4700::6812:7261"

JSON_CONFIG_FILE = "/tmp/smart-ipv6-rotator.json"

LEGACY_CONFIG_FILE = "/tmp/smart-ipv6-rotator.py"

LOGGER = logging.getLogger(__name__)
LOG_LEVELS_NAMES = list(logging._nameToLevel.keys())

IP = IPDB()
IPROUTE = IPRoute()

# IPv6 address flags - IFA_F_TENTATIVE indicates DAD is in progress
IFA_F_TENTATIVE = 0x40
IFA_FLAGS = 8  # Attribute number for flags in netlink messages

__all__: list[str] = ["ICANHAZIP_IPV6_ADDRESS", "IP", "IPROUTE", "IPBatch", "IFA_F_TENTATIVE", "IFA_FLAGS"]
