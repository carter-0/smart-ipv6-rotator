import json
import os
import socket
import sys
from dataclasses import asdict
from time import sleep, monotonic
from typing import Iterator

import requests
from requests.adapters import HTTPAdapter

from smart_ipv6_rotator.const import (
    ICANHAZIP_IPV6_ADDRESS,
    IPROUTE,
    JSON_CONFIG_FILE,
    LOGGER,
    IPBatch,
    IFA_F_TENTATIVE,
    IFA_FLAGS,
)
from smart_ipv6_rotator.models import SavedRanges
from smart_ipv6_rotator.ranges import RANGES


def root_check(skip_root: bool = False) -> None:
    if os.geteuid() != 0 and not skip_root:
        sys.exit("[Error] Please run this script as root! It needs root privileges.")


def check_ipv6_connectivity() -> None:
    try:
        s = requests.Session()
        s.mount("http://", HTTPAdapter(max_retries=3))
        s.get("http://ipv6.icanhazip.com", timeout=10)
    except requests.Timeout:
        LOGGER.error("You do not have IPv6 connectivity. This script can not work.")
        sys.exit()
    except requests.HTTPError:
        LOGGER.error(
            "icanhazip didn't return the expected status, possibly they are down right now."
        )
        sys.exit()

    LOGGER.info("You have IPv6 connectivity. Continuing.")


def what_ranges(
    services: str | None = None,
    ipv6_ranges: str | None = None,
    no_services: bool = False,
) -> list[str]:
    """Works out what service ranges the user wants to use.

    Args:
        services (str | None, optional): Defaults to None.
        ipv6_ranges (str | None, optional): Defaults to None.
        no_services (bool, optional): Default to False

    Returns:
        list[str]: IPV6 ranges
    """

    ranges_: list[str] = []

    if services and not no_services:
        for service in services.split(","):
            if service not in RANGES:
                sys.exit(f"{service} isn't a valid service.")

            ranges_ += list(RANGES[service])

    if ipv6_ranges:
        ranges_ += ipv6_ranges.split(",")

    if not ranges_:
        sys.exit("No service or ranges given.")

    return list(set(ranges_))


def clean_ipv6_check(config: SavedRanges) -> None:
    try:
        IPROUTE.route(
            "del",
            dst=ICANHAZIP_IPV6_ADDRESS,
            prefsrc=config.random_ipv6_address,
            gateway=config.gateway,
            oif=config.interface_index,
        )
    except:
        pass


def wait_for_address_ready(
    interface_index: int, 
    ipv6_address: str, 
    timeout: float = 2.0,
    poll_interval: float = 0.05
) -> bool:
    """
    Wait for an IPv6 address to become ready (non-tentative).
    
    Args:
        interface_index: Network interface index
        ipv6_address: The IPv6 address to check
        timeout: Maximum time to wait in seconds
        poll_interval: Time between checks in seconds
        
    Returns:
        True if address becomes ready, False if timeout reached
    """
    start_time = monotonic()
    deadline = start_time + timeout
    
    while monotonic() < deadline:
        try:
            # Get all IPv6 addresses on the interface
            addrs = IPROUTE.get_addr(
                index=interface_index, 
                family=socket.AF_INET6
            )
            
            for msg in addrs:
                attrs = dict(msg.get('attrs', []))
                # Check if this is our address
                if attrs.get('IFA_ADDRESS') == ipv6_address:
                    # Check if tentative flag is set
                    flags = msg.get(IFA_FLAGS, 0)
                    if not (flags & IFA_F_TENTATIVE):
                        elapsed = monotonic() - start_time
                        LOGGER.debug(f"Address {ipv6_address} ready after {elapsed:.2f}s")
                        return True
                        
        except Exception as e:
            LOGGER.debug(f"Error checking address status: {e}")
            
        sleep(poll_interval)
    
    LOGGER.warning(f"Address {ipv6_address} still tentative after {timeout}s timeout")
    return False


def batch_add_routes(
    routes: list[dict],
    commit_timeout: float = 5.0
) -> bool:
    """
    Add multiple routes in a single batch operation.
    
    Args:
        routes: List of route dictionaries with keys matching IPRoute.route() params
        commit_timeout: Timeout for batch commit operation
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with IPBatch(commit_timeout=commit_timeout) as batch:
            for route_params in routes:
                batch.route('add', **route_params)
        LOGGER.debug(f"Successfully added {len(routes)} routes in batch")
        return True
    except Exception as e:
        LOGGER.error(f"Failed to add routes in batch: {e}")
        return False


def quick_ipv6_check(
    ipv6_address: str,
    timeout: float = 2.0,
    retry_count: int = 1,
    retry_delay: float = 0.1
) -> bool:
    """
    Quickly verify that the new IPv6 address is being used.
    
    Args:
        ipv6_address: The IPv6 address to verify
        timeout: Request timeout in seconds
        retry_count: Number of retries if first attempt fails
        retry_delay: Delay between retries in seconds
        
    Returns:
        True if verification successful, False otherwise
    """
    for attempt in range(retry_count + 1):
        try:
            response = requests.get(
                f"http://[{ICANHAZIP_IPV6_ADDRESS}]",
                headers={"host": "ipv6.icanhazip.com"},
                timeout=timeout
            )
            response.raise_for_status()
            
            returned_ip = response.text.strip()
            if returned_ip == ipv6_address:
                LOGGER.debug(f"IPv6 verification successful on attempt {attempt + 1}")
                return True
            else:
                LOGGER.warning(f"Unexpected IP returned: {returned_ip} != {ipv6_address}")
                
        except requests.exceptions.RequestException as e:
            LOGGER.debug(f"IPv6 check attempt {attempt + 1} failed: {e}")
            
        if attempt < retry_count:
            sleep(retry_delay)
    
    return False


def clean_ranges(ranges_: list[str], skip_root: bool, fast_mode: bool = False) -> None:
    """Cleans root.

    Args:
        ranges_ (list[str]):
        skip_root (bool):
        fast_mode (bool): Use minimal delays for faster cleanup
    """

    root_check(skip_root)

    previous_config = PreviousConfig(ranges_)

    previous = previous_config.get()
    if not previous:
        LOGGER.info("No cleanup of previous setup needed.")
        return

    clean_ipv6_check(previous)

    try:
        for ipv6_range in previous.ranges:
            IPROUTE.route(
                "del",
                dst=ipv6_range,
                prefsrc=previous.random_ipv6_address,
                gateway=previous.gateway,
                oif=previous.interface_index,
            )
    except:
        LOGGER.error(
            f"""Failed to remove the configured IPv6 subnets {','.join(previous.ranges)}
            May be expected if the route were not yet configured and that was a cleanup due to an error
            """
        )
    try:
        IPROUTE.addr(
            "del",
            index=previous.interface_index,
            address=previous.random_ipv6_address,
            mask=previous.random_ipv6_address_mask,
        )
    except:
        LOGGER.error("Failed to remove the random IPv6 address, very unexpected!")

    previous_config.remove()

    LOGGER.info(
        "Finished cleaning up previous setup.\nWaiting for the propagation in the Linux kernel."
    )

    # In fast mode, use minimal delay
    if fast_mode:
        sleep(0.5)  # 500ms should be enough for kernel cleanup
    else:
        sleep(6)


def previous_configs() -> Iterator[SavedRanges]:
    configs = PreviousConfig._get_raw()

    for config in configs:
        yield SavedRanges(**config)


class PreviousConfig:
    def __init__(
        self,
        ranges_: list[str],
    ) -> None:
        self.__ranges = ranges_

    @classmethod
    def _get_raw(cls) -> list[dict]:
        if not os.path.exists(JSON_CONFIG_FILE):
            return []

        with open(JSON_CONFIG_FILE, "r") as f_:
            return json.loads(f_.read())

    def __ranges_exist(self, results: dict) -> bool:
        return all(value in self.__ranges for value in results["ranges"])

    def remove(self) -> None:
        """Remove range from json file."""

        results = self._get_raw()
        to_remove_index = next(
            (
                index
                for index, ranges in enumerate(results)
                if self.__ranges_exist(ranges)
            ),
            None,
        )

        if to_remove_index is not None:
            results.pop(to_remove_index)

            with open(JSON_CONFIG_FILE, "w") as f_:
                f_.write(json.dumps(results))

    def save(self, to_save: SavedRanges) -> None:
        """Save a given service/ipv6 ranges for cleanup later.

        Args:
            ranges_ (list[str]): IPV6 ranges
        """

        self.remove()

        results = self._get_raw()
        results.append(asdict(to_save))

        with open(JSON_CONFIG_FILE, "w") as f_:
            f_.write(json.dumps(results))

    def get(self) -> SavedRanges | None:
        """Gets saved ranges.

        Returns:
            SavedRanges | None: Save ranges.
        """

        results = self._get_raw()

        for result in results:
            if self.__ranges_exist(result):
                return SavedRanges(**result)
