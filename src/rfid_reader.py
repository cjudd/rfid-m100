import logging
import re
import time
from typing import Optional

import serial

from .constants import Command
from .constants import InfoVersion
from .constants import MemoryBank
from .utils import create_packet
from .utils import extract_text_from_hex
from .utils import parse_tag
from .utils import parse_tid
from .utils import verify_checksum

logger = logging.getLogger(__name__)


class RFIDReader:
    """
    RFID Reader class for ISO18000-6C / EPC C1 GEN2 protocol
    """

    def __init__(self, port: str = "/dev/ttyUSB0", baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate

    def connect(self) -> bool:
        try:
            self.serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=None,
            )
            self.serial.flush()
            return True
        except serial.SerialException as e:
            logger.exception(f"Error connecting to RFID reader: {e}")
            return False

    def disconnect(self):
        if hasattr(self, "serial") and self.serial.is_open:
            self.serial.flush()
            self.serial.close()

    def _read_hex(self) -> str:
        """Read hex data from serial port"""
        if not hasattr(self, "serial"):
            raise ValueError("Serial port not initialized")
        buffer = []
        to_read = int(getattr(self.serial, "in_waiting", 0) or 0)

        for _ in range(to_read):
            b = self.serial.read()
            if not b:
                break
            buffer.append(b.hex())

        self.serial.flush()
        return "".join(buffer)

    def send_command(
        self,
        command: Command,
        payload: Optional[bytes] = None,
        time_wait: Optional[float] = 0.1,
    ) -> bool:
        if not hasattr(self, "serial") or not self.serial.is_open:
            logger.exception("Reader is not connected")
            raise ConnectionError("Reader is not connected")

        try:
            self.serial.flush()
            self.serial.reset_input_buffer()
            frame = create_packet(command, payload)
            self.serial.write(frame)
            self.serial.write(Command.TERMINATOR.value)
            if time_wait is not None:
                # Give time for the reader to collect data
                time.sleep(time_wait)
            return True
        except Exception as e:
            logger.exception(f"Error sending command: {e}")
            return False

    def get_reader_info(self) -> Optional[dict[str, str]]:
        """Get reader information"""
        try:
            self.send_command(Command.GET_INFO, InfoVersion.HARDWARE.value)
            hw_version = self._read_hex()
            hw_version_text = extract_text_from_hex(hw_version)

            self.send_command(Command.GET_INFO, InfoVersion.SOFTWARE.value)
            sw_version = self._read_hex()
            sw_version_text = extract_text_from_hex(sw_version)

            self.send_command(Command.GET_INFO, InfoVersion.MANUFACTURERS.value)
            manufacturer = self._read_hex()
            manufacturer_text = extract_text_from_hex(manufacturer)

            return {
                "hardware_version": hw_version_text,
                "software_version": sw_version_text,
                "manufacturer": manufacturer_text,
            }

        except Exception as e:
            logger.exception(f"Error getting reader info: {e}")
            return None

    def read_tag(self) -> Optional[dict[str, str]]:
        """
        Read a single RFID tag
        Returns a dictionary with tag data if successful, None otherwise
        """
        if not hasattr(self, "serial") or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            self.send_command(Command.GET_SINGLE_POOLING, time_wait=0.4)
            buffer = self._read_hex()
            # Search for head+type+command only; exclude length bytes so tags
            # with non-96-bit EPCs (different payload length) are still matched
            prefix = Command.NOTIFICATION_POOLING.value.hex()[:6]
            pos = buffer.find(prefix)
            if pos == -1:
                return None
            payload_len = int(buffer[pos + 6 : pos + 10], 16)
            frame_len = 14 + payload_len * 2
            frame = buffer[pos : pos + frame_len]
            if len(frame) < frame_len or not verify_checksum(frame):
                return None
            tag = parse_tag(frame)
            if tag:
                tag["tid"] = self.read_tid(tag["epc"]) or ""
            return tag

        except Exception as e:
            logger.exception(f"Error reading tag: {e}")
            return None

    def read_tid(self, epc_hex: str) -> Optional[str]:
        """Read TID memory bank from a specific tag identified by its EPC."""
        try:
            epc_bytes = bytes.fromhex(epc_hex)
            epc_word_count = len(epc_bytes) // 2
            payload = (
                bytes([epc_word_count])
                + epc_bytes
                + MemoryBank.TID.value
                + b"\x00"  # word pointer = 0
                + b"\x06"  # read 6 words (12 bytes)
                + b"\x00\x00\x00\x00"  # access password
            )
            self.send_command(Command.READ_MEMORY, payload, time_wait=0.2)
            buffer = self._read_hex()
            logger.debug(f"READ_TID raw buffer: '{buffer}'")
            return parse_tid(buffer)
        except Exception as e:
            logger.exception(f"Error reading TID: {e}")
            return None

    def inventory(self, timeout: float = 1.0) -> list[dict[str, str]]:
        """
        Perform an ISO18000-6C inventory command to read multiple tags at once
        Args:
            timeout: How long to wait for response in seconds
        Returns:
            List of dictionaries containing tag data
        """
        if not hasattr(self, "serial") or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            tags: dict[str, dict[str, str]] = {}

            # Send inventory command
            # 2710: up to 10000 tags
            self.send_command(Command.GET_INVENTORY, b"\x22\x27\x10")

            # Read response
            buffer = self._read_hex()
            # Parse multiple tag response
            prefix = Command.NOTIFICATION_POOLING.value.hex()[:6]
            if buffer.startswith(prefix):
                logger.debug("Prefix matched successfully")
                # Get number of tags from response
                positions = [m.start() for m in re.finditer(re.escape(prefix), buffer)]
                boundaries = list(zip(positions, positions[1:] + [len(buffer)]))
                # Parse each tag
                for i in range(0, len(positions)):
                    start, end = boundaries[i]
                    # Minimum length for one tag frame (16-bit EPC) is 30 hex chars
                    if (end - start) < 30:
                        logger.error(
                            f"Buffer too short at tag {i}. Length: {len(buffer)}, Position: {start}"
                        )  # noqa: E501
                        break

                    tag_data = parse_tag(buffer[start:end])
                    if tag_data is None:
                        continue
                    epc = tag_data["epc"]
                    if epc not in tags:
                        tags[epc] = tag_data
                        logger.info(f"Tag data: {tag_data}")

                logger.info(f"Number of tags found: {len(tags)}")
            else:
                logger.debug("Prefix match failed")
            return list(tags.values())

        except Exception as e:
            logger.exception(f"Error during inventory: {e}")
            return []

    def automatic_frequency_hopping_mode(self, mode: bool = True) -> bool:
        if not hasattr(self, "serial") or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            self.serial.write(Command.AFHM.value)
            # xFF\xAD\x7E
            if mode:
                self.serial.write(b"\xFF")
            else:
                self.serial.write(b"\x00")

            self.serial.write(Command.TERMINATOR.value)
            time.sleep(0.1)
            return True
        except Exception as e:
            logger.exception(f"Error setting automatic frequency hopping mode: {e}")
            return False

    def get_power(self) -> Optional[float]:
        """Get reader power"""
        """ Returns a float with the dBm value """

        try:
            self.send_command(Command.GET_POWER)
            buffer = self._read_hex()
            if buffer.startswith(
                Command.GENERAL_NOTIFICATION_HEADER.value.hex()
            ) and verify_checksum(buffer):
                power = int(buffer[10:14], 16)
                return power / 100
            else:
                return None
        except Exception as e:
            logger.exception(f"Error getting power: {e}")
            return None
