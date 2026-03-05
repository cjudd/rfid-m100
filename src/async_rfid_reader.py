import asyncio
import logging
import re
from typing import cast
from typing import Optional

import serial
import serial_asyncio

from .constants import Command
from .constants import InfoVersion
from .constants import MemoryBank
from .rfid_reader import RFIDReader
from .utils import create_packet
from .utils import extract_text_from_hex
from .utils import parse_tag
from .utils import parse_tid
from .utils import verify_checksum


logger = logging.getLogger(__name__)


class AsyncRFIDReader(RFIDReader):
    """Async RFID Reader"""

    async def async_connect(self) -> bool:
        self.reader: asyncio.streams.StreamReader
        self.writer: asyncio.streams.StreamWriter
        try:
            self.reader, self.writer = await serial_asyncio.open_serial_connection(
                url=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )

            self.transport = cast(serial_asyncio.SerialTransport, self.writer.transport)
            await self.clear_buffers()

            return True
        except serial.SerialException as e:
            logger.exception(f"Error connecting to RFID reader: {e}")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error connecting to RFID reader: {e}")
            return False

    async def clear_buffers(self):
        if self.transport.serial:
            if self.is_port_open():
                await self.writer.drain()
            self.transport.serial.reset_input_buffer()
            self.transport.serial.reset_output_buffer()

    async def async_disconnect(self):
        if self.is_port_open():
            # ensure pending writes are flushed before closing
            await self.clear_buffers()
            self.writer.close()
            await self.writer.wait_closed()

    def is_port_open(self) -> bool:
        if not hasattr(self, "writer"):
            return False
        ser = getattr(self.transport, "serial", None)
        return bool(ser and ser.is_open)

    async def async_send_command(
        self, command: Command, payload: Optional[bytes] = None, time_wait: float = 0.1
    ) -> bool:
        if not self.is_port_open():
            logger.exception("Reader is not connected")
            raise ConnectionError("Reader is not connected")

        try:
            await self.clear_buffers()
            frame = create_packet(command, payload)

            self.writer.write(frame)
            self.writer.write(Command.TERMINATOR.value)
            await self.writer.drain()  # <-- important: let the loop flush the buffer

            if time_wait is not None:
                # Give time for the reader to collect data
                await asyncio.sleep(time_wait)
            return True
        except Exception as e:
            logger.exception(f"Error sending command: {e}")
            return False

    async def async_read_hex(self) -> str:
        """Read hex data from serial port asynchronously"""
        if not hasattr(self, "reader") or not hasattr(self, "writer"):
            raise ValueError("Serial streams not initialized")

        # using inWaiting with async does not have sense, we must read all data
        # Considering this rfid device will never sent more than 64K of data
        try:
            buffer = await asyncio.wait_for(self.reader.read(65536), timeout=0.1)
        except asyncio.TimeoutError:
            buffer = b""

        return buffer.hex()

    async def async_get_reader_info(self) -> Optional[dict[str, str]]:
        """Get reader information"""
        try:
            await self.async_send_command(Command.GET_INFO, InfoVersion.HARDWARE.value)
            hw_version = await self.async_read_hex()
            hw_version_text = extract_text_from_hex(hw_version)
            await self.async_send_command(Command.GET_INFO, InfoVersion.SOFTWARE.value)
            sw_version = await self.async_read_hex()
            sw_version_text = extract_text_from_hex(sw_version)

            await self.async_send_command(
                Command.GET_INFO, InfoVersion.MANUFACTURERS.value
            )
            manufacturer = await self.async_read_hex()
            manufacturer_text = extract_text_from_hex(manufacturer)

            return {
                "hardware_version": hw_version_text,
                "software_version": sw_version_text,
                "manufacturer": manufacturer_text,
            }

        except Exception as e:
            logger.exception(f"Error getting reader info: {e}")
            return None

    async def async_read_tag(self) -> Optional[dict[str, str]]:
        """Read a tag asynchronously"""
        try:
            await self.async_send_command(Command.GET_SINGLE_POOLING, time_wait=0.4)
            buffer = await self.async_read_hex()
            prefix = Command.NOTIFICATION_POOLING.value.hex()
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
                tid = await self.async_read_tid(tag["epc"])
                tag["tid"] = tid or ""
            return tag
        except Exception as e:
            logger.exception(f"Error reading tag: {e}")
            return None

    async def async_read_tid(self, epc_hex: str) -> Optional[str]:
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
            await self.async_send_command(Command.READ_MEMORY, payload, time_wait=0.2)
            buffer = await self.async_read_hex()
            logger.debug(f"READ_TID raw buffer: '{buffer}'")
            return parse_tid(buffer)
        except Exception as e:
            logger.exception(f"Error reading TID: {e}")
            return None

    async def async_inventory(self) -> list[dict[str, str]]:
        """Perform an ISO18000-6C inventory command to read multiple tags at once"""
        try:
            tags: dict[str, dict[str, str]] = {}
            # Send inventory command
            # 2710: up to 10000 tags
            await self.async_send_command(Command.GET_INVENTORY, b"\x22\x27\x10")
            buffer = await self.async_read_hex()
            # Parse multiple tag response
            if buffer.startswith(Command.NOTIFICATION_POOLING.value.hex()):
                logger.debug("Prefix matched successfully")
                # Get number of tags from response
                positions = [
                    m.start()
                    for m in re.finditer(
                        re.escape(Command.NOTIFICATION_POOLING.value.hex()), buffer
                    )
                ]
                boundaries = list(zip(positions, positions[1:] + [len(buffer)]))
                # Parse each tag
                for i in range(0, len(positions)):
                    start, end = boundaries[i]
                    # Minimum length for one tag data is 44 bytes
                    if (end - start) < 44:
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

    async def async_get_power(self) -> Optional[float]:
        """Get reader power"""
        """ Returns a float with the dBm value """

        try:
            await self.async_send_command(Command.GET_POWER)
            buffer = await self.async_read_hex()
            # Response frame has type=01, command=b7; search for it in the
            # buffer since leftover notification frames may precede it
            response_prefix = (
                Command.GENERAL_NOTIFICATION_HEADER.value.hex()
                + "01"
                + Command.GET_POWER.value.hex()
            )
            pos = buffer.find(response_prefix)
            if pos == -1:
                logger.debug("GET_POWER: response frame not found in buffer")
                return None
            payload_len = int(buffer[pos + 6 : pos + 10], 16)
            frame_len = 14 + payload_len * 2  # fixed overhead (7 bytes) + payload
            frame = buffer[pos : pos + frame_len]
            if not verify_checksum(frame):
                logger.debug(f"GET_POWER: checksum failed for frame '{frame}'")
                return None
            power = int(frame[10:14], 16)
            return power / 100
        except Exception as e:
            logger.exception(f"Error getting power: {e}")
            return None
