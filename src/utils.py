from dataclasses import dataclass
from typing import Optional

from .constants import Command
from .constants import MIN_RSSI
from .constants import PacketType


@dataclass
class RequestPacket:
    """
    A packet object with attributes:
        head: Single byte header
        type: Single byte type
        command: Single byte command
        length: 16-bit unsigned int length
        payload: Bytes/bytearray of data
        checksum: Single byte checksum
        tail: Single byte trailer
    """

    head: bytes
    type: bytes
    command: bytes
    length: bytes
    payload: Optional[bytes]
    checksum: Optional[bytes]
    tail: bytes


def calculate_crc(packet: RequestPacket) -> bytes:
    """
    Calculate CRC for YRM100 protocol.
    Returns a single byte.
    """
    data = packet.type
    data += packet.command
    data += packet.length
    if packet.payload is not None:
        data += packet.payload
    crc = 0
    for byte in data:
        crc += byte
    return bytes([crc & 0xFF])


def verify_checksum(buffer: str) -> bool:
    checksum = int(buffer[-4:-2], 16)
    crc = 0
    for i in range(2, len(buffer) - 4, 2):
        crc += int(buffer[i : i + 2], 16)
    return (crc & 0xFF) == checksum


def extract_text_from_hex(hex_string: str) -> str:
    """
    Extract ASCII text from a hex string,
    starting 2 bytes after the response head 'bb0103' byte
    and excluding the last two bytes.

    Args:
        hex_string (str): like 'bb01030010004d31303020323664426d2056312e30927e'

    Returns:
        str: Decoded ASCII text
    """
    zero_pos = hex_string.find("bb0103")
    if zero_pos == -1:
        return ""
    end_pos = hex_string.find(Command.FRAME_TAIL.value.hex(), zero_pos) - 2
    if end_pos < 0:
        end_pos = -4
    hex_text = hex_string[zero_pos + 12 : end_pos]
    try:
        bytes_data = bytes.fromhex(hex_text)
        return bytes_data.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""


def pack_frame(packet) -> bytes:
    """
    Pack a packet structure into a bytes buffer.
    Args:
        packet: A RequestPacket
    Returns:
        bytes: The packed frame
    """
    pbuf = packet.head
    pbuf += packet.type
    pbuf += packet.command
    pbuf += packet.length
    if packet.payload is not None:
        pbuf += packet.payload
    pbuf += packet.checksum if packet.checksum is not None else b"\x00"
    pbuf += packet.tail
    return pbuf


_MDID_MANUFACTURERS: dict[int, str] = {
    0x001: "NXP Semiconductors",  # UCODE 5
    0x003: "NXP Semiconductors",  # UCODE 7/8
    0x006: "EM Microelectronic",
    0x007: "Motorola",
    0x008: "Alien Technology",
    0x009: "Alien Technology",
    0x00B: "Philips Semiconductor",
    0x00C: "Texas Instruments",
    0x00E: "Atmel",
    0x011: "Quanray Electronics",
    0x012: "NXP Semiconductors",
    0x800: "Impinj",
    0x801: "Impinj",  # Monza series
    0x802: "Impinj",
    0x803: "Impinj",
    0x806: "Alien Technology",  # Higgs series
    0x807: "Alien Technology",
    0x80A: "Invengo",
    0x80D: "CAEN RFID",
}


_MDN_MODELS: dict[int, dict[int, str]] = {
    0x801: {  # Impinj Monza
        0x100: "Monza 4D",
        0x101: "Monza 4QT",
        0x102: "Monza 4E",
        0x105: "Monza 4i",
        0x110: "Monza 5",
        0x114: "Monza 4",
        0x120: "Monza R6",
        0x130: "Monza R6-P",
        0x150: "Monza R6-A",
        0x160: "Monza R6-P",
        0x170: "M700",
        0x175: "M730",
        0x191: "Avery Dennison Impinj 191 R6-P",
    },
    0x003: {  # NXP UCODE
        0x400: "UCODE 6",
        0x412: "UCODE 7",
        0x413: "UCODE 7m",
        0x414: "UCODE 8",
    },
    0x806: {  # Alien Higgs
        0x004: "Higgs-3",
        0x006: "Higgs-4",
        0x008: "Higgs-9",
    },
}


def _tid_mdid_mdn(tid_hex: str) -> tuple[int, int]:
    byte1 = int(tid_hex[2:4], 16)
    byte2 = int(tid_hex[4:6], 16)
    byte3 = int(tid_hex[6:8], 16)
    mdid = (byte1 << 4) | (byte2 >> 4)
    mdn = ((byte2 & 0xF) << 8) | byte3
    return mdid, mdn


def decode_tid_manufacturer(tid_hex: str) -> str:
    """Decode chip manufacturer name from a TID hex string.

    MDID occupies bits 19:8 of the TID:
      byte 1 (all 8 bits) + upper nibble of byte 2.
    """
    if len(tid_hex) < 6 or tid_hex[:2].lower() != "e2":
        return "Unknown"
    mdid, _ = _tid_mdid_mdn(tid_hex)
    return _MDID_MANUFACTURERS.get(mdid, f"Unknown (MDID: {mdid:#05x})")


def decode_tid_model(tid_hex: str) -> str:
    """Decode chip model name from a TID hex string.

    MDN occupies bits 31:20 of the TID:
      lower nibble of byte 2 + all of byte 3.
    """
    if len(tid_hex) < 8 or tid_hex[:2].lower() != "e2":
        return "Unknown"
    mdid, mdn = _tid_mdid_mdn(tid_hex)
    return _MDN_MODELS.get(mdid, {}).get(mdn, f"Unknown (MDN: {mdn:#05x})")


def decode_tid_serial(tid_hex: str) -> str:
    """Return the 48-bit unique serial number (bytes 6-11) as a hex string."""
    if len(tid_hex) < 24:
        return ""
    return tid_hex[12:24]


def parse_tid(buffer: str) -> Optional[str]:
    """Extract TID hex string from a Read Memory (0x39) response frame.

    Response payload format: [pc_epc_len: 1 byte][PC: 2 bytes][EPC: N bytes][TID data]
    where pc_epc_len = byte count of (PC + EPC).
    """
    response_prefix = "bb0139"
    pos = buffer.find(response_prefix)
    if pos == -1:
        return None
    payload_len = int(buffer[pos + 6 : pos + 10], 16)
    frame_len = 14 + payload_len * 2
    frame = buffer[pos : pos + frame_len]
    if len(frame) < frame_len or not verify_checksum(frame):
        return None
    payload = frame[10 : 10 + payload_len * 2]
    # Skip the PC+EPC header: 1 length byte + pc_epc_len bytes of PC+EPC
    pc_epc_len = int(payload[0:2], 16)
    data_start = (1 + pc_epc_len) * 2
    return payload[data_start:] or None


_EPC_SCHEMES: dict[int, str] = {
    0x2C: "GDTI-96",
    0x2D: "GSRN-96",
    0x30: "SGTIN-96",
    0x31: "SSCC-96",
    0x32: "SGLN-96",
    0x33: "GRAI-96",
    0x34: "GIAI-96",
    0x35: "GID-96",
    0x36: "SGTIN-198",
    0x37: "GSRN-96",
    0x38: "GDTI-96",
    0x39: "CPI-96",
    0x40: "ITIP-96",
    0x41: "ITIP-110",
    0x3A: "SGCN-96",
    0x3B: "GINC",
    0x3C: "GSIN",
    0x3D: "SGLN-195",
    0x3E: "GRAI-170",
    0x3F: "GSRN-198",
    0xA9: "DoD UID",
}

# SGTIN-96 partition → (company_prefix_bits, item_ref_bits, company_digits, item_digits)
_SGTIN96_PARTITION: dict[int, tuple[int, int, int, int]] = {
    0: (40, 4, 12, 1),
    1: (37, 7, 11, 2),
    2: (34, 10, 10, 3),
    3: (30, 14, 9, 4),
    4: (27, 17, 8, 5),
    5: (24, 20, 7, 6),
    6: (20, 24, 6, 7),
}


def decode_epc(epc_hex: str) -> dict[str, str]:
    """Decode an EPC hex string into its GS1 encoding scheme and fields."""
    if len(epc_hex) < 2:
        return {"scheme": "Unknown"}
    try:
        epc_bytes = bytes.fromhex(epc_hex)
    except ValueError:
        return {"scheme": "Unknown"}

    header = epc_bytes[0]
    scheme = _EPC_SCHEMES.get(header, f"Unknown ({header:#04x})")
    result: dict[str, str] = {"scheme": scheme}

    if header == 0x30 and len(epc_bytes) == 12:
        # SGTIN-96: 96-bit integer extraction
        val = int(epc_hex, 16)
        # bits 87:85 = filter (3 bits)
        filter_val = (val >> 85) & 0x7
        # bits 84:82 = partition (3 bits)
        partition = (val >> 82) & 0x7
        if partition in _SGTIN96_PARTITION:
            cp_bits, ir_bits, cp_digits, ir_digits = _SGTIN96_PARTITION[partition]
            # company prefix starts at bit 81, width = cp_bits
            company_prefix = (val >> (82 - cp_bits)) & ((1 << cp_bits) - 1)
            # item reference follows, width = ir_bits
            item_ref = (val >> 38) & ((1 << ir_bits) - 1)
            serial = val & ((1 << 38) - 1)
            result["filter"] = str(filter_val)
            result["company_prefix"] = str(company_prefix).zfill(cp_digits)
            result["item_reference"] = str(item_ref).zfill(ir_digits)
            result["serial"] = str(serial)

    elif header == 0x35 and len(epc_bytes) == 12:
        # GID-96
        val = int(epc_hex, 16)
        general_manager = (val >> 60) & ((1 << 28) - 1)
        object_class = (val >> 36) & ((1 << 24) - 1)
        serial = val & ((1 << 36) - 1)
        result["general_manager"] = str(general_manager)
        result["object_class"] = str(object_class)
        result["serial"] = str(serial)

    return result


def parse_user_memory(buffer: str) -> Optional[str]:
    """Extract user memory hex string from a Read Memory (0x39) response frame.

    Response payload format: [pc_epc_len: 1 byte][PC: 2 bytes][EPC: N bytes][user data]
    where pc_epc_len = byte count of (PC + EPC).
    """
    response_prefix = "bb0139"
    pos = buffer.find(response_prefix)
    if pos == -1:
        return None
    payload_len = int(buffer[pos + 6 : pos + 10], 16)
    frame_len = 14 + payload_len * 2
    frame = buffer[pos : pos + frame_len]
    if len(frame) < frame_len or not verify_checksum(frame):
        return None
    payload = frame[10 : 10 + payload_len * 2]
    pc_epc_len = int(payload[0:2], 16)
    data_start = (1 + pc_epc_len) * 2
    data = payload[data_start:]
    # Return None if all zeros (empty user memory)
    return data if data and any(c != "0" for c in data) else None


def parse_tag(data: str) -> Optional[dict[str, str]]:
    raw_rssi = int(data[10:12], 16)
    rssi = -((-raw_rssi) & 0xFF)
    if rssi < MIN_RSSI:
        return None
    pc = data[12:16]
    # EPC length in words is encoded in bits 15:11 of the PC word
    epc_word_count = (int(pc, 16) >> 11) & 0x1F
    epc_hex_len = epc_word_count * 4  # each word = 2 bytes = 4 hex chars
    epc = data[16 : 16 + epc_hex_len]
    crc = data[16 + epc_hex_len : 16 + epc_hex_len + 4]
    return {"pc": pc, "epc": epc, "rssi": str(rssi), "crc": crc}


def create_packet(command: Command, payload: Optional[bytes] = None) -> bytes:
    packet = RequestPacket(
        head=Command.FRAME_HEAD.value,
        type=PacketType.COMMAND.value,
        command=command.value,
        length=(
            b"\x00\x00"
            if payload is None
            else len(payload).to_bytes(2, byteorder="big")
        ),
        payload=None if payload is None else payload,
        checksum=None,
        tail=Command.FRAME_TAIL.value,
    )
    packet.checksum = calculate_crc(packet)
    frame = pack_frame(packet)

    return frame
