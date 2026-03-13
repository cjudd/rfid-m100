#!/usr/bin/env python3
import logging
import sys
import time

from .rfid_reader import RFIDReader
from .utils import decode_epc
from .utils import decode_tid_manufacturer
from .utils import decode_tid_model
from .utils import decode_tid_serial

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def print_tag(tag: dict[str, str]):
    """Helper function to print tag information"""
    print(f"PC:           {tag['pc']}")
    print(f"EPC:          {tag['epc']}")
    epc_info = decode_epc(tag["epc"])
    print(f"  Scheme:     {epc_info['scheme']}")
    if "company_prefix" in epc_info:
        print(f"  Company:    {epc_info['company_prefix']}")
        print(f"  Item Ref:   {epc_info['item_reference']}")
        print(f"  Serial:     {epc_info['serial']}")
    elif "general_manager" in epc_info:
        print(f"  Mgr:        {epc_info['general_manager']}")
        print(f"  Class:      {epc_info['object_class']}")
        print(f"  Serial:     {epc_info['serial']}")
    tid = tag.get("tid") or ""
    print(f"TID:          {tid or 'N/A'}")
    if tid:
        print(f"  Manufacturer: {decode_tid_manufacturer(tid)}")
        print(f"  Model:        {decode_tid_model(tid)}")
        print(f"  Serial:       {decode_tid_serial(tid)}")
    user_mem = tag.get("user_memory") or ""
    if user_mem:
        print(f"User Mem:     {user_mem}")
    print(f"RSSI:         {tag['rssi']} dBm")
    print(f"CRC:          {tag['crc']}")


def print_menu():
    """Print the operation mode menu"""
    print("\nRFID Reader Modes:")
    print("1. Single Tag Reading")
    print("2. Inventory Mode (Multiple Tags)")
    print("3. Get Transmit Power")
    print("q. Quit")
    return input("Select mode (1, 2, 3, or q): ")


def single_tag_mode(reader: RFIDReader):
    """Run single tag reading mode"""
    print("\nSingle Tag Reading Mode")
    print("Press Ctrl+C to return to menu")
    try:
        while True:
            tag = reader.read_tag()
            if tag:
                print("\nTag detected!")
                print_tag(tag)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nReturning to menu...")


def inventory_mode(reader: RFIDReader):
    """Run inventory mode"""
    print("\nInventory Mode (Multiple Tags)")
    print("Press Ctrl+C to return to menu")
    try:
        while True:
            print("\nPerforming ISO18000-6C inventory...")
            tags = reader.inventory()

            if tags:
                print(f"\nFound {len(tags)} tags in this inventory round:")
                for i, tag in enumerate(tags, 1):
                    print(f"\nTag {i}:")
                    print_tag(tag)
            else:
                print("No tags found")

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nReturning to menu...")


def main():
    # Initialize the RFID reader
    reader = RFIDReader(port="/dev/tty.usbserial-144320")

    try:
        # Connect to the reader
        if not reader.connect():
            print("Failed to connect to RFID reader")
            sys.exit(1)

        print("Successfully connected to RFID reader")
        print("\nReader Information:")
        reader_info = reader.get_reader_info()
        if reader_info:
            print(f"Hardware Version: {reader_info['hardware_version']}")
            print(f"Software Version: {reader_info['software_version']}")
            print(f"Manufacturer: {reader_info['manufacturer']}")

        # Main program loop
        while True:
            choice = print_menu()

            if choice == "1":
                single_tag_mode(reader)
            elif choice == "2":
                inventory_mode(reader)
            elif choice == "3":
                power = reader.get_power()
                if power:
                    print(f"\nPower: {power} dBm")
            elif choice.lower() == "q":
                break
            else:
                print("\nInvalid choice. Please try again.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        reader.disconnect()
        print("\nRFID reader disconnected")


if __name__ == "__main__":
    main()
