"""
- [ ] Comment on each process
- [ ] Click
- [ ] Enumerations for modes, etc
- [ ] Refactor mac reader
- [ ] wrap commands in a Interface controller
- [ ] Bool instead of int
- [ ] Reconnect with net ifacing down and startup without netifaces
- [ ] Use rich for command outputs
- [ ] make tests for sample arp packet
"""

from enum import Enum
import netifaces
import time
import threading
import os
from scapy.all import *
from pyfiglet import Figlet
import random
import argparse
import logging
import click




class SensorMode(str, Enum):
    Passive = "passive"
    Active = "active"


class HandlerMode(str, Enum):
    Offensive = "offensive"
    Defensive = "defensive"


class Sensor:
    """A sensor has:
    - Traffic sniffer
    - A trigger
    - Can be either active*crafting packets) or passive(sniffing) scanning
    """

    def sniff(self):
        raise NotImplementedError()

    def trigger(self):
        raise NotImplementedError()

    def __call__(self):
        raise NotImplementedError()


class Handler:
    """A handler has:
    - A response to a sensor trigger
    - Is parallelized
    - A checker to see if response worked
    """

    def check(self):
        raise NotImplementedError()

    def react(self):
        raise NotImplementedError()

    def __call__(self):
        raise NotImplementedError()


class InterfaceControlCenter:
    def __init__(self, iface_name):
        self.name = iface_name

        logging.debug(f"Interfaces are: {netifaces.interfaces()}")
        if iface_name in netifaces.interfaces():
            self.mac = scapy.all.get_if_hwaddr(self.name)
        else:
            raise Exception(f"Invalid network iterface {self.name}")

    def reset(self, iface=None):
        #if self.os == "LINUX":
        print(f"Setting {self.name} to managed mode!")
        if not os.system(f"ip link set dev {self.name} down"):
            if not os.system(f"sudo iwconfig {self.name} mode monitor"):
                if not os.system(f"ip link set dev {self.name} up"):
                    print("Interface set to managed mode")
        #else:
        #    raise NotImplementedError()

    def unlink(self):
        logging.debug(f'running command - "ip link set dev {self.name} down"')
        os.system(f"sudo ip link set dev {self.name} down")

class GatewayControlCenter:
    def __init__(self, iface_name):
        logging.debug(f"Gateways are: {netifaces.gateways()}")
        for network in netifaces.gateways()[2]:
            if iface_name in network:
                self.ip = network[0]
                self.mac = MacAddress.get_mac_address(ip=self.ip, iface_name=iface_name)
                logging.debug(f"[IP]: {self.ip}, [MAC]: {self.mac}")

class Attacker:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac

class MacAddress:
    @staticmethod
    def get_mac_address(ip, iface_name):
        arp_request = scapy.all.ARP(
            pdst=ip,
        )
        broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        response = scapy.all.srp(
            arp_request_broadcast, timeout=1, verbose=False, iface=iface_name
        )[0]
        return response[0][1].hwsrc
    
    @staticmethod
    def get_mac_vendor(attacker_mac_vendor_id):
        mac_vendor_file = open("mac_vendors.txt", "r")
        for line in mac_vendor_file:
            if attacker_mac_vendor_id in line[0:7]:
                print("Spoofer's MAC ID and vendor is ", line)


class startup:
    def __init__(
        self,
        OS="linux",
        mode="defensive",
        reset_da_iface=0,
        unlink_all_ifaces=0,
        iface=None,
        da_iface=None,
        command=None,
    ):
        self.reset_da_iface = reset_da_iface
        self.OS = OS.upper()
        self.mode = HandlerMode(mode)
        self.unlink_all_ifaces = unlink_all_ifaces
        self.command = command

        self.iface = InterfaceControlCenter(iface)
        try:
            self.da_iface = InterfaceControlCenter(da_iface)
        except:
            assert self.mode != HandlerMode.Offensive, "In offensive mode, you must have a deauth interface, capable of packet injection"
            self.da_iface = None

        self.gateway = GatewayControlCenter(self.iface.name)

    def unlink_ifaces(self):
        self.iface.unlink()
        try:
            self.da_iface.unlink()
        except:
            pass
        #for network in netifaces.gateways()[2]:
        #    os.system(f"sudo ip link set dev {network[1]} down")
        #    logging.debug(f'running command - "ip link set dev {network[1]} down"')


    def do_active_scan(self, interval=1):
        while True:
            if MacAddress.get_mac_address(ip=self.gateway.ip, iface_name=self.iface.name) == self.gateway.mac:
                logging.debug("recvd MAC id of gateway is same as self.gateway_MAC")
            else:
                if self.mode == HandlerMode.Defensive:
                    logging.debug("entering defensive mode")
                    defense_mode_thread = threading.Thread(
                        target=self.defensive_mode,
                        args=(self.unlink_all_ifaces, self.command),
                    )
                    defense_mode_thread.start()
                    logging.debug("defensive_mode_thread started")
                elif self.mode == HandlerMode.Offensive:
                    logging.debug(f"entering offensive mode with {self.da_iface.name}")
                    offense_mode_thread = threading.Thread(
                        target=self.offensive_mode, args=(self.da_iface.name,)
                    )
                    offense_mode_thread.start()
                    logging.debug("offensive_mode_thread started")
            logging.debug("sleeping for %s seconds" % str(interval))
            time.sleep(interval)

    def do_passive_scan(self):
        try:
            logging.debug("starting passive scan")
            sniff(
                iface=self.iface.name,
                prn=self.pkt_callback,
                filter=f"host  {self.gateway.ip}",
            )
        except Exception as e:
            logging.warning(f"Failed passive scan callback")
            self.unlink_ifaces()
            raise e

    def pkt_callback(self, pkt):
        if (
            pkt["Ethernet"].src != self.gateway.mac
            and pkt["Ethernet"].src != self.iface.mac
        ):
            print("MAC address changed", pkt["Ethernet"].src, pkt["Ethernet"].dst)

            self.attacker_MAC = str(pkt["Ethernet"].src)
            print(f"Attackers MAC ID is :{self.attacker_MAC}")

            logging.debug(f"Attackers MAC ID is {self.attacker_MAC}")
            attacker_mac_vendor_id = (
                str(pkt["Ethernet"].src).replace(":", "")[0:6].upper()
            )
            MacAddress.get_mac_vendor(attacker_mac_vendor_id)

            if self.mode == HandlerMode.Defensive:
                logging.debug("entering defensive mode")
                defense_mode_thread = threading.Thread(
                    target=self.defensive_mode,
                    args=(self.unlink_all_ifaces, self.command),
                )
                defense_mode_thread.start()
                logging.debug("defensive_mode_thread started")
            elif self.mode == HandlerMode.Offensive:
                logging.debug("entering offensive mode")
                offense_mode_thread = threading.Thread(
                    target=self.offensive_mode, args=(self.da_iface.name,)
                )
                offense_mode_thread.start()
                logging.debug("offensive_mode_thread started")

        else:
            print("No Problem", pkt["Ethernet"].src, pkt["Ethernet"].dst)

    def defensive_mode(self, unlink_all_ifaces=True, command=None):
        if self.OS == "LINUX":
            if unlink_all_ifaces:
                self.unlink_ifaces()
            else:
                os.system(f"sudo ip link set dev {self.iface.name} down")
                logging.debug(f'running command - "ip link set dev {self.iface.name} down"')
        elif self.OS == "WINDOWS":
            raise NotImplementedError("Windows not supported")

        if command is not None:
            os.system(command)
            logging.debug(f'running provided command - "{command}"')

    def offensive_mode(self, da_iface=None):
        print("Create deauth packets")
        self.create_deauth_packets()
        print("Setting %s to monitor mode!" % da_iface)
        if not os.system(f"sudo ip link set dev {da_iface} down"):
            if not os.system(f"sudo iwconfig {da_iface} mode monitor"):
                if not os.system(f"sudo ip link set dev {da_iface} up"):
                    print(f"{da_iface} is now running on monitor mode.")
                    print(f"Sending deauthentication packets to {self.attacker_MAC}")
                    while True:
                        logging.debug("sending deauth packets")
                        self.send_deauth_packets(da_iface)

    def create_deauth_packets(self):
        self.deauth_pkt = (
            RadioTap()
            / Dot11(
                addr1=self.gateway.mac, addr2=self.attacker_MAC, addr3=self.attacker_MAC
            )
            / Dot11Deauth(reason=7)
        )

    def send_deauth_packets(self, iface):
        try:
            sendp(self.deauth_pkt, iface=iface, verbose=True, inter=0.1, count=100)
        except KeyboardInterrupt:
            if self.reset_da_face:
                #self.reset_interface(iface=self.da_iface)
                self.da_iface.reset()
            else:
                print(
                    f"Stopped sending Deauthentication packets to {self.attacker_MAC}"
                )
                if self.reset_da_iface:
                    #self.reset_interface(iface=self.iface.name)
                    self.iface.reset()

    #def reset_interface(self, iface=None):
    #    if not iface:
    #        iface = self.da_iface
    #    if self.os == "LINUX":
    #        print(f"Setting {iface} to managed mode!")
    #        if not os.system(f"ip link set dev {iface} down"):
    #            if not os.system(f"sudo iwconfig {iface} mode monitor"):
    #                if not os.system(f"ip link set dev {iface} up"):
    #                    print("Interface set to managed mode")

@click.command()
@click.option("-m", "--mode", type=str, default="defensive", help="Set response mode")
@click.option("-s", "--scan", type=str, default="passive", help="Set scanning method")
@click.option(
    "-t", "--time_interval", type=int, default=1, help="Set scanning interval"
)
@click.option("-i", "--net_iface", type=str, default=None, help="Network interface")
@click.option("-d", "--da_iface", type=str, default=None, help="Deauth interface")
@click.option(
    "-u",
    "--unlink_all_ifaces",
    type=str,
    default="",
    help="Disconnect all interfaces connected to this network",
)
@click.option(
    "-r", "--reset_da_iface", type=str, default=False, help="Reset deauth interface "
)
@click.option(
    "-c",
    "--command",
    type=str,
    default=None,
    help="Explicitly give commands to respond in case spoofing is detected.",
)
def CLI(mode, scan, time_interval, net_iface, da_iface, unlink_all_ifaces, reset_da_iface, command):
    start = startup(
        iface=net_iface,
        da_iface=da_iface,
        OS="linux",
        reset_da_iface=reset_da_iface,
        mode=mode,
        unlink_all_ifaces=unlink_all_ifaces,
        command=command,
    )

    if scan.upper() == "ACTIVE":
        logging.debug("Active mode selected")
        active_scanner_thread = threading.Thread(
            target=start.do_active_scan, args=(time_interval,)
        )
        active_scanner_thread.start()
    elif scan.upper() == "PASSIVE":
        logging.debug("Passive mode selected")
        passive_scanner_thread = threading.Thread(target=start.do_passive_scan)
        passive_scanner_thread.start()
    else:
        print("Error: Wrong scanning mode.")
        exit()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # font=['colossal','doom','doh','isometric3','poison']

    f = Figlet(font="slant")
    print(f.renderText("shARPy"))
    CLI()
