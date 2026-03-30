import socket
import uuid
import random
import ifaddr
import struct
import threading
import dns.message
import dns.opcode
import dns.rdtypes.ANY.PTR
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.SRV
import dns.rdtypes.IN.AAAA
import typing
import dataclasses
from . import encoding, device

DNS_SD_SERVICES_NAME = dns.name.Name(["_services", "_dns-sd", "_udp", "local", ""])
MATTER_DNS_NAME = dns.name.Name(["_matterc", "_udp", "local", ""])
MATTER_FABRIC_DNS_NAME = dns.name.Name(["_matter", "_tcp", "local", ""])
MATTER_COMMISSIONING_DNS_NAME = dns.name.Name(["_CM", "_sub", "_matterc", "_udp", "local", ""])


class MDNS:
    def __init__(self, device_state: device.DeviceState, port: int):
        self.dns_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.dns_socket.bind(("", 5353))
        self.add_dns_socket_to_multicast_group()

        self.instance_name = f"{random.randint(0, 2 ** 64 - 1):016X}"
        self.host_name = f"{uuid.getnode():012X}"
        self.port = port
        self.device = device_state

    def add_dns_socket_to_multicast_group(self):
        mdns_addr6_bytes = socket.inet_pton(socket.AF_INET6, "ff02::fb")
        for iface in ifaddr.get_adapters():
            if any(addr.is_IPv6 for addr in iface.ips):
                iface_bin = struct.pack("@I", iface.index)
                value = mdns_addr6_bytes + iface_bin
                self.dns_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, value)
        self.dns_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        self.dns_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, True)

    def process_packets(self):
        timer = threading.Timer(1, self.send_unsolicited_packets)
        timer.start()
        while True:
            buf, addr = self.dns_socket.recvfrom(9000)
            try:
                msg = dns.message.from_wire(buf)
            except dns.exception.DNSException:
                continue
            self.process_message(msg, addr)

    def send_unsolicited_packets(self, count: int = 0):
        for iface in ifaddr.get_adapters():
            response = dns.message.Message(0)
            response.flags = dns.flags.QR
            response.set_opcode(dns.opcode.QUERY)
            response.answer.append(dns.rrset.from_rdata(
                MATTER_DNS_NAME,
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.instance_dns_name
                )
            ))
            if self.device.in_commissioning_mode:
                response.answer.append(dns.rrset.from_rdata(
                    MATTER_COMMISSIONING_DNS_NAME,
                    300,
                    dns.rdtypes.ANY.PTR.PTR(
                        dns.rdataclass.RdataClass.IN,
                        dns.rdatatype.RdataType.PTR,
                        self.instance_dns_name
                    )
                ))
            response.answer.append(dns.rrset.from_rdata(
                self.full_discriminator_dns_name,
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.instance_dns_name
                )
            ))
            response.answer.append(dns.rrset.from_rdata(
                self.partial_discriminator_dns_name,
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.instance_dns_name
                )
            ))
            response.answer.append(dns.rrset.from_rdata(
                self.vendor_id_dns_name,
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.instance_dns_name
                )
            ))
            response.answer.append(dns.rrset.from_rdata(
                self.device_type_dns_name,
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.instance_dns_name,
                )
            ))
            self.add_srv_response(None, response)
            self.add_txt_response(None, response)
            self.add_addr_response(None, response, iface.index)

            response_wire = response.to_wire()
            self.dns_socket.sendto(response_wire, ("ff02::fb", 5353, 0, iface.index))

        if count < 8:
            timer = threading.Timer(2 ** count, self.send_unsolicited_packets, args=(count + 1,))
            timer.start()

    def send_unsolicited_fabric_packets(self, fabric_index: int, count: int = 0):
        fabric = self.device.fabrics[fabric_index]
        for iface in ifaddr.get_adapters():
            response = dns.message.Message(0)
            response.flags = dns.flags.QR
            response.set_opcode(dns.opcode.QUERY)
            response.answer.append(dns.rrset.from_rdata(
                MATTER_FABRIC_DNS_NAME,
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.fabric_instance_dns_name(fabric)
                )
            ))
            response.answer.append(dns.rrset.from_rdata(
                self.fabric_discriminator_dns_name(fabric),
                300,
                dns.rdtypes.ANY.PTR.PTR(
                    dns.rdataclass.RdataClass.IN,
                    dns.rdatatype.RdataType.PTR,
                    self.fabric_instance_dns_name(fabric)
                )
            ))
            self.add_fabric_srv_response(fabric, None, response)
            self.add_txt_response(None, response)
            self.add_addr_response(None, response, iface.index)

            response_wire = response.to_wire()
            self.dns_socket.sendto(response_wire, ("ff02::fb", 5353, 0, iface.index))

        if count < 8:
            timer = threading.Timer(2 ** count, self.send_unsolicited_packets, args=(count + 1,))
            timer.start()

    def process_message(self, msg: dns.message.Message, source_addr):
        if msg.opcode() == dns.opcode.QUERY and not (msg.flags & dns.flags.QR):
            response = dns.message.Message(msg.id)
            response.flags = dns.flags.QR | dns.flags.AA
            response.set_opcode(dns.opcode.QUERY)
            for question in msg.question:
                if question.rdclass != dns.rdataclass.RdataClass.IN:
                    continue
                if question.rdtype == dns.rdatatype.RdataType.PTR:
                    if question.name == DNS_SD_SERVICES_NAME:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            DNS_SD_SERVICES_NAME,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                MATTER_DNS_NAME,
                            )
                        ))
                        continue
                    elif question.name == MATTER_DNS_NAME:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            MATTER_DNS_NAME,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                self.instance_dns_name
                            )
                        ))
                    elif question.name == MATTER_COMMISSIONING_DNS_NAME and self.device.in_commissioning_mode:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            MATTER_COMMISSIONING_DNS_NAME,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                self.instance_dns_name
                            )
                        ))
                    elif question.name == self.full_discriminator_dns_name:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            self.full_discriminator_dns_name,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                self.instance_dns_name
                            )
                        ))
                    elif question.name == self.partial_discriminator_dns_name:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            self.partial_discriminator_dns_name,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                self.instance_dns_name
                            )
                        ))
                    elif question.name == self.vendor_id_dns_name:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            self.vendor_id_dns_name,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                self.instance_dns_name
                            )
                        ))
                    elif self.device.meta.primary_device_type is not None and question.name == self.device_type_dns_name:
                        self.add_dns_response(msg, response, dns.rrset.from_rdata(
                            self.device_type_dns_name,
                            300,
                            dns.rdtypes.ANY.PTR.PTR(
                                dns.rdataclass.RdataClass.IN,
                                dns.rdatatype.RdataType.PTR,
                                self.instance_dns_name,
                            )
                        ))
                    else:
                        if question.name == MATTER_FABRIC_DNS_NAME:
                            for fabric in self.device.fabrics.values():
                                self.add_dns_response(msg, response, dns.rrset.from_rdata(
                                    MATTER_FABRIC_DNS_NAME,
                                    300,
                                    dns.rdtypes.ANY.PTR.PTR(
                                        dns.rdataclass.RdataClass.IN,
                                        dns.rdatatype.RdataType.PTR,
                                        self.fabric_instance_dns_name(fabric)
                                    )
                                ))
                                self.add_fabric_srv_response(fabric, msg, response, additional=True)
                                self.add_fabric_txt_response(fabric, msg, response, additional=True)
                                self.add_addr_response(msg, response, source_addr[3], additional=True)
                        else:
                            for fabric in self.device.fabrics.values():
                                dn = self.fabric_discriminator_dns_name(fabric)
                                if question.name == dn:
                                    self.add_dns_response(msg, response, dns.rrset.from_rdata(
                                        dn,
                                        300,
                                        dns.rdtypes.ANY.PTR.PTR(
                                            dns.rdataclass.RdataClass.IN,
                                            dns.rdatatype.RdataType.PTR,
                                            self.fabric_instance_dns_name(fabric)
                                        )
                                    ))
                                    self.add_fabric_srv_response(fabric, msg, response, additional=True)
                                    self.add_fabric_txt_response(fabric, msg, response, additional=True)
                                    self.add_addr_response(msg, response, source_addr[3], additional=True)
                        continue
                    self.add_srv_response(msg, response, additional=True)
                    self.add_txt_response(msg, response, additional=True)
                    self.add_addr_response(msg, response, source_addr[3], additional=True)
                elif question.rdtype == dns.rdatatype.RdataType.SRV:
                    if question.name == self.instance_dns_name:
                        self.add_srv_response(msg, response)
                        self.add_txt_response(msg, response, additional=True)
                        self.add_addr_response(msg, response, source_addr[3], additional=True)
                    for fabric in self.device.fabrics.values():
                        if question.name == self.fabric_instance_dns_name(fabric):
                            self.add_fabric_srv_response(fabric, msg, response)
                            self.add_fabric_txt_response(fabric, msg, response, additional=True)
                            self.add_addr_response(msg, response, source_addr[3], additional=True)
                elif question.rdtype == dns.rdatatype.RdataType.TXT:
                    if question.name == self.instance_dns_name:
                        self.add_txt_response(msg, response)
                        self.add_srv_response(msg, response, additional=True)
                        self.add_addr_response(msg, response, source_addr[3], additional=True)
                    for fabric in self.device.fabrics.values():
                        if question.name == self.fabric_instance_dns_name(fabric):
                            self.add_fabric_txt_response(fabric, msg, response)
                            self.add_fabric_srv_response(fabric, msg, response, additional=True)
                            self.add_addr_response(msg, response, source_addr[3], additional=True)
                elif question.rdtype == dns.rdatatype.RdataType.AAAA:
                    if question.name == self.device_dns_name:
                        self.add_addr_response(msg, response, source_addr[3])

            if response.answer:
                response_wire = response.to_wire()
                self.dns_socket.sendto(response_wire, ("ff02::fb", 5353, 0, source_addr[3]))

    def add_srv_response(self, query: typing.Optional[dns.message.Message], response: dns.message.Message,
                         additional: bool = False):
        self.add_dns_response(query, response, dns.rrset.from_rdata(
            self.instance_dns_name,
            300,
            dns.rdtypes.IN.SRV.SRV(
                dns.rdataclass.RdataClass.IN,
                dns.rdatatype.RdataType.SRV,
                0,
                0,
                self.port,
                self.device_dns_name
            )
        ), additional)

    def add_fabric_srv_response(self, fabric: device.Fabric, query: typing.Optional[dns.message.Message],
                                response: dns.message.Message, additional: bool = False):
        self.add_dns_response(query, response, dns.rrset.from_rdata(
            self.fabric_instance_dns_name(fabric),
            300,
            dns.rdtypes.IN.SRV.SRV(
                dns.rdataclass.RdataClass.IN,
                dns.rdatatype.RdataType.SRV,
                0,
                0,
                self.port,
                self.device_dns_name
            )
        ), additional)

    def add_addr_response(self, query: typing.Optional[dns.message.Message], response: dns.message.Message,
                          scope_id: int, additional: bool = False):
        iface: typing.Optional[ifaddr.Adapter] = next(
            filter(lambda i: i.index == scope_id, ifaddr.get_adapters()), None)
        if not iface:
            return
        for addr in iface.ips:
            if addr.is_IPv6:
                self.add_dns_response(query, response, dns.rrset.from_rdata(
                    self.device_dns_name,
                    300,
                    dns.rdtypes.IN.AAAA.AAAA(
                        dns.rdataclass.RdataClass.IN,
                        dns.rdatatype.RdataType.AAAA,
                        addr.ip[0]
                    )
                ), additional)

    def add_txt_response(self, query: typing.Optional[dns.message.Message], response: dns.message.Message,
                         additional: bool = False):
        d = {
            "D": str(self.device.discriminator),
            "VP": f"{self.device.meta.vendor_id}+{self.device.meta.product_id}",
            "CM": "1" if self.device.in_commissioning_mode else "0",
            "T": str(SupportedTransportModes(
                tcp_client=False,
                tcp_server=False,
            ).encode_to_bytes()[0])
        }
        if self.device.meta.primary_device_type is not None:
            d["DT"] = str(self.device.meta.primary_device_type)
        if self.device.meta.device_name:
            d["DN"] = self.device.meta.device_name
        self.add_dns_response(query, response, dns.rrset.from_rdata(
            self.instance_dns_name,
            300,
            dns.rdtypes.ANY.TXT.TXT(
                dns.rdataclass.RdataClass.IN,
                dns.rdatatype.RdataType.TXT,
                self.encode_dns_sd_txt(d)
            )
        ), additional)

    def add_fabric_txt_response(self, fabric: device.Fabric, query: typing.Optional[dns.message.Message],
                                response: dns.message.Message, additional: bool = False):
        self.add_dns_response(query, response, dns.rrset.from_rdata(
            self.fabric_instance_dns_name(fabric),
            300,
            dns.rdtypes.ANY.TXT.TXT(
                dns.rdataclass.RdataClass.IN,
                dns.rdatatype.RdataType.TXT,
                self.encode_dns_sd_txt({
                    "T": str(SupportedTransportModes(
                        tcp_client=False,
                        tcp_server=False,
                    ).encode_to_bytes()[0])
                })
            )
        ), additional)

    @staticmethod
    def encode_dns_sd_txt(data: typing.Dict) -> typing.List[bytes]:
        out = []
        for k, v in data.items():
            if isinstance(v, bool):
                if v:
                    out.append(k.encode("ascii"))
            else:
                i = bytearray(k.encode("ascii"))
                i.extend(b"=")
                if isinstance(v, str):
                    i.extend(v.encode("utf-8"))
                else:
                    i.extend(bytes(v))
                out.append(bytes(i))
        return out

    @staticmethod
    def add_dns_response(query: typing.Optional[dns.message.Message], response: dns.message.Message,
                         rrset: dns.rrset.RRset, additional: bool = False):
        if not query:
            response.answer.append(rrset)
            return

        known_rrset = next(
            filter(
                lambda r: r.name == rrset.name and r.rdclass == rrset.rdclass and r.rdtype == rrset.rdtype,
                query.answer
            ), None
        )
        if not known_rrset:
            if not additional:
                response.answer.append(rrset)
            else:
                response.additional.append(rrset)
        else:
            if known_rrset.ttl < rrset.ttl // 2:
                if not additional:
                    response.answer.append(rrset)
                else:
                    response.additional.append(rrset)
            else:
                response_rdatas = rrset.difference(known_rrset)
                if response_rdatas:
                    rrset = dns.rrset.from_rdata(rrset.name, rrset.ttl, *response_rdatas)
                    if not additional:
                        response.answer.append(rrset)
                    else:
                        response.additional.append(rrset)

    @property
    def instance_dns_name(self) -> dns.name.Name:
        return dns.name.Name([self.instance_name, "_matterc", "_udp", "local", ""])

    @staticmethod
    def fabric_instance_dns_name(fabric: device.Fabric) -> dns.name.Name:
        return dns.name.Name([fabric.instance_name, "_matter", "_tcp", "local", ""])

    @property
    def device_dns_name(self) -> dns.name.Name:
        return dns.name.Name([self.host_name, "local", ""])

    @property
    def full_discriminator_dns_name(self) -> dns.name.Name:
        return dns.name.Name([f"_L{self.device.discriminator}", "_sub", "_matterc", "_udp", "local", ""])

    @property
    def partial_discriminator_dns_name(self) -> dns.name.Name:
        return dns.name.Name([f"_S{self.device.discriminator >> 8}", "_sub", "_matterc", "_udp", "local", ""])

    @property
    def vendor_id_dns_name(self) -> dns.name.Name:
        return dns.name.Name([f"_V{self.device.meta.vendor_id}", "_sub", "_matterc", "_udp", "local", ""])

    @property
    def device_type_dns_name(self) -> dns.name.Name:
        return dns.name.Name([f"_D{self.device.meta.primary_device_type}", "_sub", "_matterc", "_udp", "local", ""])

    @staticmethod
    def fabric_discriminator_dns_name(fabric: device.Fabric) -> dns.name.Name:
        return dns.name.Name([f"_I{fabric.compressed_fabric_id.hex().upper()}", "_sub", "_matter", "_tcp", "local", ""])


@dataclasses.dataclass
class SupportedTransportModes(encoding.BitMask):
    tcp_client: bool
    tcp_server: bool

    class Meta:
        size = 1
        fields = (
            (1, "tcp_client"),
            (2, "tcp_server"),
        )
