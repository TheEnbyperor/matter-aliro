import base64
import datetime
import json
import pathlib
import random
import dataclasses
import enum
import typing
import cryptography.x509
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
from . import crypto, verhoeff, encoding
from .encoding import protocol_messages, TLVElement, tlv
from .interaction_model import interaction_model, cluster

BASE38_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."

def base38_encode(data: bytes) -> str:
    output = ""
    for b in [data[i:i + 3] for i in range(0, len(data), 3)]:
        if len(b) == 3:
            v = (b[2] << 16) | (b[1] << 8) | b[0]
        elif len(b) == 2:
            v = (b[1] << 8) | b[0]
        else:
            v = b[0]
        s = ""
        while v != 0:
            v, i = divmod(v, 38)
            s = f"{s}{BASE38_ALPHABET[i]}"
        if len(b) == 3:
            output += f"{s:05}"
        elif len(b) == 2:
            output += f"{s:04}"
        elif len(b) == 1:
            output += f"{s:02}"
    return output

@dataclasses.dataclass(frozen=True)
class DeviceMeta:
    vendor_id: int
    vendor_name: str
    product_id: int
    product_name: str
    primary_device_type: typing.Optional[int]
    device_name: str
    hardware_version: int = 0
    hardware_version_string: str = ""
    software_version: int = 0
    software_version_string: str = ""
    serial_number: str = ""
    unique_id: str = ""

@dataclasses.dataclass
class Fabric:
    root_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    admin_vendor_id: int
    operational_private_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    noc: bytes
    icac: typing.Optional[bytes]
    rcac: protocol_messages.MatterCertificate
    fabric_id: int
    node_id: int
    ipk: bytes
    label: str = ""

    def __post_init__(self):
        self._compressed_fabric_id = None
        self._instance_name = None

    @property
    def compressed_fabric_id(self) -> bytes:
        if self._compressed_fabric_id is None:
            cid = crypto.kdf(
                input_key=self.root_public_key.public_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.X962,
                    cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
                )[1:],
                salt=self.fabric_id.to_bytes(8, "big"),
                info=b"CompressedFabric",
                length=8
            )
            self._compressed_fabric_id = cid
            return cid
        else:
            return self._compressed_fabric_id

    @property
    def instance_name(self) -> str:
        if self._instance_name is None:
            n = f"{self.compressed_fabric_id.hex().upper()}-{self.node_id:016X}"
            self._instance_name = n
            return n
        else:
            return self._instance_name


class DeviceState:
    def __init__(self, meta: DeviceMeta, state_dir: pathlib.Path):
        self.state_dir = state_dir
        self.meta = meta
        self.country_code = "XX"
        self.discriminator = 0
        self.passcode = 0
        self.fabrics: typing.Dict[int, Fabric] = {}
        self.in_commissioning_mode = False
        self.pai_cert: typing.Optional[cryptography.x509.Certificate] = None
        self.dac_cert: typing.Optional[cryptography.x509.Certificate] = None
        self.dac_key: typing.Optional[cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey] = None
        self.next_event_id = 0
        self.events: typing.List[interaction_model.Event] = []

    def init_state(self):
        self.country_code = "XX"
        self.discriminator = random.randint(0, 0xfff)
        self.passcode = self.generate_passcode()
        self.in_commissioning_mode = True
        self.fabrics = {}
        self.events = []
        self.next_event_id = 1

    def save_state(self):
        with open(self.state_dir / "device_state.json", "w") as f:
            json.dump({
                "country_code": self.country_code,
                "discriminator": self.discriminator,
                "passcode": self.passcode,
                "next_event_id": self.next_event_id,
                "fabrics": [{
                    "id": fid,
                    "fabric": {
                        "operational_private_key": base64.b64encode(f.operational_private_key.private_bytes(
                            cryptography.hazmat.primitives.serialization.Encoding.DER,
                            cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
                            cryptography.hazmat.primitives.serialization.NoEncryption()
                        )).decode("ascii"),
                        "rcac": base64.b64encode(f.rcac.encode_to_bytes()).decode("ascii"),
                        "icac": base64.b64encode(f.icac).decode("ascii") if f.icac else None,
                        "noc": base64.b64encode(f.noc).decode("ascii"),
                        "admin_vendor_id": f.admin_vendor_id,
                        "ipk": base64.b64encode(f.ipk).decode("ascii"),
                        "label": f.label,
                    }
                } for fid, f in self.fabrics.items()],
                "events": [{
                    "key": {
                        "endpoint_id": event.key.endpoint_id,
                        "cluster_id": event.key.cluster_id,
                        "event_id": event.key.event_id,
                    },
                    "number": event.number,
                    "priority": event.priority.value,
                    "timestamp": int(event.timestamp.timestamp() * 1000),
                    "data": base64.b64encode(TLVElement(
                        tag=None,
                        data=tlv.TaggedFields.encode_type(event.data, {})
                    ).encode_to_bytes()).decode("ascii"),
                } for event in self.events]
            }, f, indent=2)

    def load_state(self):
        state_file = self.state_dir / "device_state.json"
        if state_file.is_file():
            with open(self.state_dir / "device_state.json", "r") as f:
                state = json.load(f)
                self.country_code = str(state["country_code"])
                self.discriminator = int(state["discriminator"])
                self.passcode = int(state["passcode"])
                self.in_commissioning_mode = len(state["fabrics"]) == 0
                self.next_event_id = int(state["next_event_id"])

                for fabric in state["fabrics"]:
                    pk_bytes = base64.b64decode(fabric["fabric"]["operational_private_key"])
                    pk = cryptography.hazmat.primitives.serialization.load_der_private_key(pk_bytes, None)

                    noc_bytes = base64.b64decode(fabric["fabric"]["noc"])
                    noc = protocol_messages.MatterCertificate.decode_from_bytes(noc_bytes)
                    fabric_id = next(filter(lambda a: a.variant == "matter-fabric-id", noc.subject)).value
                    node_id = next(filter(lambda a: a.variant == "matter-node-id", noc.subject)).value

                    rcac_bytes = base64.b64decode(fabric["fabric"]["rcac"])
                    rcac = protocol_messages.MatterCertificate.decode_from_bytes(rcac_bytes)
                    root_pub_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                        cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
                        rcac.ec_pub_key
                    )

                    self.fabrics[fabric["id"]] = Fabric(
                        fabric_id=fabric_id,
                        node_id=node_id,
                        operational_private_key=pk,
                        rcac=rcac,
                        root_public_key=root_pub_key,
                        icac=base64.b64decode(fabric["fabric"]["icac"]) if fabric["fabric"]["icac"] else None,
                        noc=noc_bytes,
                        admin_vendor_id=int(fabric["fabric"]["admin_vendor_id"]),
                        ipk=base64.b64decode(fabric["fabric"]["ipk"]),
                    )

                for event in state["events"]:
                    self.events.append(interaction_model.Event(
                        key=interaction_model.EventKey(
                            endpoint_id=int(event["key"]["endpoint_id"]),
                            cluster_id=int(event["key"]["cluster_id"]),
                            event_id=int(event["key"]["event_id"]),
                        ),
                        number=int(event["number"]),
                        priority=cluster.EventPriority(int(event["priority"])),
                        timestamp=datetime.datetime.fromtimestamp(int(event["timestamp"]) / 1000, datetime.UTC),
                        data=TLVElement.decode_from_bytes(base64.b64decode(event["data"])).data,
                    ))
        else:
            self.init_state()
            self.save_state()

    def load_custom_state(self, name: str) -> typing.Optional[typing.Any]:
        state_file = self.state_dir / f"state_{name}.json"
        if state_file.is_file():
            with open(self.state_dir / f"state_{name}.json", "r") as f:
                try:
                    return json.load(f)
                except json.decoder.JSONDecodeError:
                    return None
        else:
            return None

    def save_custom_state(self, name: str, state: typing.Any):
        state_file = self.state_dir / f"state_{name}.json"
        with open(self.state_dir / f"state_{name}.json", "w") as f:
            json.dump(state, f, indent=2)

    def set_pai_cert(self, cert: cryptography.x509.Certificate):
        self.pai_cert = cert

    def set_dac_cert(self, cert: cryptography.x509.Certificate):
        self.dac_cert = cert

    def set_dac_key(self, cert: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
        self.dac_key = cert

    @property
    def is_commissioned(self):
        return len(self.fabrics) > 0

    @staticmethod
    def generate_passcode():
        while True:
            candidate = random.randint(0, 99999998)
            if candidate == 0:
                continue
            elif candidate == 11111111:
                continue
            elif candidate == 22222222:
                continue
            elif candidate == 33333333:
                continue
            elif candidate == 44444444:
                continue
            elif candidate == 55555555:
                continue
            elif candidate == 66666666:
                continue
            elif candidate == 77777777:
                continue
            elif candidate == 88888888:
                continue
            elif candidate == 99999999:
                continue
            elif candidate == 12345678:
                continue
            elif candidate == 87654321:
                continue
            return candidate

    @property
    def qr_discovery_string(self) -> str:
        data = DiscoveryQRData(
            vendor_id=self.meta.vendor_id,
            product_id=self.meta.product_id,
            custom_flow=DeviceCommissioningFlow.Standard,
            discovery_capabilities=DiscoveryCapabilities(
                ble=False,
                on_ip_network=True,
                wifi_public_action_frame=False,
                nfc=False
            ),
            discriminator=self.discriminator,
            passcode=self.passcode,
        )
        return f"MT:{base38_encode(data.encode_to_bytes())}"

    @property
    def manual_discovery_string(self) -> str:
        digits = [
            str(self.discriminator >> 10),
            f"{((self.discriminator & 0x300) << 6) | (self.passcode & 0x3FFF):05}",
            f"{(self.passcode >> 14):04}"
        ]
        v = "".join(digits)
        v = f"{v:010}{verhoeff.calc_check_digit(v)}"
        return f"{v[0:4]}-{v[4:7]}-{v[7:11]}"




class DeviceCommissioningFlow(enum.Enum):
    Standard = 0
    UserIntent = 1
    Custom = 2


@dataclasses.dataclass
class DiscoveryCapabilities(encoding.BitMask):
    ble: bool
    on_ip_network: bool
    wifi_public_action_frame: bool
    nfc: bool

    class Meta:
        size = 1
        fields = (
            (1, "ble"),
            (2, "on_ip_network"),
            (3, "wifi_public_action_frame"),
            (4, "nfc"),
        )


@dataclasses.dataclass
class DiscoveryQRData(encoding.BitStruct):
    vendor_id: int
    product_id: int
    custom_flow: DeviceCommissioningFlow
    discovery_capabilities: DiscoveryCapabilities
    discriminator: int
    passcode: int

    class Meta:
        fields = (
            (3, None),
            (16, "vendor_id"),
            (16, "product_id"),
            (2, "custom_flow"),
            (8, "discovery_capabilities"),
            (12, "discriminator"),
            (27, "passcode"),
            (4, None),
        )