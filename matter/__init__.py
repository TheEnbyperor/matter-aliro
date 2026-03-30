import pathlib
import threading
from . import device, mdns, interaction_model
from .message import message_layer
from .device import DeviceMeta

class Device:
    state: device.DeviceState
    message: message_layer.MessageLayer
    mdns: mdns.MDNS
    im: interaction_model.InteractionModel

    def __init__(self, meta: device.DeviceMeta, state_folder: pathlib.Path):
        self.state = device.DeviceState(meta, state_folder)
        self.state.load_state()

        self.message_layer = message_layer.MessageLayer(self.state)
        self.mdns = mdns.MDNS(self.state, self.message_layer.port)

        self.im = interaction_model.InteractionModel(self.state, self.message_layer, self.mdns)
        self.message_layer.register_protocol_handler(self.im)
        self.im.startup_complete()

    def start(self):
        t = threading.Thread(target=self.mdns.process_packets, daemon=True)
        t.start()

        self.message_layer.process_matter_udp_packets()

    def add_endpoint(self, e: interaction_model.Endpoint):
        self.im.add_endpoint(e)