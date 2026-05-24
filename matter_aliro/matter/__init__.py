import asyncio
import pathlib
from . import device, mdns, interaction_model
from .message import message_layer
from .device import DeviceMeta

class Device:
    state: device.DeviceState
    message: message_layer.MessageLayer
    mdns: mdns.MDNS
    im: interaction_model.InteractionModel

    def __init__(self, meta: device.DeviceMeta, state_folder: pathlib.Path, matter_port: int, coaps_port: int):
        self.state = device.DeviceState(meta, state_folder)
        self.state.load_state()

        self.message_layer = message_layer.MessageLayer(self.state, matter_port)
        self.mdns = mdns.MDNS(self.state, self.message_layer.port, coaps_port)

        self.im = interaction_model.InteractionModel(self.state, self.message_layer, self.mdns)
        self.message_layer.register_protocol_handler(self.im)
        self.im.startup_complete()

    async def start(self):
        asyncio.create_task(self.mdns.process_packets())
        await self.message_layer.process_matter_udp_packets()

    def add_endpoint(self, e: interaction_model.Endpoint):
        self.im.add_endpoint(e)