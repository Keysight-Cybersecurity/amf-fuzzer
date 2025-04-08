from abc import abstractmethod

# Logging
import logging
logger = logging.getLogger(__name__)



class Packet():
    def __init__(self):
        self.original_packet = self
        self.parent_packet = None
        self.child_packet = None
        self.data = None #RAW
        self.response = None

    

class FuzzerEngine():
    @property

    @abstractmethod
    def fuzz_packet(self, packet:Packet)->Packet:
        pass

    def __createChildPacket(parent_packet:Packet)->Packet:
        child_packet = Packet()
        child_packet.original_packet = parent_packet.original_packet
        child_packet.parent_packet = parent_packet
        parent_packet.child_packet = child_packet
        return child_packet


class RandomMutationEngine(FuzzerEngine):
    def __init__(self):
        pass

    def fuzz_packet(self, packet:Packet)->Packet:
        pass

