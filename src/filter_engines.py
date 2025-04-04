from pycrate_asn1dir import NGAP
from pycrate_mobile.NAS5G import *
from mutation_engine import FuzzerEngine

# Relies on Pycrates' implementation of paths.
class PDU_Filter():

    def __init__(self, configuration:dict, fuzzer_engine:FuzzerEngine):
        
        self.WHITELIST = True
        self.BLACKLIST = False
        # Default Behaviour
        self.FUZZ_THEN_SEND_PACKET = 0
        self.SEND_PACKET = 1
        self.BLOCK_PACKET = 2
        self.RAISE_ERROR = 3

        self.filterType:int = None
        self.filterOnFailBehaviour:int = None
        self.filterRuleSatisfiedBehaviour:int = None
        self.rules:dict[str] = None
        self.fuzzer_engine = fuzzer_engine

        filter_configuration = configuration["Filter"]
        match filter_configuration["filterType"]:
            case "whitelist":
                self.filterType = self.WHITELIST
            case "blacklist":
                self.filterType = self.BLACKLIST
            case _:
                raise ValueError(f"Error: filter type {filter_configuration["filterType"]} not accepted.")
        
        match filter_configuration["defaultBehaviour"]:
            case "fuzz":
                self.filterOnFailBehaviour = self.FUZZ_THEN_SEND_PACKET
            case "send":
                self.filterOnFailBehaviour = self.SEND_PACKET
            case "block":
                self.filterOnFailBehaviour = self.BLOCK_PACKET
            case "raiseError":
                self.filterOnFailBehaviour = self.RAISE_ERROR
            case _:
                raise ValueError(f"Error: filter on fail Behaviour parameter {filter_configuration["filterOnFailBehaviour"]} not accepted.")

        match filter_configuration["ruleSatisfiedBehaviour"]:
            case "fuzz":
                self.filterRuleSatisfiedBehaviour = self.FUZZ_THEN_SEND_PACKET
            case "send":
                self.filterRuleSatisfiedBehaviour = self.SEND_PACKET
            case "block":
                self.filterRuleSatisfiedBehaviour = self.BLOCK_PACKET
            case "raiseError":
                self.filterRuleSatisfiedBehaviour = self.RAISE_ERROR
            case _:
                raise ValueError(f"Error: filter on rule satisfied behaviour parameter {filter_configuration["ruleSatisfiedBehaviour"]} not accepted.")

        self.rules = filter_configuration["apply"]


    def __apply_rule(self, pdu, rule):
        match rule:
            case self.FUZZ_THEN_SEND_PACKET:
                self.fuzzer_engine.fuzz(pdu)
            case self.SEND_PACKET:
                return pdu
            case self.BLOCK_PACKET:
                return None
            case self.RAISE_ERROR:
                raise Exception #Eh, I should really reconsider this option. It's stupid.
            case _:
                raise ValueError(f"Unknown rule value specificed : {rule}")

    def __is_rule_satisfied(self, pdu):
        for path in pdu.get_val_paths():
            for key in self.rules.keys():
                if key in path[0] and path[1]==self.rules[key]:
                    return True
        return False
    

    def apply_filter(self, pdu):
        # Four cases: let flag_apply_rule be A
        #   - if rule satisfied and whitebox : apply "rule satisfied behaviour"
        #   - if rule satisfied and blackbox : apply "default behaviour"
        #   - if rule NOT satisfied and whitebox : apply "default behaviour"
        #   - if rule NOT satisfied and blackbox : apply "rule satisfied behaviour"
        if not (self.__is_rule_satisfied(pdu) ^ self.WHITELIST):
            return self.__apply_rule(pdu, self.filterRuleSatisfiedBehaviour)
        else:
            return self.__apply_rule(pdu, self.filterOnFailBehaviour)
                    