from pycrate_asn1dir import NGAP
from pycrate_mobile.NAS5G import *
from mutation_engine import FuzzerEngine
from pyparsing import infixNotation, opAssoc, Keyword, Word, alphanums, ParseException, alphas
import ast, string

MAX_KEY_LENGTH = 30
MAX_VALUE_LENGTH = 30
MAX_EXPRESSION_LENGTH = 100
UNSECURE_CHARACTERS = set('!@#$%^|&*()+{}:"<>?[];\'\\\",./`~ ')
UNSECURE_CHARACTERS_EXPRESSION = set('!@#$%^|&*+{}:"<>?[];\'\\\",./`~')


# ====================================================================================== #
#                                                                                        #
#                                     BOOLEAN PARSER                                     #
#                                                                                        #
# ====================================================================================== #

# From https://stackoverflow.com/questions/29107499/how-to-validate-boolean-expression-syntax-using-pyparsing

class BoolOperand(object):
    def __init__(self,t):
        self.label = t[0]
        #self.value = eval(t[0])
    def __bool__(self):
        return self.value
    def __str__(self):
        return self.label
    __repr__ = __str__
    __nonzero__ = __bool__

class BoolBinOp(object):
    def __init__(self,t):
        self.args = t[0][0::2]
    def __str__(self):
        sep = " %s " % self.reprsymbol
        return "(" + sep.join(map(str,self.args)) + ")"
    def __bool__(self):
        return self.evalop(bool(a) for a in self.args)
    __nonzero__ = __bool__
    __repr__ = __str__

class BoolAnd(BoolBinOp):
    reprsymbol = '&'
    evalop = all

class BoolOr(BoolBinOp):
    reprsymbol = '|'
    evalop = any

class BoolNot(object):
    def __init__(self,t):
        self.arg = t[0][1]
    def __bool__(self):
        v = bool(self.arg)
        return not v
    def __str__(self):
        return "~" + str(self.arg)
    __repr__ = __str__
    __nonzero__ = __bool__

TRUE = Keyword("True")
FALSE = Keyword("False")
#valid_chars = string.ascii_letters + string. + "_"
boolOperand = TRUE | FALSE | Word(alphanums+"_")
boolOperand.setParseAction(BoolOperand)

# define expression, based on expression operand and
# list of operations in precedence order
boolExpr = infixNotation( boolOperand,
    [
    ("not", 1, opAssoc.RIGHT, BoolNot),
    ("and", 2, opAssoc.LEFT,  BoolAnd),
    ("or",  2, opAssoc.LEFT,  BoolOr),
    ])







# ====================================================================================== #
#                                                                                        #
#                                     BOOLEAN PARSER                                     #
#                                                                                        #
# ====================================================================================== #

# Relies on Pycrates' implementation of paths.
class PDU_Filter():

    def __init__(self, configuration, fuzzer_engine:FuzzerEngine):
        
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

        filter_configuration:dict[str,str] = configuration["Filter"]

        self.filter_expression:str = filter_configuration["logic"]["expression"]

        assert len(self.filter_expression)<MAX_EXPRESSION_LENGTH and not bool(set(self.filter_expression) & UNSECURE_CHARACTERS_EXPRESSION), f"Expression {self.filter_expression} contains unsecure characters or is too long (>{MAX_EXPRESSION_LENGTH} characters)."
        

        # These are going to go in eval functions later. They NEED to be safe. TODO
        for rule_key, rule_value in filter_configuration.items():
            assert len(rule_key)<MAX_KEY_LENGTH and not bool(set(rule_key) & UNSECURE_CHARACTERS), f"Rule key {rule_key} contains unsecure characters or is too long (>{MAX_KEY_LENGTH} characters)."
            assert len(rule_value)<MAX_VALUE_LENGTH and not bool(set(rule_key) & UNSECURE_CHARACTERS), f"Rule value {rule_value} contains unsecure characters or is too long (>{MAX_VALUE_LENGTH} characters)."

        
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
                self.fuzzer_engine.fuzz_packet(pdu)
            case self.SEND_PACKET:
                return pdu
            case self.BLOCK_PACKET:
                return None
            case self.RAISE_ERROR:
                raise Exception #TODO Eh, I should really reconsider this option. It's stupid.
            case _:
                raise ValueError(f"Unknown rule value specificed : {rule}")
    
    
    def __is_filter_expression_satisfied(self, pdu):
        pdu_paths = pdu.get_val_paths()

        for rule_key, rule_value in self.rules.items():
            rule_satisfied_result = str(self.__is_rule_element_satisfied(pdu_paths, rule_key, rule_value))
            string_to_evaluate = rule_key.replace("-","_")+"="+rule_satisfied_result
            exec(string_to_evaluate)

        try: #TODO: do it cleanly !
            expr = self.filter_expression.replace("-","_")
            res = boolExpr.parseString(expr, parseAll=True)[0]
            output = eval(res)
        except ParseException as e:
            print(e)

        return bool(res)
        

    
    def __is_rule_element_satisfied(self, pdu_paths, rule_key, rule_value):
        for path in pdu_paths:
            if rule_key in path[0] and rule_value==path[1]:
                return True
        return False



    def apply_filter(self, pdu):
        if self.__is_filter_expression_satisfied(pdu):
            return self.__apply_rule(pdu, self.filterRuleSatisfiedBehaviour)
        else:
            return self.__apply_rule(pdu, self.filterOnFailBehaviour)
                    
