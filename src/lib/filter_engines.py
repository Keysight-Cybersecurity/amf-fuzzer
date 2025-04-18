from pycrate_asn1dir import NGAP
from pycrate_mobile.NAS5G import *
from pyparsing import ParseException, alphas, nums, alphanums
from lib.constants import *
import random, hashlib

# Logging
import logging
logger = logging.getLogger(__name__)

ENABLE_HASHED_VARIABLES = True
SALT_LENGTH = 16


# ====================================================================================== #
#                                                                                        #
#                                     BOOLEAN PARSER                                     #
#                                                                                        #
# ====================================================================================== #

# # From https://stackoverflow.com/questions/29107499/how-to-validate-boolean-expression-syntax-using-pyparsing

# class BoolOperand(object):
#     def __init__(self,t):
#         self.label = t[0]
#         #self.value = eval(t[0])
#     def __bool__(self):
#         return self.value
#     def __str__(self):
#         return self.label
#     __repr__ = __str__
#     __nonzero__ = __bool__

# class BoolBinOp(object):
#     def __init__(self,t):
#         self.args = t[0][0::2]
#     def __str__(self):
#         sep = " %s " % self.reprsymbol
#         return "(" + sep.join(map(str,self.args)) + ")"
#     def __bool__(self):
#         return self.evalop(bool(a) for a in self.args)
#     __nonzero__ = __bool__
#     __repr__ = __str__

# class BoolAnd(BoolBinOp):
#     reprsymbol = '&'
#     evalop = all

# class BoolOr(BoolBinOp):
#     reprsymbol = '|'
#     evalop = any

# class BoolNot(object):
#     def __init__(self,t):
#         self.arg = t[0][1]
#     def __bool__(self):
#         v = bool(self.arg)
#         return not v
#     def __str__(self):
#         return "~" + str(self.arg)
#     __repr__ = __str__
#     __nonzero__ = __bool__

# TRUE = Keyword("True")
# FALSE = Keyword("False")
# #valid_chars = string.ascii_letters + string. + "_"
# boolOperand = TRUE | FALSE | Word(alphanums+"_")
# boolOperand.setParseAction(BoolOperand)

# # define expression, based on expression operand and
# # list of operations in precedence order
# boolExpr = infixNotation( boolOperand,
#     [
#     ("not", 1, opAssoc.RIGHT, BoolNot),
#     ("and", 2, opAssoc.LEFT,  BoolAnd),
#     ("or",  2, opAssoc.LEFT,  BoolOr),
#     ])







# ====================================================================================== #
#                                                                                        #
#                                     BOOLEAN PARSER                                     #
#                                                                                        #
# ====================================================================================== #

def compute_md5(data):
    md5_hash = hashlib.md5()
    md5_hash.update(data.encode('utf-8'))
    return md5_hash.hexdigest()


# Relies on Pycrates' implementation of paths.
# This filter 
# Filter effect is based on "rule for packet management" constants in constants.py
class PDU_Filter():

    def __init__(self, configuration):
        
        # Default filter values.
        self.filterOnFailBehaviour:int = None
        self.filterRuleSatisfiedBehaviour:int = None
        self.filter_rules:dict[str] = None

        filter_configuration:dict[str,str] = configuration["Filter"]
        self.filter_expression:str = filter_configuration["logic"]["expression"]
        self.filter_rules = filter_configuration["apply"]

        try:
            assert len(self.filter_expression)<MAX_EXPRESSION_LENGTH and not bool(set(self.filter_expression) & UNSECURE_CHARACTERS_EXPRESSION), f"Expression {self.filter_expression} contains unsecure characters or is too long (>{MAX_EXPRESSION_LENGTH} characters)."

            # These are going to go in eval functions later. They NEED to be safe. TODO
            
            for rule_key, rule_value in self.filter_rules.items():
                assert len(rule_key)<MAX_KEY_LENGTH and not bool(set(rule_key) & UNSECURE_CHARACTERS), f"Rule key {rule_key} contains unsecure characters or is too long (>{MAX_KEY_LENGTH} characters)."
                if type(rule_value)==str:
                    assert len(rule_value)<MAX_VALUE_LENGTH and not bool(set(rule_key) & UNSECURE_CHARACTERS), f"Rule value {rule_value} contains unsecure characters or is too long (>{MAX_VALUE_LENGTH} characters)."

        except AssertionError as e:
            logger.error(f"Assertion error: {e}",exc_info=True)


        # For security, we may want to obfuscate variable names before sending them through exec and eval.
        # Results will be the same, as this creates a bijection on a per-execution basis.
        # This only protects from variable re-assignment. Protection for eval should be re-evaluated.
        if ENABLE_HASHED_VARIABLES:
            self.__salt = ''.join(random.choices(alphas+nums, k=SALT_LENGTH))
            self.__hashed_dictionnary = dict()
            self.__filter_expression_with_hashed_values = self.filter_expression
            for plain_filter_key in self.filter_rules.keys():
                hashed_value = "var_"+compute_md5(plain_filter_key+self.__salt)
                self.__hashed_dictionnary[plain_filter_key] = hashed_value
                self.__filter_expression_with_hashed_values = self.__filter_expression_with_hashed_values.replace(plain_filter_key,hashed_value)
            

        # For effiency, so we don't have to hash the strings for comparison everytime. Also for readability.
        match filter_configuration["defaultBehaviour"]:
            case "fuzz":
                self.filterOnFailBehaviour = FUZZ_THEN_SEND_PACKET
            case "send":
                self.filterOnFailBehaviour = SEND_PACKET
            case "block":
                self.filterOnFailBehaviour = BLOCK_PACKET
            case "raiseError":
                self.filterOnFailBehaviour = RAISE_ERROR
            case _:
                raise ValueError(f"Error: filter on fail Behaviour parameter {filter_configuration["filterOnFailBehaviour"]} not accepted.")

        # For effiency, so we don't have to hash the strings for comparison everytime. Also for readability.
        match filter_configuration["ruleSatisfiedBehaviour"]:
            case "fuzz":
                self.filterRuleSatisfiedBehaviour = FUZZ_THEN_SEND_PACKET
            case "send":
                self.filterRuleSatisfiedBehaviour = SEND_PACKET
            case "block":
                self.filterRuleSatisfiedBehaviour = BLOCK_PACKET
            case "raiseError":
                self.filterRuleSatisfiedBehaviour = RAISE_ERROR
            case _:
                raise ValueError(f"Error: filter on rule satisfied behaviour parameter {filter_configuration["ruleSatisfiedBehaviour"]} not accepted.")

    
    # Watch out, this will check if rule_key is in the path name AND the endpoint value of the path has a value corresponding to rule_value
    # This means that if path = 'word1, word2, word3, word4' -> value, and rule_key = word2 and rule_value = value, then the function will output TRUE.
    # TODO We may later want to change that so it is only valid for rule_key = word4 and rule_value = value 
    def __is_rule_element_satisfied(self, pdu_paths, rule_key, rule_value):
        for path in pdu_paths:
            if rule_key in path[0] and str(rule_value)==str(path[1]):
                return True
        return False


    def __is_filter_expression_satisfied(self, paths):
        output = False

        # If security mode is enabled.
        if ENABLE_HASHED_VARIABLES:
            for rule_key, rule_value in self.filter_rules.items():
                rule_satisfied_result = str(self.__is_rule_element_satisfied(paths, rule_key, rule_value))
                string_to_evaluate = self.__hashed_dictionnary[rule_key]+"="+rule_satisfied_result
                exec(string_to_evaluate) # var_token = True/False, users won't be able to control variable re-assignment.
                # Instead of the varialbe being GLOBAL_PROTECT_MEMORY, it's going to be var_+md5hash(GLOBAL_PROTECT_NAME+salt)
            try:
                # Users may be able to execute commands, even with all useful characters disabled.
                # TODO: create a parser with a grammar for simple boolean expressions.
                output = eval(self.__filter_expression_with_hashed_values)
            except e: #TODO: Create clean exception management.
                print(e)

        # If security mode disabled. Might be helpful for debugging, but for now leave disabled.
        else:
            for rule_key, rule_value in self.filter_rules.items():
                rule_satisfied_result = str(self.__is_rule_element_satisfied(paths, rule_key, rule_value))
                string_to_evaluate = rule_key.replace("-","_")+"="+rule_satisfied_result
                exec(string_to_evaluate)

            try: #DONE: do it cleanly ! To avoid users from editing global/local variables, we may need to associate them with tokens.
                output = eval(self.filter_expression.replace("-","_"))
            except ParseException as e:
                print(e)

        return bool(output)
        

    def get_behaviour(self, paths):
        if self.__is_filter_expression_satisfied(paths):
            return self.filterRuleSatisfiedBehaviour
        else:
            return self.filterOnFailBehaviour
                    