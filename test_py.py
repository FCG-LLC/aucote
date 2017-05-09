# Patterns used to check the value of component
import re

from cpe.comp.cpecomp2_3_wfn import CPEComponent2_3_WFN

_UNRESERVED = "\w|\.|\-"
_PUNC = "\!|\"|\;|\#|\$|\%|\&|\'|\(|\)|\+|\,|\/|\:|\<|\=|\>|\@|\[|\]|\^|\`|\{|\||\}|\~|\-"

#: Separator of components of CPE name with URI style
SEPARATOR_COMP = ":"

#: Separator of language parts: language and region
SEPARATOR_LANG = "-"

# Logical values in string format

#: Logical value associated with a any value logical value
VALUE_ANY = "*"

#: Logical value associated with a not applicable logical value
VALUE_NA = "-"

#: Constant associated with wildcard to indicate a sequence of characters
WILDCARD_MULTI = CPEComponent2_3_WFN.WILDCARD_MULTI
#: Constant associated with wildcard to indicate a character
WILDCARD_ONE = CPEComponent2_3_WFN.WILDCARD_ONE

# Compilation of regular expression associated with value of CPE part
_logical = "(\{0}|{1})".format(VALUE_ANY, VALUE_NA)
_quest = "\{0}".format(WILDCARD_ONE)
_asterisk = "\{0}".format(WILDCARD_MULTI)
_special = "{0}|{1}".format(_quest, _asterisk)
_spec_chrs = "{0}+|{1}".format(_quest, _asterisk)
_quoted = r"\\(\\" + "|{0}|{1})".format(_special, _PUNC)
_avstring = "{0}|{1}".format(_UNRESERVED, _quoted)
_value_string_pattern = "^(({0}+|{1}*({2})+|{3}({4})+)({5})?|{6})$".format(
    _quest, _quest, _avstring, _asterisk, _avstring, _spec_chrs, _logical)

_part_value_rxc = re.compile(_value_string_pattern)