#!/usr/bin/env python3
import re
import sys
from enum import Enum
from dataclasses import dataclass
from argparse import ArgumentParser
# mistletoe is an OpenSource Markdown parser
# https://github.com/miyuchina/mistletoe/
import mistletoe
from mistletoe.block_token import Heading, Table
from mistletoe.span_token import InlineCode

parser = ArgumentParser(prog='generate_immtests',
                        description='Generate NEON immediate range checking \
                        tests from the ACLE specification mardown document.')
parser.add_argument('filename', type=str,
                    help='Path to a file containing the ACLE markdown')
parser.add_argument('target-header', type=str, nargs='+',
                    help='The ACLE header chain that the desired intrinsics \
                    appear under.')
parser.add_argument('-output-file', type=str,
                    help='The name of the .c file to place these tests in, \
                    the target-header string is used by default.')
parser.add_argument('-test-prefix', type=str,
                    help='Replace the default ACLE header prefix in the test \
                    function names.')
parser.add_argument('-target-features', type=str, nargs='+',
                    help='Additional feature flags needed for the RUN line')
parser.add_argument('-additional-headers', type=str, nargs='+',
                    help='Headers other than arm_neon.h to be inclued.')
parser.add_argument('--verbose', action='store_true')
parser.add_argument('--stdout', action='store_true')
parser.add_argument('--no-file', action='store_true')
args = vars(parser.parse_args())


# known position of items in a prototype list
POS_RET_TYPE = 0
POS_NAME = 1
POS_PARAM_START = 2


RUN_LINE_START_STR = '// RUN: %clang_cc1 -triple aarch64-linux-gnu -target-feature +neon '
# <optional arguments>
RUN_LINE_END_STR = ' -ffreestanding -fsyntax-only -verify %s'
REQUIRED_TARGET_STR = '// REQUIRES: aarch64-registered-target'

NEON_HEADER_STR = '#include <arm_neon.h>'
EXP_ERROR_STR = '// expected-error-re {{argument value {{.*}} is outside the valid range}}'

# FIXME: ugly
rx_range = re.compile(r"(\s*)(?P<lower>.*)(\s*)<=(\s*)(?P<name>[^\s]*)(\s*)<=(\s*)(?P<upper>.*)")
rx_single = re.compile(r"(\s*)(?P<name>[^\s]*)(\s*)==(\s*)(?P<const>.*)(\s*)")


class RangeType(Enum):
    SINGLE_VAL = 0      # parameter can only take one value
    RANGING_VAL = 1     # parameter can take a range of values


@dataclass
class RangedImm:
    lower: int
    upper: int
    range_ty: RangeType


class Intrinsic:
    """
        Intrinsic

    Represents a single Arm NEON intrinsic.

    A test is emitted for each immediate argument; a valid
    immediate is checked to raise no error, and immediates
    above and below the upper bounds are checked to raise
    a range error.
    """
    def __init__(self, proto_list: [str], immchecks):
        self.__proto_dict = {}
        self.__checks = immchecks

        self.__proto_dict['ret'] = proto_list[POS_RET_TYPE]
        self.__proto_dict['name'] = proto_list[POS_NAME]
        self.__proto_dict['params'] = []    # list of types
        for i in range(POS_PARAM_START, len(proto_list)):
            if i % 2 == 0:  # types will have an even prototype string index
                self.__proto_dict['params'].append(proto_list[i])

    def get_param_set(self) -> set:    # excluding immediates
        no_imm_types = self.__proto_dict['params']
        for i, idx in enumerate(self.__checks.keys()):  # remove immdiate types
            no_imm_types = no_imm_types[:idx - i] + no_imm_types[(idx+1) - i:]
        return set(no_imm_types)

    def get_base_type(self) -> str:
        return re.findall(r'_[^_]+\d$', self.__proto_dict['name'])[0]

    def emit_call(self, types_to_name, tested_param_idx,
                  test_value, is_error=False) -> str:
        call_str = '\t' + self.__proto_dict['name'] + '('

        for i, param in enumerate(self.__proto_dict['params']):
            if i == tested_param_idx:
                call_str += str(test_value)
            elif i in self.__checks.keys():
                call_str += str(self.__checks[i].lower)
            else:
                call_str += types_to_name[self.__proto_dict['params'][i]]

            if i != len(self.__proto_dict['params']) - 1:
                call_str += ', '

        if is_error:
            return call_str + '); ' + EXP_ERROR_STR + '\n'
        return call_str + ');\n'

    def emit_tests(self, types_to_name):
        test_str = ''

        for tested_param_idx in self.__checks.keys():
            # a test is emitted for each checked parameter
            imm_range = self.__checks[tested_param_idx]

            # tests that should pass
            test_str += self.emit_call(types_to_name, tested_param_idx,
                                       imm_range.lower)
            if imm_range.range_ty == RangeType.RANGING_VAL:
                test_str += self.emit_call(types_to_name, tested_param_idx,
                                           imm_range.upper)
            # tests that should fail
            test_str += self.emit_call(types_to_name, tested_param_idx,
                                       imm_range.lower - 1, True)
            test_str += self.emit_call(types_to_name, tested_param_idx,
                                       imm_range.upper + 1, True)

        return test_str


class TestFunc:
    """
        TestFunc

    Represents a test-containing function within the output
    test file.

    The function can contain the tests for multiple intrinsics,
    the set of parameters includes one of each type required to
    accomodate this.
    """
    def __init__(self, test_name, base_type):
        self.__func_name = 'test_' + test_name + base_type
        self.__required_types = set()
        self.__intrinsics = []

    def add_intrinsic(self, intrinsic):
        self.__required_types |= intrinsic.get_param_set()  # union
        self.__intrinsics.append(intrinsic)

    @staticmethod
    def get_size_specifier(t_string: str):
        size = re.findall(r'[\dx]+', t_string)
        if len(size):
            return t_string[0] + size[0]
        return t_string     # has no size specifier

    def generate_types_to_names(self):
        return {element: 'arg_' +
                TestFunc.get_size_specifier(element) for
                element in self.__required_types}

    def emit(self):
        types_to_names = self.generate_types_to_names()

        func_str = 'void ' + self.__func_name + '('
        for i, t in enumerate(types_to_names.keys()):
            func_str += t + ' ' + types_to_names[t]

            if i != len(types_to_names.keys()) - 1:
                func_str += ', '

        func_str += ') {\n'

        for intrinsic in self.__intrinsics:
            func_str += intrinsic.emit_tests(types_to_names)
            func_str += '\n'

        return func_str + '}\n'


class TestSet:
    """
        TestSet

    Represents a set of test functions.

    When adding intrinsics to TestSet, they are split into
    functions of their base type. This keeps test functions
    reasonably small and logically separated.
    """
    def __init__(self, test_name):
        self.__test_name = '_'.join(re.split(' |-', test_name.lower()))
        self.__funcs = {}

    def add_intrinsic(self, intrinsic):
        base = intrinsic.get_base_type()
        if base not in self.__funcs.keys():
            self.__funcs[base] = TestFunc(self.__test_name, base)
        self.__funcs[base].add_intrinsic(intrinsic)

    def emit(self):
        test = ''
        for base in self.__funcs.keys():
            test += self.__funcs[base].emit() + '\n'
        return test


class TestFile:
    """
        TestFile

    Represents a collection of test sets that should
    be emitted in a single .c output file.
    """
    def __init__(self, name):
        self.__name = name
        self.__test_sets = []

    def add_from_table(self, table: Table, prefix):
        test_set = TestSet(prefix)

        for row in table.children:
            intrinsic = row.children[0].children[0]     # intrinsic html string
            arg_preps = row.children[1].children  # list of inline code objects

            # mistletoe refuses to recognise this part... regex needed for
            # text between html tags
            removed_html = re.findall(r'\>(.*?)\<', intrinsic.content)

            stripped = ' '.join([element.strip() for element in removed_html])
            proto_list = list(filter(
                lambda x: len(x) and x != 'const', re.split(r'[(, ,,)]', stripped)))

            checked_imms = {}
            for constraint in arg_preps:
                if isinstance(constraint, InlineCode):

                    constr_str = constraint.children[0].content

                    match_ranging = rx_range.match(constr_str)
                    match_single = rx_single.match(constr_str)

                    if match_ranging:
                        param_idx = (proto_list.index(match_ranging.group('name')) - 2) // 2
                        lower = int(match_ranging.group('lower'))
                        upper = int(match_ranging.group('upper'))

                        if lower == upper:  # n <= k <= n exists in the ACLE...
                            checked_imms[param_idx] = RangedImm(lower, upper,
                                                                RangeType.SINGLE_VAL)
                        else:
                            checked_imms[param_idx] = RangedImm(lower, upper,
                                                                RangeType.RANGING_VAL)
                    elif match_single:
                        param_idx = (proto_list.index(match_single.group('name')) - 2) // 2
                        value = int(match_single.group('const'))

                        checked_imms[param_idx] = RangedImm(value, value,
                                                            RangeType.SINGLE_VAL)
            if len(checked_imms.keys()):
                test_set.add_intrinsic(Intrinsic(proto_list, checked_imms))

        self.__test_sets.append(test_set)

    def add_from_header(self, doc_children, header):
        prefix_str = args['test_prefix'] if args['test_prefix'] else header.children[-1].content

        for element in doc_children:
            if isinstance(element, Heading):
                if element.level <= header.level:   # no more tables directly
                    break                           # under the current header
                if not args['test_prefix']:
                    prefix_str = element.children[-1].content
            elif isinstance(element, Table):
                self.add_from_table(element, prefix_str)

    def emit(self):
        file_str = RUN_LINE_START_STR

        # add target features to run line
        if args['target_features']:
            for feat in args['target_features']:
                file_str += ' -target-feaure ' + feat

        file_str += RUN_LINE_END_STR + '\n\n' + NEON_HEADER_STR + '\n'
        # add additional headers to file
        if args['additional_headers']:
            for header in args['additional_headers']:
                file_str += '#include <' + header + '>\n'

        file_str += REQUIRED_TARGET_STR + '\n\n\n'

        for test_set in self.__test_sets:
            file_str += test_set.emit()

        return file_str


def generate_output(document: mistletoe.Document):
    output = TestFile(args['output_file'])

    for i, element in enumerate(document.children):
        if not isinstance(element, Heading):
            continue

        if element.children[-1].content == args['target-header'][0]:
            args['target-header'] = args['target-header'][1:]
            if not len(args['target-header']):  # header found!
                if args['verbose']:
                    print('Header found.', file=sys.stderr)

                output.add_from_header(document.children[i+1:], element)
                return output.emit()
    return None


def main():
    if not args['output_file']:
        args['output_file'] = '_'.join(
            re.split(' |-', args['target-header'][0].lower())) + '.c'

    output = None
    with open(args['filename'], 'r') as acle:
        document = mistletoe.Document(acle)
        output = generate_output(document)

    if output:
        if not args['no_file']:
            with open(args['output_file'], 'w') as out:
                out.write(output)
        if args['stdout']:
            print(output)
    else:
        if args['verbose']:
            print("Header: '" + ' '.join(args['target-header']) +
                  "' could not be found.", file=sys.stderr)


if __name__ == '__main__':
    main()
