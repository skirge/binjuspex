#
# Description:  Binary Ninja plugin to decompile all the codebase in Pseudo C
# and dump it into a given directory, though File -> Export would also work for some
# cases instead of using this plugin, depending on what you are trying to achieve.
#
# Author: Asher Davila (@asher_davila)
# https://github.com/AsherDLL/PCDump-bn
#

import calendar
import ntpath
import os
import platform
import re
import time
from pathlib import Path

from binaryninja import *

from tree_sitter import Language, Parser, Query
import emoji

# directory path to the current script
CURRENT_DIR = Path(__file__).parent

# tree-sitter files
TREE_SITTER_C = CURRENT_DIR / "tree-sitter-c"
TREE_SITTER_LIB = CURRENT_DIR / "build" / "tree-sitter-c.so"

# query to search tree-sitter's syntax tree for illegal identifier annotations
FUNC_ANNOT_QUERY_STR = """
(function_definition
type: (primitive_type)
declarator: (function_declarator
    declarator: (identifier)
    parameters: (parameter_list)
    . (identifier) @annotation))
"""

# symbol types that are dumped in the pseudo C
DUMPED_SYMBOL_TYPES = (
    SymbolType.DataSymbol,
    SymbolType.ImportedDataSymbol,
    SymbolType.ExternalSymbol,
    SymbolType.ImportAddressSymbol,
    SymbolType.ImportedFunctionSymbol
)

# regex for valid identifier syntax
VALID_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*")

parser: Parser
func_annot_query: Query


class PseudoCDump(BackgroundTaskThread):
    """PseudoCDump class definition.

    Attributes:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.

        msg: A string containing the message displayed when started.
        destination_path: A string containing the path of the folder where
            the Pseudo C code will be dumped.
    Class constants:
        FILE_SUFFIX: The suffix of the filenames where the content of the
            functions will be written. In this case, is a constant string 'c'
            (file extension .c).

        MAX_PATH: Maximum path length (255).            
    """
    FILE_SUFFIX = 'c'
    MAX_PATH = 255

    def __init__(self, bv: BinaryView, msg: str, destination_path: str):
        """Inits PseudoCDump class"""
        BackgroundTaskThread.__init__(self, msg, can_cancel=True)
        self.bv = bv
        self.destination_path = destination_path

    def __get_function_name(self, function: Function) -> str:
        """This private method is used to normalize the name of the function
        being dumped. It tries to use the symbol of the function if it exists
        and if the length of the destination path plus the length of the
        symbol doesn't exceed MAX_PATH. Otherwise, it uses the address at the
        start of the function. Again, it checks that the length of the
        destination path plus the length of the address(sub_<address>) doesn't
        exceed MAX_PATH. If the still exceeds MAX_PATH, it raises an exception.

        Args:
            function: A Binary Ninja Function instance containing
                the current function to be dumped.
        
        Returns:
            The string containing the normalized function name.

        Raises:
            File name too long for function <function> 
            Try using a different path.
        """
        function_symbol = self.bv.get_symbol_at(function.start)

        if hasattr(function_symbol,
                   'short_name') and (len(self.destination_path) + len(
                       function_symbol.short_name)) <= self.MAX_PATH:
            return function_symbol.short_name
        elif len(self.destination_path) + len(
                'sub_%x' % (function.start)) <= self.MAX_PATH:
            return 'sub_%x' % (function.start)
        else:
            if hasattr(function_symbol, 'short_name'):
                raise ValueError('File name too long for function: '
                                 f'{function_symbol.short_name!r}\n'
                                 'Try using a different path')
            else:
                raise ValueError('File name too long for function: '
                                 f'sub_{function.start:x}\n'
                                 'Try using a different path')

    def __create_directory(self) -> str:
        """This function creates a new directory with a name that is based on
        the name of the file that is being processed and the current time, and
        returns the path of the new directory.
        """
        directory_name = ''.join(
            (f'PseudoCDump_{ntpath.basename(self.bv.file.filename)}_',
             str(calendar.timegm(time.gmtime()))))
        new_directory = os.path.join(self.destination_path, directory_name)
        os.mkdir(new_directory)

        return new_directory

    def run(self) -> None:
        """Method representing the thread's activity. It invokes the callable
        object passed to the object's constructor as the target argument.
        Additionally, writes the content of each function into a <function_name>.c
        file in the provided destination folder.
        """
        global parser
        global func_annot_query

        disas_settings = DisassemblySettings()
        disas_settings.set_option(DisassemblyOption.ShowAddress, False)
        disas_settings.set_option(DisassemblyOption.WaitForIL, True)
        self.linear_obj = LinearViewObject.language_representation(
            self.bv, disas_settings
        )

        # initialize tree-sitter
        if not TREE_SITTER_LIB.is_file():
            Language.build_library(str(TREE_SITTER_LIB), [str(TREE_SITTER_C)])
            if not TREE_SITTER_LIB.is_file():
                raise Exception("Failed to build tree-sitter lib")

        c_language = Language(str(TREE_SITTER_LIB), "c")
        parser = Parser()
        parser.set_language(c_language)
        func_annot_query = c_language.query(FUNC_ANNOT_QUERY_STR)

        self.destination_path = self.__create_directory()
        fix_identifiers(self.bv)
        log_info(f'Number of functions to dump: {len(self.bv.functions)}')
        count = 1
        for function in self.bv.functions:
            function_name = self.__get_function_name(function)
            log_info(f'Dumping function {function_name}')
            self.progress = "Dumping Pseudo C: %d/%d" % (
                count, len(self.bv.functions))
            force_analysis(self.bv, function)
            pcode = get_pseudo_c(self.bv, function)
            destination = os.path.join(
                self.destination_path,
                normalize_destination_file(function_name, self.FILE_SUFFIX))
            with open(destination, 'wb') as file:
                file.write(bytes(pcode, 'utf-8'))
            count += 1
        log_alert(f'Done \nFiles saved in {self.destination_path}')


def normalize_destination_file(destination_file: str,
                               filename_suffix: str) -> str:
    """Normalizes the file name depending on the platform being run.
    It will replace reserved characters with an underscore '_'

    Args:
        destination_file: A string containing the file name.

        filename_suffix:  A string containing the file suffix
            (file extension).
    
    Return:
        The string containing the normalized file name.
    """
    if 'Windows' in platform.os.name:
        normalized_destination_file = '.'.join(
            (re.sub(r'[><:"/\\|\?\*]', '_',
                    destination_file), filename_suffix))
        return normalized_destination_file
    else:
        normalized_destination_file = '.'.join(
            (re.sub(r'/', '_', destination_file), filename_suffix))
        return normalized_destination_file


def force_analysis(bv: BinaryView, function: Function) -> None:
    """Binary Ninja may have skipped the analysis of the function being dumped.
    It forces the analysis of the function if Binary ninja skipped it.
    
    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: A Binary Ninja Function instance containing
            the current function to be dumped.
    """
    if function is not None and function.analysis_skipped:
        log_warn(
            ''
            f'Analyzing the skipped function {bv.get_symbol_at(function.start)}'
        )
        function.analysis_skipped = False
        # bv.update_analysis_and_wait()

def fix_identifiers(bv) -> bool:
    """
    Renames invalid identifiers ("invalid" from the C standard). Invalid
    characters are replaced with "__". Renamed identifiers are updated in
    the binary view (so pseudo C can be generated), however, they are later
    reverted to avoid destructive renaming after performing psuedo-C dump.

    Returns `True` if an identifier was renamed.
    """
    renamed = False

    # track changes
    state = bv.begin_undo_actions()

    # global vars
    #
    # use a context manager to efficiently rename symbols. "Renaming"
    # symbols here means defining a new symbol and undefining the old
    # symbol.
    with bv.bulk_modify_symbols():
        for sym in bv.get_symbols():

            # some binaries add _ in beginning of symbols
            # which confuses semgrep rules
            identifier = sym.name
            if identifier[0] == '_':
                identifier = identifier[1:]
                new_sym = Symbol(
                    sym.type,
                    sym.address,
                    identifier,
                )
                bv.define_user_symbol(new_sym)
                bv.undefine_user_symbol(sym)
                renamed = True

            if sym.type in DUMPED_SYMBOL_TYPES:

                if not VALID_IDENTIFIER_RE.fullmatch(identifier):
                    new_identifier = re.sub(r"[^a-zA-Z0-9_]", "__", identifier)
                    new_sym = Symbol(
                        sym.type,
                        sym.address,
                        identifier,
                    )
                    bv.define_user_symbol(new_sym)
                    bv.undefine_user_symbol(sym)

                    renamed = True

    # local vars
    #
    # trigger a reanalysis of the function if a variable is renamed.
    for func in bv.functions:
        for var in func.vars:
            identifier = var.name
            if not VALID_IDENTIFIER_RE.fullmatch(identifier):
                new_identifier = re.sub(r"[^a-zA-Z0-9_]", "__", identifier)
                var.name = new_identifier

                func_modified = True
                renamed = True

    # commit changes
    bv.commit_undo_actions(state)

    return renamed

def get_pseudo_c(bv: BinaryView, function: Function) -> str:
    """Gets the Pseudo C of the function being dumped. It stores every
    line of the function (header and body) into a list while the function
    is being traversed. Finally, it returns the entire function Pseudo C
    dump.

    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: A Binary Ninja Function instance containing
            the current function to be dumped.

    Return:
        lines_of_code: A single string containing the entire Pseudo C code of
            the function.
    """
    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowAddress, False)
    settings.set_option(DisassemblyOption.WaitForIL, True)
    obj = LinearViewObject.language_representation(bv, settings)
    cursor_end = LinearViewCursor(obj)
    cursor_end.seek_to_address(function.highest_address)
    body = bv.get_next_linear_disassembly_lines(cursor_end)
    cursor_end.seek_to_address(function.highest_address)
    header = bv.get_previous_linear_disassembly_lines(cursor_end)

    pseudo_c = "\n".join(
        emoji.replace_emoji(str(line.contents), replace="")
        for line in header + body
    )

    return remove_function_annotations(pseudo_c)

def remove_function_annotations(src: str) -> str:
    global parser
    global func_annot_query
    """
    Uses tree-sitter to locate invalid function annotations added by Binary
    Ninja. e.g., appending "__noreturn", "__pure" to a function definition.

    Any matches to the query string's like @annotation tags are removed,
    rest is kept the same.
    """
    tree = parser.parse(bytes(src, "utf8"))
    captures = func_annot_query.captures(tree.root_node)
    src_list = list(src)

    for node, _ in captures:
        # replace each annotation with the empty string
        for i in range(node.start_byte, node.end_byte):
            src_list[i] = ""

    # reconstruct source code from the list
    return "".join(src_list)

def dump_pseudo_c(bv: BinaryView, function=None) -> None:
    """
    Receives path and instantiates PseudoCDump, and calls PseudoCDump 
    to start the thread in the background.

    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: None.
    """
    destination_path = get_directory_name_input('Destination')

    if destination_path == None:
        log_error(''
                  'No directory was provided to save the decompiled Pseudo C')
        return

    dump = PseudoCDump(bv, 'Starting the Pseudo C Dump...', destination_path)
    dump.start()


"""Register the plugin that will be called with an address argument.
"""
PluginCommand.register_for_address('Pseudo C Dump',
                                   'Dumps Pseudo C for the whole code base',
                                   dump_pseudo_c)
