import os
import sys

import ida_auto
import idaapi
import ida_funcs
import ida_name
import idautils


DIAPHORA_DIR = os.environ.get(
    "DIAPHORA_DIR",
    os.path.expanduser("~/.idapro/plugins/diaphora"),
)
sys.path.insert(0, DIAPHORA_DIR)

import diaphora_ida

diaphora_ida.config.EXPORTING_COMPILATION_UNITS = False


def main() -> None:
    output = os.environ["DIAPHORA_EXPORT_FILE"]
    ida_auto.auto_wait()

    name_fragments = tuple(
        fragment
        for fragment in os.environ.get("DIAPHORA_NAME_FRAGMENTS", "").split(",")
        if fragment
    )
    selected = {
        ea
        for ea in idautils.Functions()
        if any(fragment in ida_name.get_name(ea) for fragment in name_fragments)
    }
    for raw_ea in os.environ.get("DIAPHORA_EXTRA_EAS", "").split(","):
        if not raw_ea:
            continue
        function = ida_funcs.get_func(int(raw_ea, 0))
        if function is None:
            raise RuntimeError(f"no function contains requested address {raw_ea}")
        selected.add(function.start_ea)

    if not selected:
        raise RuntimeError("no functions selected for Diaphora export")

    selected_functions = sorted(selected)
    print("Selected Diaphora functions:")
    for ea in selected_functions:
        print(f"  {ea:#x} {ida_name.get_name(ea)}")

    diaphora_ida.Functions = lambda _start, _end: iter(selected_functions)

    if os.path.exists(output):
        diaphora_ida.remove_file(output)

    differ = diaphora_ida.CIDABinDiff(output)
    differ.use_decompiler = False
    differ.export_microcode = False
    differ.function_summaries_only = True
    differ.exclude_library_thunk = True
    differ.ida_subs = True
    differ.export()
    idaapi.qexit(0)


main()
