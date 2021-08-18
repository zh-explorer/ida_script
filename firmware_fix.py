import idaapi
import ida_ida
import ida_kernwin
import ida_search
import ida_funcs
import idautils
import ida_bytes
import ida_offset
import ida_segment

import functools
import typing


def on_first_call_method(func: callable):
    first: bool = True

    def call_decorator(f):
        @functools.wraps(f)
        def wrapped_function(self, *args, **kwargs):
            nonlocal first
            if first:
                func(self)
                first = False
            return f(self, *args, **kwargs)

        return wrapped_function

    return call_decorator


def disable_filed(self):
    input_list = [self.iStartCode, self.iEndCode, self.iStartStr, self.iEndStr, self.iStartP, self.iEndP]
    for ctrl in input_list:
        self.EnableField(ctrl, 0)


class InfoForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""Segment Info

{FormChangeCb}
<Fix function: {rFunc}>{ChkFunc}>
<## Start of code        :{iStartCode}>
<## End of code          :{iEndCode}>

<Fix string: {rString}>{ChkStr}>
<## Start of string      :{iStartStr}>
<## End of string        :{iEndStr}>

<Fix data reg: {rData}>{ChkData}>
<## Start of data point  :{iStartP}>
<## End of data point    :{iEndP}>
            """, {
                "ChkFunc": F.ChkGroupControl(("rFunc",)),
                "ChkStr": F.ChkGroupControl(("rString",)),
                "ChkData": F.ChkGroupControl(("rData",)),
                "iStartCode": F.NumericInput(tp=F.FT_ADDR),
                "iEndCode": F.NumericInput(tp=F.FT_ADDR),
                "iStartStr": F.NumericInput(tp=F.FT_ADDR),
                "iEndStr": F.NumericInput(tp=F.FT_ADDR),
                "iStartP": F.NumericInput(tp=F.FT_ADDR),
                "iEndP": F.NumericInput(tp=F.FT_ADDR),
                "FormChangeCb": F.FormChangeCb(self.OnFormChange)
            }
        )

    @on_first_call_method(disable_filed)
    def OnFormChange(self, fid):
        notify_ctr = (self.rFunc, self.rString, self.rData)
        notify_map = dict(map(lambda x: (x.id, x), notify_ctr))

        control_map = {
            self.rFunc: (self.iStartCode, self.iEndCode),
            self.rString: (self.iStartStr, self.iEndStr),
            self.rData: (self.iStartP, self.iEndP),
        }

        if fid in notify_map:
            ctrl = notify_map[fid]
            for i in control_map[ctrl]:
                self.EnableField(i, self.GetControlValue(ctrl))
        return 1

    @staticmethod
    def show_from() -> typing.Dict[str, typing.Tuple]:
        f = InfoForm()
        f.Compile()

        value_map = {
            "func": {"ctrl": f.rFunc, "start": f.iStartCode, "end": f.iEndCode},
            "str": {"ctrl": f.rString, "start": f.iStartStr, "end": f.iEndStr},
            "data": {"ctrl": f.rData, "start": f.iStartP, "end": f.iEndP},
        }

        for key, value in value_map.items():
            value["start"].value = ida_ida.inf_get_min_ea()
            value["end"].value = ida_ida.inf_get_max_ea()

        ok = f.Execute()
        if ok == 1:
            res = {}
            for key, value in value_map.items():
                if value["ctrl"].checked:
                    res[key] = (value["start"].value, value["end"].value)
            return res
        else:
            return {}


class Context(object):
    accept_process = ("ARM", "MIPS", "metapc")

    def __init__(self):
        if ida_ida.idainfo_is_64bit():
            self.bits = 64
        elif ida_ida.idainfo_is_32bit():
            self.bits = 32
        else:
            self.bits = 16

        self.is_be = ida_ida.idainfo_is_be()
        self.proc_name = ida_ida.inf_get_procname()
        if self.proc_name not in self.accept_process:
            print(f"The process {self.proc_name} not support, the result maybe not right")


def search_function(start: int, end: int):
    ea = start
    while ea < end:
        ea1 = ida_search.find_unknown(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
        ea2 = ida_search.find_not_func(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
        ea = min(ea1, ea2)
        ida_funcs.add_func(ea)


def search_string(start: int, end: int):
    for s in filter(lambda x: start < x.ea < end, idautils.Strings()):
        ida_bytes.create_strlit(s.ea, s.length, 0)

    # for str in idautils.Strings():
    #     if start < str.ea < end:
    #         ida_bytes.create_strlit(str.ea, str.length, 0)


def search_data(start: int, end: int):
    process_bytes = context.bits // 8

    find_next_data = lambda x: ida_search.find_data(x, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
    find_next_unknown = lambda x: ida_search.find_unknown(x, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
    check_data_size = lambda x: ida_bytes.get_item_size(x) == process_bytes
    check_data_align = lambda x: x % process_bytes == 0
    is_unknown = lambda x: ida_bytes.is_unknown(ida_bytes.get_flags(x))
    all_unknown = lambda x: all(map(lambda i: is_unknown(x + i), range(process_bytes)))
    get_data = (lambda x: ida_bytes.get_wide_dword(x)) if process_bytes == 4 else (
        lambda x: ida_bytes.get_qword(x))
    in_mem_range = lambda x: ida_segment.getseg(get_data(x)) is not None

    def ea_iter(find_next):
        ea = start
        while ea < end:
            ea = find_next(ea)
            yield ea

    f = ea_iter(find_next_data)
    f = filter(check_data_size, f)
    f = filter(in_mem_range, f)
    for ea in f:
        ida_offset.op_plain_offset(ea, 0, 0)

    f = ea_iter(find_next_unknown)
    f = filter(check_data_align, f)
    f = filter(all_unknown, f)
    f = filter(in_mem_range, f)
    for ea in f:
        ida_offset.op_plain_offset(ea, 0, 0)


class DoFix(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        result = InfoForm.show_from()
        if "func" in result:
            code_start, code_end = result["func"]
            search_function(code_start, code_end)

        if "str" in result:
            str_start, str_end = result["str"]
            search_string(str_start, str_end)

        if "data" in result:
            data_start, data_end = result["data"]
            search_data(data_start, data_end)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


if __name__ == '__main__':
    context = Context()

    act_name = "firmware:Fixed"
    if ida_kernwin.register_action(ida_kernwin.action_desc_t(
            act_name,
            "fix firmware",
            DoFix()
    )):
        print("add firmware fix plugins")
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", act_name, ida_kernwin.SETMENU_APP)
    else:
        ida_kernwin.unregister_action(act_name)
        print("add firmware fix plugin failed")

# print("big" if context.is_be else "little")
# print(f"bits {context.bits}")
# print(f"process name {context.proc_name}")
