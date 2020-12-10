import logging
import sys
import time

from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import *
from qiling.os.windows.thread import *
from qiling.os.windows.utils import *


log = logging.getLogger(__name__)

mem_regions = []


def dump_memory_region(ql, address, size):

    ql.nprint(D_INFO, "Read memory region at address: {} - size: {}".format(hex(address), hex(size)))

    try:
        excuted_mem = ql.mem.read(address, size)
    except Exception as err:
        log.warning('Unable to read memory region at address: {}. Error: {}'.format(hex(address), err))
        return
    
    ql.nprint(D_INFO, "Dump memory region at address: {} - size: {}".format(hex(address), hex(size)))

    with open("unpacked_"+hex(address)+".bin", "wb") as f:
        f.write(excuted_mem) # write extracted code to a binary file


@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_VirtualFree(ql, address, params):

    global mem_regions

    lpAddress = params["lpAddress"]

    ql.nprint(D_INFO, "VirtualFree called for address: {}".format(hex(lpAddress)))

    ql.nprint(D_INFO, "Memory regions stored: {}".format(mem_regions))

    try:
        if mem_regions:
            unpacked_layer = mem_regions[-1] # Unpacked layer is in the last allocated block
            start = unpacked_layer["start"]
            size = unpacked_layer["size"]
            dump_memory_region(ql, start, size)
    except Exception as err:
       ql.nprint(D_INFO, 'Unable to dump memory region: {}'.format(err))

    ql.os.heap.free(lpAddress)

    ql.emu_stop()

    return 1

@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_VirtualAllocEx(ql, address, params):
    dw_size = params["dwSize"]
    addr = ql.os.heap.alloc(dw_size)
    
    fl_protect = params["flProtect"]
    if fl_protect in [0x1, 0x2, 0x4, 0x8,0x10, 0x20, 0x40, 0x80]:

        ql.nprint(D_INFO, "VirtualAllocEx start: {} - size: {}".format(hex(addr), hex(dw_size)))
        mem_regions.append({"start": addr, "size": dw_size})

    return addr

@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_VirtualAlloc(ql, address, params):
    dw_size = params["dwSize"]
    addr = ql.os.heap.alloc(dw_size)

    fl_protect = params["flProtect"]
    if fl_protect in [0x1, 0x2, 0x4, 0x8,0x10, 0x20, 0x40, 0x80]:

        ql.nprint(D_INFO, "VirtualAlloc start: {} - size: {}".format(hex(addr), hex(dw_size)))
        mem_regions.append({"start": addr, "size": dw_size})

    return addr


@winsdkapi(cc=STDCALL, dllname="msvcrt_dll")
def hook___wgetmainargs(ql, address, params):
    return 0


@winsdkapi(cc=STDCALL, dllname="comctl32_dll")
def hook_ImageList_Add(ql, address, params):
    ret = 0xFFFFFFFF
    return ret


@winsdkapi(cc=STDCALL, dllname="user32_dll")
def hook_GetWindowContextHelpId(ql, address, params):
 
    ERROR_INVALID_WINDOW_HANDLE = 0x578

    ql.os.last_error = ERROR_INVALID_WINDOW_HANDLE

    return 0


@winsdkapi(cc=STDCALL, dllname="user32_dll")
def hook_SetClassLongA(ql, address, params):

    ERROR_INVALID_WINDOW_HANDLE = 0x578

    ql.os.last_error = ERROR_INVALID_WINDOW_HANDLE

    return 0


@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_CreateEventA(ql, address, params):
    return 0


@winsdkapi(cc=STDCALL, dllname="ole32_dll")
def hook_CoReleaseMarshalData(ql, addrss, params):

    E_INVALIDARG = 0x80070057

    return E_INVALIDARG


@winsdkapi(cc=STDCALL, dllname="shell32_dll")
def hook_ShellExecuteA(ql, address, params):
    return 0


@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_VirtualQuery(ql, address, params):
    return params['dwLength']


def patch_binary(ql):

    patches = []

    '''
    Original
        81 7D B4 40 42 0F 00                    cmp     [ebp+var_4C], 1000000

    Patch:
        81 7D B4 00 00 00 00                    cmp     [ebp+var_4C], 0
    '''
    patch_ = {
        'original': b'\x81\x7D\xB4\x40\x42\x0F\x00',
        'patch': b'\x81\x7D\xB4\x00\x00\x00\x00'
    }
    patches.append(patch_)

    for patch in patches:

        antiemu_loop_addr = ql.mem.search(patch['original'])
        if antiemu_loop_addr:
            ql.nprint(D_INFO, 'Found Anti-Emulation loop at addr: {}'.format(hex(antiemu_loop_addr[0])))

            try:
                ql.patch(antiemu_loop_addr[0], patch['patch'])
                ql.nprint(D_INFO, 'Successfully patched!')
                return 
            except Exception as err:
                ql.nprint(D_INFO, 'Unable to patch binary: {}'.format(err))


def sandbox(path, rootfs):

    start_time = time.time()

    # create a sandbox for Windows x86
    ql = Qiling([path], rootfs, output = "debug")

    try:
        # set API breakpoints
        ql.set_api("__wgetmainargs", hook___wgetmainargs)
        ql.set_api("CoReleaseMarshalData", hook_CoReleaseMarshalData)
        ql.set_api("CreateEventA", hook_CreateEventA)
        ql.set_api("GetWindowContextHelpId", hook_GetWindowContextHelpId)
        ql.set_api("ImageList_Add", hook_ImageList_Add)
        ql.set_api("SetClassLongA", hook_SetClassLongA)
        ql.set_api("ShellExecuteA", hook_ShellExecuteA)
        ql.set_api("VirtualAlloc", hook_VirtualAlloc)
        ql.set_api("VirtualAllocEx", hook_VirtualAllocEx)
        ql.set_api("VirtualFree", hook_VirtualFree)
        ql.set_api("VirtualQuery", hook_VirtualQuery)

        # Patch binary for anti-emulation loops
        patch_binary(ql)

        ql.run()

    except Exception as err:
        ql.nprint(D_INFO, 'An error occurred with Qiling Framework: {}'.format(err))

    elapsed_time = time.time() - start_time

    ql.nprint(D_INFO, "Elapsed time {}".format(elapsed_time))


if __name__ == "__main__":
    if not len(sys.argv) == 2:
        exit(-1)

    path = sys.argv[1]
    sandbox(path, "examples/rootfs/x86_windows")
