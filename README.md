# unpack-ta505packer-qiling

The purpose of this proof of concept is to unpack samples packed with **TA505 packer** using [Qiling Framework 1.2](https://github.com/qilingframework/qiling/tree/1.2) without knowing how the unpacking algorithm works.

To achieve this, several hooks have been created in specific calls with the purpose of:

- Bypass anti-emulation techniques to execute the Packer Stub
- Store dynamically allocated blocks of memory information (address and size)
- Dump the unpacked PE once it is ready. (For example, before **VirtualFree()** gets executed)

The unpacked PE will be saved when the packer calls to **VirtualFree()**:

```python
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

```

Once **hook_VirtualFree()** is triggered, this function will call to **dump_memory_region()** to dump the content of the unpacked binary:

```python
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
```

Example with:

```
python3 unpack_TA505Packer_1.2.py samples/sample_bb5054f0ec4e6980f65fb9329a0b5acec1ed936053c3ef0938b5fa02a9daf7ee 
```

```
[...]
1 VirtualAlloc start: 0x50f247c - size: 0x28400
0x1076b856: VirtualAlloc(lpAddress = 0x0, dwSize = 0x28400, flAllocationType = 0x3000, flProtect = 0x4) = 0x50f247c
1 VirtualFree called for address: 0x50cf6ac
1 Memory regions stored: [{'start': 84732200, 'size': 3360}, {'start': 84735660, 'size': 142800}, {'start': 84878460, 'size': 164864}]
1 Read memory region at address: 0x50f247c - size: 0x28400
1 Dump memory region at address: 0x50f247c - size: 0x28400
[...]
1 Elapsed time 361.46228432655334
```

This process can take a few minutes, in this case the process has taken 360 seconds.

It is possible to find the unpacked sample in the same directory with this name:

```unpacked_0x50f247c.bin - sha256 6d15cd4cadac81ee44013d1ad32c18a27ccd38671dee051fb58b5786bc0fa7d3```

**Note:**
Sometimes the call to **ql.emu_stop()** made from **VirtualFree()** does not end the execution of the emulator, and an exception is thrown, even though the sample has been correctly unpacked.

## Requirements

- [Python 3](https://www.python.org/download/releases/3.0/)
- [Qiling Framework 1.2](https://github.com/qilingframework/qiling/tree/1.2)

## Usage

```
python3 unpack_TA505Packer_1.2.py <sample_path>
python3 unpack_TA505Packer_1.2.py samples/sample_bb5054f0ec4e6980f65fb9329a0b5acec1ed936053c3ef0938b5fa02a9daf7ee
```

**Output**

```
unpacked_0x50f247c.bin
unpacked_<hex_addr>.bin
```

## Samples

| SHA256 Packed samples                                        | SHA256 Unpacked samples                                      | Malware |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------- |
| bb5054f0ec4e6980f65fb9329a0b5acec1ed936053c3ef0938b5fa02a9daf7ee | 6d15cd4cadac81ee44013d1ad32c18a27ccd38671dee051fb58b5786bc0fa7d3 | GELUP   |
| 4b0eafcb1ec03ff3faccd2c0f465f5ac5824145d00e08035f57067a40cd179d2 | b9a0bde76d0bc7cc497c9cd17670d86813c97a9f8bed09ea99d4bf531adafb27 | SILENCE |
| ad320839e01df160c5feb0e89131521719a65ab11c952f33e03d802ecee3f51f | 8a30f4c59d111658b7f9efbd5f5b794228394cd53d22a1fb389fd3a03fc4d1f7 | AMY RAT |
| 74c5ae5e64d0a850eb0ebe3cbca4c6b92918a8365f2f78306643be9cffc32def | 6831fc67ca09d9027fef8b3031a11e9595fc1df1cb547c6f587947d13dad151a | TINYMET |
| e4eb1a831a8cc7402c8e0a898effd3fb966a9ee1a22bce9ddc3e44e574fe8c5e | 103084a964d0b150e1268c8a1a9d8c2545f7f0721e78a1b98b74304320aeb547 | AZORULT |

## References

- [Blueliv - Using Qiling Framework to Unpack TA505 packed samples](https://www.blueliv.com/cyber-security-and-cyber-threat-intelligence-blog-blueliv/using-qiling-framework-to-unpack-ta505-packed-samples/)