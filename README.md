# GDB EBPF
When attempting to solve some of my ctf competitions, I would always stumble across ebpf programs that would be loaded into memory dynamically:
```c
  local_d8 = 0x400000020;
  local_d0 = 0xc000003e15000015;
  local_c8 = 0x20;
  local_c0 = 0x4000000001000035;
  local_b8 = 0xffffffff12000015;
  local_b0 = 0x100015;
  local_a8 = 0x1000f0015;
  local_a0 = 0x3000e0015;
  local_98 = 0x9000d0015;
  local_90 = 0xa000c0015;
  local_88 = 0xb000b0015;
  local_80 = 0xc000a0015;
  local_78 = 0xf00090015;
  local_70 = 0x1400080015;
  local_68 = 0x3c00070015;
  local_60 = 0xe700060015;
  local_58 = 0x13e00050015;
  local_50 = 0x205000015;
  local_48 = 0x1c00000020;
  local_40 = 0x3000015;
  local_38 = 0x1800000020;
  local_30 = 0x1000015;
  local_28 = 0x7fff000000000006;
  local_20 = 6;
  local_18 = 0;
  local_e8[0] = 0x18;
  local_e0 = &local_d8;
```
And therefore unable to be decompiled by Ghidra (the Ghidra ebpf decompiler is broken anyways).
This script is meant to be pointed at the sock_fprog descriptor of the program after it has been built on the stack, and will decompile the program and dump the result into gdb.
