/**
 * `WasmRiscv` is an interface between user JavaScript code and
 * WebAssembly RISC-V emulator. The following code is example
 * JavaScript user code.
 *
 * ```ignore
 * // JavaScript code
 * const riscv = WasmRiscv.new();
 * // Setup program content binary
 * riscv.load_image(new Uint8Array(elfBuffer));
 * // Setup filesystem content binary
 * riscv.setup_filesystem(new Uint8Array(fsBuffer));
 *
 * // Emulator needs to break program regularly to handle input/output
 * // because the emulator is currenlty designed to run in a single thread.
 * // Once `SharedArrayBuffer` lands by default in major browsers
 * // we would run input/output handler in another thread.
 * const runCycles = () => {
 *   // Run 0x100000 (or certain) cycles, handle input/out,
 *   // and fire next cycles.
 *   // Note: Evety instruction is completed in a cycle.
 *   setTimeout(runCycles, 0);
 *   riscv.run_cycles(0x100000);
 *
 *   // Output handling
 *   while (true) {
 *     const data = riscv.get_output();
 *     if (data !== 0) {
 *       // print data
 *     } else {
 *       break;
 *     }
 *   }
 *
 *   // Input handling. Assuming inputs holds
 *   // input ascii data.
 *   while (inputs.length > 0) {
 *     riscv.put_input(inputs.shift());
 *   }
 * };
 * runCycles();
 * ```
 */
export class WasmRiscv {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmRiscv.prototype);
        obj.__wbg_ptr = ptr;
        WasmRiscvFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRiscvFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmriscv_free(ptr, 0);
    }
    /**
     * Disassembles an instruction Program Counter points to.
     * Use `get_output()` to get the disassembled strings.
     */
    disassemble() {
        wasm.wasmriscv_disassemble(this.__wbg_ptr);
    }
    /**
     * Gets virtual address corresponding to symbol strings.
     *
     * # Arguments
     * * `s` Symbol strings
     * * `error` If symbol is not found error[0] holds non-zero. Otherwize
     *   zero.
     * @param {string} s
     * @param {Uint8Array} error
     * @returns {bigint}
     */
    get_address_of_symbol(s, error) {
        const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = passArray8ToWasm0(error, wasm.__wbindgen_malloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmriscv_get_address_of_symbol(this.__wbg_ptr, ptr0, len0, ptr1, len1, error);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Gets ascii code byte sent from the emulator to terminal.
     * The emulator holds output buffer inside. This method returns zero
     * if the output buffer is empty. So if you want to read all buffered
     * output content, repeatedly call this method until zero is returned.
     *
     * ```ignore
     * // JavaScript code
     * while (true) {
     *   const data = riscv.get_output();
     *   if (data !== 0) {
     *     // print data
     *   } else {
     *     break;
     *   }
     * }
     * ```
     * @returns {number}
     */
    get_output() {
        const ret = wasm.wasmriscv_get_output(this.__wbg_ptr);
        return ret;
    }
    /**
     * Sets up program run by the program. This method is expected to be called
     * only once.
     *
     * # Arguments
     * * `content` Program binary
     * @param {Uint8Array} content
     */
    load_image(content) {
        const ptr0 = passArray8ToWasm0(content, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmriscv_load_image(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Creates a new `WasmRiscv`.
     * @returns {WasmRiscv}
     */
    static new() {
        const ret = wasm.wasmriscv_new();
        return WasmRiscv.__wrap(ret);
    }
    /**
     * Puts ascii code byte sent from terminal to the emulator.
     *
     * # Arguments
     * * `data` Ascii code byte
     * @param {number} data
     */
    put_input(data) {
        wasm.wasmriscv_put_input(this.__wbg_ptr, data);
    }
    /**
     * Reads Program Counter content.
     * @returns {bigint}
     */
    read_pc() {
        const ret = wasm.wasmriscv_read_pc(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Reads integer register content.
     *
     * # Arguments
     * * `reg` register number. Must be 0-31.
     * @param {number} _reg
     * @returns {bigint}
     */
    read_register(_reg) {
        const ret = wasm.wasmriscv_read_register(this.__wbg_ptr, _reg);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Runs program set by `load_image()`. The emulator won't stop forever
     * unless [`riscv-tests`](https://github.com/riscv/riscv-tests) programs.
     * The emulator stops if program is `riscv-tests` program and it finishes.
     */
    run() {
        wasm.wasmriscv_run(this.__wbg_ptr);
    }
    /**
     * Runs program set by `load_image()` in `cycles` cycles.
     *
     * # Arguments
     * * `cycles`
     * @param {number} cycles
     */
    run_cycles(cycles) {
        wasm.wasmriscv_run_cycles(this.__wbg_ptr, cycles);
    }
    /**
     * Runs program until breakpoints. Also known as debugger's continue
     * command. This method takes `max_cycles`. If the program doesn't hit
     * any breakpoint in `max_cycles` cycles this method returns `false`.
     * Otherwise `true`.
     *
     * Even without this method, you can write the same behavior JavaScript
     * code as the following code. But JS-WASM bridge cost isn't ignorable
     * now. So this method has been introduced.
     *
     * ```ignore
     * const runUntilBreakpoints = (riscv, breakpoints, maxCycles) => {
     *   for (let i = 0; i < maxCycles; i++) {
     *     riscv.run_cycles(1);
     *     const pc = riscv.read_pc()
     *     if (breakpoints.includes(pc)) {
     *       return true;
     *     }
     *   }
     *   return false;
     * };
     * ```
     *
     * # Arguments
     * * `breakpoints` An array including breakpoint virtual addresses
     * * `max_cycles` See the above description
     * @param {BigUint64Array} breakpoints
     * @param {number} max_cycles
     * @returns {boolean}
     */
    run_until_breakpoints(breakpoints, max_cycles) {
        const ptr0 = passArray64ToWasm0(breakpoints, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmriscv_run_until_breakpoints(this.__wbg_ptr, ptr0, len0, max_cycles);
        return ret !== 0;
    }
    /**
     * Sets up device tree. The emulator has default device tree configuration.
     * If you want to override it, use this method. This method is expected to
     * to be called up to only once.
     *
     * # Arguments
     * * `content` DTB content binary
     * @param {Uint8Array} content
     */
    setup_dtb(content) {
        const ptr0 = passArray8ToWasm0(content, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmriscv_setup_dtb(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Sets up filesystem. Use this method if program (e.g. Linux) uses
     * filesystem. This method is expected to be called up to only once.
     *
     * # Arguments
     * * `content` File system content binary
     * @param {Uint8Array} content
     */
    setup_filesystem(content) {
        const ptr0 = passArray8ToWasm0(content, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmriscv_setup_filesystem(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmRiscv.prototype[Symbol.dispose] = WasmRiscv.prototype.free;

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_copy_to_typed_array_d2f20acdab8e0740: function(arg0, arg1, arg2) {
            new Uint8Array(arg2.buffer, arg2.byteOffset, arg2.byteLength).set(getArrayU8FromWasm0(arg0, arg1));
        },
        __wbg___wbindgen_is_undefined_52709e72fb9f179c: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_6ddd609b62940d55: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_instanceof_Window_23e677d2c6843922: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_now_16f0c993d5dd6c27: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_now_c6d7a7d35f74f6f1: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_performance_28be169151161678: function(arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_8adb955bd33fac2f: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_ad356e0db91c7913: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_f207c857566db248: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_bb9f1ba69d61b386: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./simmerv_wasm_bg.js": import0,
    };
}

const WasmRiscvFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmriscv_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedBigUint64ArrayMemory0 = null;
function getBigUint64ArrayMemory0() {
    if (cachedBigUint64ArrayMemory0 === null || cachedBigUint64ArrayMemory0.byteLength === 0) {
        cachedBigUint64ArrayMemory0 = new BigUint64Array(wasm.memory.buffer);
    }
    return cachedBigUint64ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray64ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 8, 8) >>> 0;
    getBigUint64ArrayMemory0().set(arg, ptr / 8);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedBigUint64ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('simmerv_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
