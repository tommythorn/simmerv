import os
import re
import subprocess
import logging
import riscof.utils as utils
from riscof.pluginTemplate import pluginTemplate

logger = logging.getLogger()

# ISA string for spike — covers all extensions in the DUT ISA YAML
SPIKE_ISA = "rv64imafdc_zba_zbb_zbc_zbs_zicbom_zicbop_zicboz_zicond_zfhmin_zihpm"


class spike(pluginTemplate):
    __model__ = "spike_simulator"
    __version__ = "0.1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = kwargs.get('config')
        if config is None:
            logger.error("Config node for spike missing.")
            raise SystemExit(1)
        self.num_jobs = str(config.get('jobs', 1))
        self.pluginpath = os.path.abspath(config['pluginpath'])
        path_prefix = config.get('PATH', '')
        self.spike_exe = os.path.join(path_prefix, 'spike') if path_prefix else 'spike'

    def initialise(self, suite, work_dir, archtest_env):
        self.work_dir = work_dir
        self.compile_cmd = (
            'riscv{1}-elf-gcc -march={0}'
            ' -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -g -w'
            ' -T ' + self.pluginpath + '/env/link.ld'
            ' -I ' + self.pluginpath + '/env/'
            ' -I ' + archtest_env + ' {2} -o {3} {4}'
        )

    def build(self, isa_yaml, platform_yaml):
        ispec = utils.load_yaml(isa_yaml)['hart0']
        self.xlen = '64' if 64 in ispec['supported_xlen'] else '32'
        self.compile_cmd += ' -mabi=' + ('lp64' if self.xlen == '64' else 'ilp32')

    def runTests(self, testList, cgf_file=None):
        if os.path.exists(self.work_dir + "/Makefile." + self.name[:-1]):
            os.remove(self.work_dir + "/Makefile." + self.name[:-1])
        make = utils.makeUtil(
            makefilePath=os.path.join(self.work_dir, "Makefile." + self.name[:-1]))
        make.makeCommand = 'make -k -j' + self.num_jobs

        # Emit the Python helper script once to the work dir.
        helper = os.path.join(self.work_dir, '_spike_sig.py')
        with open(helper, 'w') as f:
            f.write(_SPIKE_SIG_HELPER)

        for testname in testList:
            testentry = testList[testname]
            test = testentry['test_path']
            test_dir = testentry['work_dir']
            elf = 'ref.elf'
            sig_file = os.path.join(test_dir, self.name[:-1] + ".signature")
            compile_macros = ' -D' + ' -D'.join(testentry['macros'])
            cmd = self.compile_cmd.format(
                testentry['isa'].lower(), self.xlen, test, elf, compile_macros)
            # Use the helper to run spike in debug mode and dump the signature region.
            sig_cmd = (
                f'python3 {helper}'
                f' {self.spike_exe} riscv{self.xlen}-elf-nm {elf} {sig_file}'
                f' {SPIKE_ISA}'
            )
            execute = f'@cd {test_dir}; {cmd}; {sig_cmd}'
            make.add_target(execute)
        make.execute_all(self.work_dir)


# Helper script: run spike in debug mode, stop at write_tohost, dump signature memory.
_SPIKE_SIG_HELPER = '''\
#!/usr/bin/env python3
"""spike_sig_helper: spike_exe nm_exe elf sig_file isa"""
import re, subprocess, sys, os, tempfile

spike_exe, nm_exe, elf, sig_file, isa = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

# Get symbol addresses from ELF.
nm_out = subprocess.check_output([nm_exe, elf], text=True)
syms = {m.group(2): int(m.group(1), 16)
        for m in re.finditer(r"([0-9a-f]+) . (\\S+)", nm_out)}
beg = syms.get("begin_signature", 0)
end = syms.get("end_signature", 0)
halt = syms.get("write_tohost", 0)

if beg == 0 or end == 0 or beg >= end or halt == 0:
    open(sig_file, "w").close()
    sys.exit(0)

# Build spike debug commands: stop at write_tohost, read memory 8 bytes at a time.
beg8 = beg & ~7
end8 = (end + 7) & ~7
cmds_file = sig_file + ".cmds"
with open(cmds_file, "w") as f:
    f.write(f"until pc 0 0x{halt:x}\\n")
    for addr in range(beg8, end8, 8):
        f.write(f"mem 0x{addr:x}\\n")
    f.write("q\\n")

result = subprocess.run(
    [spike_exe, "-d", f"--debug-cmd={cmds_file}", f"--isa={isa}", elf],
    capture_output=True, text=True
)

# Parse 64-bit hex values from stderr, split into 32-bit words (little-endian).
mem_words = {}
i = 0
for line in result.stderr.splitlines():
    line = line.strip()
    if re.match(r"0x[0-9a-f]+$", line):
        val64 = int(line, 16)
        addr = beg8 + i * 8
        mem_words[addr] = val64 & 0xFFFFFFFF
        mem_words[addr + 4] = (val64 >> 32) & 0xFFFFFFFF
        i += 1

with open(sig_file, "w") as out:
    addr = beg
    while addr < end:
        out.write(f"{mem_words.get(addr, 0):08x}\\n")
        addr += 4

os.unlink(cmds_file)
'''
