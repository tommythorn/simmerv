import os
import re
import shutil
import subprocess
import shlex
import logging
import random
import string
from string import Template
import sys

import riscof.utils as utils
import riscof.constants as constants
from riscof.pluginTemplate import pluginTemplate

logger = logging.getLogger()

# Constants for the Tenstorrent-specific signature memory region
SIGNATURE_BASE = 0x70000000
SIGNATURE_SIZE = 0x1000  # Default size, assuming 4KB for signature region

class riscvrust(pluginTemplate):
    __model__ = "riscvrust"

    #TODO: please update the below to indicate family, version, etc of your DUT.
    __version__ = "XXX"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        config = kwargs.get('config')

        # If the config node for this DUT is missing or empty. Raise an error. At minimum we need
        # the paths to the ispec and pspec files
        if config is None:
            print("Please enter input file paths in configuration.")
            raise SystemExit(1)

        # Path to the directory where this python file is located. Collect it from the config.ini
        self.pluginpath=os.path.abspath(config['pluginpath'])

        # In case of an RTL based DUT, this would be point to the final binary executable of your
        # test-bench produced by a simulator (like verilator, vcs, incisive, etc). In case of an iss or
        # emulator, this variable could point to where the iss binary is located. If 'PATH variable
        # is missing in the config.ini we can hardcode the alternate here.
        self.dut_exe = os.path.join(config['PATH'] if 'PATH' in config else "", self.pluginpath + "/../../target/release/simmerv_cli")

        # Number of parallel jobs that can be spawned off by RISCOF
        # for various actions performed in later functions, specifically to run the tests in
        # parallel on the DUT executable. Can also be used in the build function if required.
        self.num_jobs = str(config['jobs'] if 'jobs' in config else 1)

        # Collect the paths to the  riscv-config absed ISA and platform yaml files. One can choose
        # to hardcode these here itself instead of picking it from the config.ini file.
        self.isa_spec = os.path.abspath(config['ispec'])
        self.platform_spec = os.path.abspath(config['pspec'])

        #We capture if the user would like the run the tests on the target or
        #not. If you are interested in just compiling the tests and not running
        #them on the target, then following variable should be set to False
        if 'target_run' in config and config['target_run']=='0':
            self.target_run = False
        else:
            self.target_run = True

    def initialise(self, suite, work_dir, archtest_env):

       # capture the working directory. Any artifacts that the DUT creates should be placed in this
       # directory. Other artifacts from the framework and the Reference plugin will also be placed
       # here itself.
       self.work_dir = work_dir

       # capture the architectural test-suite directory.
       self.suite_dir = suite

       # Note the march is not hardwired here, because it will change for each
       # test. Similarly the output elf name and compile macros will be assigned later in the
       # runTests function
       self.compile_cmd = 'riscv{1}-unknown-elf-gcc -march={0} \
         -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -g -w\
         -T '+self.pluginpath+'/env/link.ld\
         -I '+self.pluginpath+'/env/\
         -I ' + archtest_env + ' {2} -o {3} {4}'

       # Store signature constants for use in other methods
       self.signature_base = SIGNATURE_BASE
       self.signature_size = SIGNATURE_SIZE

    def build(self, isa_yaml, platform_yaml):

      # Build riscvrust
      utils.shellCommand("cargo build -r --all").run(cwd=os.path.abspath(os.path.join(self.pluginpath, '../..')))

      # load the isa yaml as a dictionary in python.
      ispec = utils.load_yaml(isa_yaml)['hart0']

      # capture the XLEN value by picking the max value in 'supported_xlen' field of isa yaml. This
      # will be useful in setting integer value in the compiler string (if not already hardcoded);
      self.xlen = ('64' if 64 in ispec['supported_xlen'] else '32')

      # start building the isa string.
      self.isa = 'rv' + self.xlen
      isa_string = ispec['ISA']
      if "I" in isa_string: self.isa += 'i'
      if "M" in isa_string: self.isa += 'm'
      if "F" in isa_string: self.isa += 'f'
      if "D" in isa_string: self.isa += 'd'
      if "C" in isa_string: self.isa += 'c'
      if "V" in isa_string: self.isa += 'v'

      # The following assumes you are using the riscv-gcc toolchain. If
      # not please change appropriately
      self.compile_cmd = self.compile_cmd+' -mabi='+('lp64' if 64 in ispec['supported_xlen'] else 'ilp32')

    def runTests(self, testList):

      # Delete Makefile if it already exists.
      if os.path.exists(self.work_dir+ "/Makefile." + self.name[:-1]):
            os.remove(self.work_dir+ "/Makefile." + self.name[:-1])
      # create an instance the makeUtil class that we will use to create targets.
      make = utils.makeUtil(makefilePath=os.path.join(self.work_dir, "Makefile." + self.name[:-1]))

      # set the make command that will be used. The num_jobs parameter was set in the __init__
      # function earlier
      make.makeCommand = 'make -k -j' + self.num_jobs

      # we will iterate over each entry in the testList. Each entry node will be refered to by the
      # variable testname.
      for testname in testList:
        # for each testname we get all its fields (as described by the testList format)
        testentry = testList[testname]

        # we capture the path to the assembly file of this test
        test = testentry['test_path']

        # capture the directory where the artifacts of this test will be dumped/created.
        test_dir = testentry['work_dir']

        # name of the elf file after compilation of the test.
        elf = 'my.elf'

        # name of the signature file as per requirement of RISCOF.
        sig_file = os.path.join(test_dir, self.name[:-1] + ".signature")

        # For each test, generate specific compile macros.
        compile_macros= ' -D' + " -D".join(testentry['macros'])

        # substitute all variables in the compile command.
        cmd = self.compile_cmd.format(testentry['isa'].lower(), self.xlen, test, elf, compile_macros)

        if self.target_run:
          # set up the simulation command with arguments for the custom signature region.
          simcmd = (f'{self.dut_exe} --riscof-sigfile {sig_file} '
                    f'--mem-region 0x{self.signature_base:x}:0x{self.signature_size:x} '
                    f'--sig-region-start 0x{self.signature_base:x} {elf}')
        else:
          simcmd = 'echo "NO RUN"'

        # concatenate all commands that need to be executed within a make-target.
        execute = f'@cd {test_dir}; {cmd}; {simcmd}'

        # The signature file is the final target of the rule.
        make.add_target(sig_file, deps=[test], command=execute)

    def extract_signature(self, sig_file, mem_dump):
        '''
        This method is a no-op because the simulator is instructed to write the 
        signature file directly to the path given by `sig_file` via the 
        `--riscof-sigfile` argument. RISCOF will then verify this file.
        '''
        pass