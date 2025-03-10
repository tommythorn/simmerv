from riscof.pluginTemplate import pluginTemplate
import shutil

class dummy(pluginTemplate):
    __model__ = "dummy_simulator"
    __version__ = "0.5.0"

    def __init__(self, *args, **kwargs):
        sclass = super().__init__(*args, **kwargs)
        return sclass

    def initialise(self, suite, work_dir, archtest_env):
        pass

    def build(self, isa_yaml, platform_yaml):
        pass

    def runTests(self, testList, cgf_file=None):
         for file in testList:
            testentry = testList[file]
            sig_path = testentry['work_dir'] + "/Reference-sail_c_simulator.signature";
            # Copy test case to working dir
            shutil.copyfile(sig_path.replace("/riscof_work/", "/generated/"), sig_path.replace("sail_c", "dummy"))