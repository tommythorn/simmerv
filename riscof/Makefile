run: init
	riscof run --config=config.ini --suite=riscv-arch-test/riscv-test-suite/ --env=riscv-arch-test/riscv-test-suite/env

init:
ifeq (,$(wildcard ./riscv-arch-test))
	riscof --verbose info arch-test --clone
endif

# Python is an absolute abomination
setup:
	sudo apt install python3-pip
	pip3 install --break-system-packages riscof
