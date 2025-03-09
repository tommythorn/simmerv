#!/bin/bash
for class in passes fails sim-crash
do echo
   echo "$class:"
   for x in riscv-tests/$class/*
   do printf "%-25s " `basename $x`
      target/release/riscv_emu_rust_cli 2>&1 $x|tail -2|head -1
   done
done
