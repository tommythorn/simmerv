#!/bin/bash
for x in sim-hang sim-crash fails passes;do printf "%-10s %d\n" $x `(cd $x;\ls | wc -l)`;done
