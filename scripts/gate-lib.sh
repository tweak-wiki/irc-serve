#!/bin/sh
# scripts/gate-lib.sh -- the gate family's single sanitizer-wiring definition.
#
# WHY THIS FILE EXISTS (#544). gate.sh's ASan cell, gate-linux-cell.sh and
# teeth-linux.sh each carried their own copy of the ASan options, and a word added
# to two of the three silently stopped running in the third. There is now one
# definition, sourced by all three: scripts, not comments, are what the teeth and
# check-wired.sh verify.
#
# POSIX sh throughout: sourced by the bash scripts and by gate-linux-cell.sh's
# `sh --report-render` path alike, so no bashisms.
#
# LINUX carries detect_leaks=1 because LeakSanitizer exists there; DARWIN carries
# detect_leaks=0 because it does not, and a red-by-design probe is not a signal.
# Both carry detect_stack_use_after_return=1: it defaults to OFF in three of the
# five toolchains measured, and it is the class that found the nf_free() defect.
GATE_ASAN_OPTS_LINUX="detect_leaks=1:detect_stack_use_after_return=1"
GATE_ASAN_OPTS_DARWIN="detect_leaks=0:detect_stack_use_after_return=1"
