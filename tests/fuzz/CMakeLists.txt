# Fuzz tests -- the stdin/corpus harness over message_parse_n() (#533).
#
# Convention, same as the other test directories: one add_executable per test.
# The corpus seeds are regression lines from tests/protocol/test_message_parse.c
# plus the boundary inputs (empty, embedded NUL, overlong, smuggled CRLF).

add_executable(fuzz_message_parse fuzz_message_parse.c)
target_link_libraries(fuzz_message_parse PRIVATE irc_core)

# Runs the deterministic sweep (FUZZ_ITERS mutations per seed). Bounded and
# fast (~1s); the open-ended libFuzzer entry in the same file is for manual
# runs, not CI, because AppleClang ships no libFuzzer.
add_test(NAME FuzzMessageParse
  COMMAND fuzz_message_parse "${CMAKE_CURRENT_SOURCE_DIR}/corpus")
set_tests_properties(FuzzMessageParse PROPERTIES LABELS Fuzz)
set_tests_properties(FuzzMessageParse PROPERTIES TIMEOUT 120)
