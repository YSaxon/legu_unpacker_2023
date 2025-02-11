Here are some important functions and constants to look out for, together with their offsets in the sample libraries included. You might want to run bindiff against the libraries included and see if you can find the corresponding offsets in your version. Then you can focus your static and dynamic analysis on those addresses. (Be aware that these are given without any base address, whereas Ghidra tends to default to putting 0x100000 as the base address so you'd need to add that to find the corresponding address). These are not the "true" names in the original source, they are my own descriptive names, and my own guesses at types.

* `sets_key_global_xored_with_16_byte_password_in_file(char* file_path_tosversion)`
* * v31_arm32: `3abe4`
* * v31_arm64: `38334`
* * v20_arm32: `35b24` (in this version no extra xor is done)

* `decrypt(char* src, char** out, size_t len)`
* * v31_arm32: `32b1c`
* * v31_arm64: `2c180`
* * v20_arm32: `2dec0`

* `copy_key_from_global(char* key_global_copy, char* dummy_value_misleading, size_t len)`
* * v31_arm32: `3a7c0`
* * v31_arm64: `37b88`
* * v20_arm32: `3576c`

* the key_global, 0x20 in length
* * v31_arm32: `46ddc`
* * v31_arm64: `56f58`
* * v20_arm32: `46558`

* `chacha_state_matrix_init_and_final_key_derive(uint *state_matrix, char* key_global, int always_set_to_0x100)`
* * v31_arm32: `3b004`
* * v31_arm64: `387a0`
* * v20_arm32: `35b50`
