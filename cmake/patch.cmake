function(patch_file target_file patch_file)
    execute_process(COMMAND readlink -f ${target_file} OUTPUT_VARIABLE PATH_TARGET_FILE)
    string(REGEX REPLACE "\n$" "" PATH_TARGET_FILE "${PATH_TARGET_FILE}")
    execute_process(COMMAND patch -u -N -f -s --no-backup-if-mismatch -r "/dev/null"
        "${PATH_TARGET_FILE}"
        "${patch_file}"
    )
endfunction(patch_file)

function(patch_files target_dir patch_file)
    execute_process(COMMAND readlink -f ${target_dir} OUTPUT_VARIABLE PATH_TARGET_DIR)
    string(REGEX REPLACE "\n$" "" PATH_TARGET_DIR "${PATH_TARGET_DIR}")
    execute_process(COMMAND patch -u -N -f -s --no-backup-if-mismatch -r "/dev/null"
        WORKING_DIRECTORY "${PATH_TARGET_DIR}"
        INPUT_FILE "${patch_file}"
    )
endfunction(patch_files)
