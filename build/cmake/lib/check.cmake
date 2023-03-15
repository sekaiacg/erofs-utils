include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)

function(check_include include_list)
	set(_output_list)
	foreach (inc ${${include_list}})
		string(REGEX REPLACE "[./]" "_" _inc ${inc})
		string(TOUPPER ${_inc} INC_UPPER)
		CHECK_INCLUDE_FILE(${inc} HAVE_${INC_UPPER})
		if (${INC_UPPER})
			list(APPEND _output_list "-DHAVE_${INC_UPPER}")
			#message("INC=HAVE_${INC_UPPER}")
		endif ()
	endforeach (inc)
endfunction()

function(check_fun func_list)
	set(_output_list)
	foreach (func ${${func_list}})
		string(TOUPPER ${func} FUNC_UPPER)
		check_function_exists(${func} HAVE_${FUNC_UPPER})
		if (${HAVE_${FUNC_UPPER}})
			list(APPEND _output_list "-DHAVE_${FUNC_UPPER}")
			#message("FUNC=HAVE_${FUNC_UPPER}")
		endif ()
	endforeach (func)
endfunction(check_fun)