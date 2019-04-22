# COPYRIGHT (c) 2015 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

function(RDMA_BuildType)
  set(build_types Debug Release RelWithDebInfo MinSizeRel)

  # Set the default build type to RelWithDebInfo. Since RDMA is typically used
  # in performance contexts it doesn't make much sense to have the default build
  # turn off the optimizer.
  if(NOT CMAKE_BUILD_TYPE)
	  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
      "Options are ${build_types}"
      FORCE
      )
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${build_types})
  endif()

  # Release should be used by packagers, it is the same as the default RelWithDebInfo,
  # this means it uses -O2 and -DNDEBUG (not -O3)
  foreach (language CXX C)
    set(VAR_TO_MODIFY "CMAKE_${language}_FLAGS_RELEASE")
    if ("${${VAR_TO_MODIFY}}" STREQUAL "${${VAR_TO_MODIFY}_INIT}")
      set(${VAR_TO_MODIFY} "${CMAKE_${language}_FLAGS_RELWITHDEBINFO_INIT}"
	  CACHE STRING "Default flags for Release configuration" FORCE)
    endif()
  endforeach()

  # RelWithDebInfo should be used by developers, it is the same as Release but
  # with the -DNDEBUG removed
  foreach (language CXX C)
    set(VAR_TO_MODIFY "CMAKE_${language}_FLAGS_RELWITHDEBINFO")
    if (${${VAR_TO_MODIFY}} STREQUAL ${${VAR_TO_MODIFY}_INIT})
	string(REGEX REPLACE "(^| )[/-]D *NDEBUG($| )"
	  " "
	  replacement
	  "${${VAR_TO_MODIFY}}"
	  )
	set(${VAR_TO_MODIFY} "${replacement}"
	    CACHE STRING "Default flags for RelWithDebInfo configuration" FORCE)
    endif()
  endforeach()
endfunction()
