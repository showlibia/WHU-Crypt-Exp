find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_path(GMPXX_INCLUDE_DIR NAMES gmpxx.h)

find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP
    REQUIRED_VARS 
    GMP_INCLUDE_DIR 
    GMPXX_INCLUDE_DIR
    GMP_LIBRARIES 
    GMPXX_LIBRARIES
)

mark_as_advanced(
    GMP_INCLUDE_DIR
    GMPXX_INCLUDE_DIR 
    GMP_LIBRARIES
    GMPXX_LIBRARIES
)

if(GMP_FOUND AND NOT TARGET GMP::GMP)
    add_library(GMP::GMP UNKNOWN IMPORTED)
    set_target_properties(GMP::GMP PROPERTIES
        IMPORTED_LOCATION "${GMP_LIBRARIES}"
        INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}"
    )
endif()

if(GMP_FOUND AND NOT TARGET GMP::GMPXX)
    add_library(GMP::GMPXX UNKNOWN IMPORTED)
    set_target_properties(GMP::GMPXX PROPERTIES
        IMPORTED_LOCATION "${GMPXX_LIBRARIES}"
        INTERFACE_INCLUDE_DIRECTORIES "${GMPXX_INCLUDE_DIR}"
    )
endif()