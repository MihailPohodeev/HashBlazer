cmake_minimum_required(VERSION 3.25)
project(HashBlazer VERSION 0.0.1)

set( CMAKE_CXX_STANDARD           20  )
set( CMAKE_CXX_STANDARD_REQUIRED  ON  )
set( CMAKE_CXX_EXTENSIONS         OFF )

option( BUILD_TESTS        "Build tests."      ON )
option( BUILD_SHARED_LIBS  "Build shared lib." ON )

set(HEADER_FILES
	include/md5.hxx
    include/base.hxx
)

set(SOURCE_FILES
	src/md5.cxx
    src/base.cxx
)

if(BUILD_SHARED_LIBS)
	add_library(${PROJECT_NAME} SHARED
		${HEADER_FILES}
		${SOURCE_FILES}
	)
else()
	add_library(${PROJECT_NAME} STATIC
		${HEADER_FILES}
		${SOURCE_FILES}
	)
endif()
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (BUILD_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
