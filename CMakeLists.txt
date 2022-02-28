# sources: https://stackoverflow.com/questions/50877135/cmake-specify-linux-kernel-module-output-build-directory
# https://gitlab.com/christophacham/cmake-kernel-module/-/blob/master/CMakeLists.txt
# https://musteresel.github.io/posts/2020/02/cmake-template-linux-kernel-module.html

cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(zynqmp-fpga-fmod VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# default installation path
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX "/opt/fredsys/"
           CACHE PATH "default install path" FORCE)
endif()

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake")
find_package(KernelHeaders REQUIRED)
include_directories(${KERNELHEADERS_INCLUDE_DIRS})

# fpga-mgr driver is required
# this firmware requires PETALINUX 2019.2 or later. Older versions will give error in include/linux/fpga/fpga-mgr.h 
# because, for instance, FPGA_MGR_STATUS_EOS_ERR is not defined
# according to https://support.xilinx.com/s/article/72950?language=en_US, PETALINUX 2019.2 uses kernel 4.19.
# this is the link to the oldest supported mum kernel version https://github.com/Xilinx/linux-xlnx/blob/xlnx_rebase_v4.19/Makefile
# https://github.com/Xilinx/linux-xlnx/blob/e06217e669a63445c229eef419ee02023ce434c5/include/linux/fpga/fpga-mgr.h
# commit done Dec 31, 2019
#$ git describe --contains e06217e669a63445c229eef419ee02023ce434c5
#xilinx-v2020.1~198^2~441
#https://github.com/Xilinx/linux-xlnx/blob/xlnx_rebase_v5.4/include/linux/fpga/fpga-mgr.h
#https://github.com/Xilinx/linux-xlnx/blob/release-2020.2.2_k26/include/linux/fpga/fpga-mgr.h
# https://github.com/Xilinx/linux-xlnx/blob/c194cf31b9f0a7ced9f3d42d52b8559aedbfd7e7/include/linux/fpga/fpga-mgr.h
#git describe --contains c194cf31b9f0a7ced9f3d42d52b8559aedbfd7e7
#xlnx_rebase_v5.4_2020.1~616
find_path(FPGA_MGR_DIR
        include/linux/fpga/fpga-mgr.h
        PATHS ${KERNELHEADERS_DIR} 
        )

if (NOT FPGA_MGR_DIR)
    message(FATAL_ERROR "FPGA manager driver was not found in ${KERNELHEADERS_DIR}/include/linux/fpga/fpga-mgr.h !")
endif ()
# is it required to test for include/linux/firmware/xlnx-zynqmp.h ?
# Xilinx Zynq MPSoC Firmware layer

set(DRIVER_FILE ${PROJECT_NAME}.ko)
set(KBUILD_CMD ${CMAKE_MAKE_PROGRAM} -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})

# Generate the Kbuild file through cmake.
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := ${PROJECT_NAME}.o")

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${PROJECT_NAME}.c VERBATIM)

add_custom_target(${PROJECT_NAME} ALL DEPENDS ${DRIVER_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild) 

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${DRIVER_FILE}"
        DESTINATION modules
)
