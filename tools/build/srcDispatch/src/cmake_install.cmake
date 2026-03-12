# Install script for directory: /Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local/")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/opt/homebrew/opt/llvm/bin/llvm-objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/Users/afiaasante/Security-Code-Smells/tools/build/bin/libsrcdispatch.a")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsrcdispatch.a" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsrcdispatch.a")
    execute_process(COMMAND "/opt/homebrew/opt/llvm/bin/llvm-ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsrcdispatch.a")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/dispatch" TYPE FILE FILES
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/dispatcher/srcDispatchUtilities.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/dispatcher/srcDispatcher.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/dispatcher/srcDispatcherMultiEvent.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/Access.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/BlockPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/CallPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/CasePolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/CatchPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ClassPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ConditionPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ConditionalPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ControlPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ConvertPlexerPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/DeclPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/DeclStmtPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/DeltaElement.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/DeltaElement.tcc"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/Diff.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/DoPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ElementData.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ElseIfPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ElsePolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ExprStmtPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ExprTypePolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ExpressionPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ForPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/FunctionPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/GenericArgumentsPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/GenericPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/GotoPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/IfPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/IfStmtPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/IncludePolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/IncrPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/InitPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/LabelPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/LiteralPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/NamePolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/OperatorPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/Position.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ReturnPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/SwitchPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/ThrowPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/TryPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/TypePolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/TypedefPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/UnitPolicy.hpp"
    "/Users/afiaasante/Security-Code-Smells/tools/srcslice/srcDispatch/src/policy_classes/WhilePolicy.hpp"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/afiaasante/Security-Code-Smells/tools/build/srcDispatch/src/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
