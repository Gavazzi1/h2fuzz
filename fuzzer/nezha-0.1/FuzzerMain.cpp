//===- FuzzerMain.cpp - main() function and flags -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// main() and flags.
//===----------------------------------------------------------------------===//

#include "FuzzerInternal.h"
#include <iostream>

extern "C" {
// This function should be defined by the user.
int64_t LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
}  // extern "C"

int main(int argc, char **argv) {
  return fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
