//===- FuzzerMutate.cpp - Mutate a test input -----------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Mutate a test input.
//===----------------------------------------------------------------------===//

#include <cstring>

#include "FuzzerInternal.h"


namespace fuzzer {

const size_t Dictionary::kMaxDictSize;

MutationDispatcher::MutationDispatcher(Random &Rand,
                                       const FuzzingOptions &Options)
    : Rand(Rand), Options(Options) {
  DefaultMutators.insert(
      DefaultMutators.begin(),
      {
          {&MutationDispatcher::Mutate_EraseByte, "EraseByte"},
          {&MutationDispatcher::Mutate_InsertByte, "InsertByte"},
          {&MutationDispatcher::Mutate_InsertRepeatedBytes, "InsertRepeatedBytes"},
          {&MutationDispatcher::Mutate_ChangeByte, "ChangeByte"},
          {&MutationDispatcher::Mutate_ChangeASCIIInteger, "ChangeASCIIInt"},
          {&MutationDispatcher::Mutate_AddWordFromManualDictionary, "AddFromManualDict"},
          {&MutationDispatcher::Mutate_ChangeCase, "ChangeCase"},
          {&MutationDispatcher::Mutate_ClearField, "ClearField"},
          {&MutationDispatcher::Mutate_AddCharAtBeginning, "AddCharAtBeginning"},
          {&MutationDispatcher::Mutate_AddCharAtEnd, "AddCharAtEnd"},
          {&MutationDispatcher::Mutate_SetWordFromManualDictionary, "SetWordFromManualDictionary"}
      });

  if (EF->LLVMFuzzerCustomMutator)
    Mutators.push_back({&MutationDispatcher::Mutate_Custom, "Custom"});
  else
    Mutators = DefaultMutators;

  if (EF->LLVMFuzzerCustomCrossOver)
    Mutators.push_back(
        {&MutationDispatcher::Mutate_CustomCrossOver, "CustomCrossOver"});
}

static char FlipRandomBit(char X, Random &Rand) {
  int Bit = Rand(8);
  char Mask = 1 << Bit;
  char R;
  if (X & (1 << Bit))
    R = X & ~Mask;
  else
    R = X | Mask;
  assert(R != X);
  return R;
}

static char RandCh(Random &Rand) {
  if (Rand.RandBool()) return Rand(256);
  const char *Special = "!*'();:@&=+$,/?%#[]123ABCxyz-`~.";
  return Special[Rand(sizeof(Special) - 1)];
}

size_t MutationDispatcher::Mutate_Custom(uint8_t *Data, size_t Size,
                                         size_t MaxSize) {
  return EF->LLVMFuzzerCustomMutator(Data, Size, MaxSize, Rand.Rand());
}

size_t MutationDispatcher::Mutate_CustomCrossOver(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
  if (!Corpus || Corpus->size() < 2 || Size == 0)
    return 0;
  size_t Idx = Rand(Corpus->size());
  const Unit &Other = (*Corpus)[Idx];
  if (Other.empty())
    return 0;
  MutateInPlaceHere.resize(MaxSize);
  auto &U = MutateInPlaceHere;
  size_t NewSize = EF->LLVMFuzzerCustomCrossOver(
      Data, Size, Other.data(), Other.size(), U.data(), U.size(), Rand.Rand());
  if (!NewSize)
    return 0;
  assert(NewSize <= MaxSize && "CustomCrossOver returned overisized unit");
  memcpy(Data, U.data(), NewSize);
  return NewSize;
}

size_t MutationDispatcher::Mutate_ShuffleBytes(uint8_t *Data, size_t Size,
                                               size_t MaxSize) {
  if (Size == 0) { return 0; }
  size_t ShuffleAmount =
      Rand(std::min(Size, (size_t)8)) + 1; // [1,8] and <= Size.
  size_t ShuffleStart = Rand(Size - ShuffleAmount);
  assert(ShuffleStart + ShuffleAmount <= Size);
  std::random_shuffle(Data + ShuffleStart, Data + ShuffleStart + ShuffleAmount,
                      Rand);
  return Size;
}

size_t MutationDispatcher::Mutate_EraseByte(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {
  if (Size == 0) { return 0; }
  if (Size == 1) return 0;
  size_t Idx = Rand(Size);
  // Erase Data[Idx].
  memmove(Data + Idx, Data + Idx + 1, Size - Idx - 1);
  return Size - 1;
}

size_t MutationDispatcher::Mutate_InsertByte(uint8_t *Data, size_t Size,
                                             size_t MaxSize) {
  if (Size == MaxSize) return 0;
  size_t Idx = Rand(Size + 1);
  // Insert new value at Data[Idx].
  memmove(Data + Idx + 1, Data + Idx, Size - Idx);
  Data[Idx] = RandCh(Rand);
  return Size + 1;
}

size_t MutationDispatcher::Mutate_InsertRepeatedBytes(uint8_t *Data, size_t Size, size_t MaxSize) {
    const size_t kMinBytesToInsert = 3;
    if (Size + kMinBytesToInsert >= MaxSize) return 0;
    size_t MaxBytesToInsert = std::min(MaxSize - Size, (size_t)128);
    size_t N = Rand(MaxBytesToInsert - kMinBytesToInsert + 1) + kMinBytesToInsert;
    assert(Size + N <= MaxSize && N);

    // only append or prepend
    size_t Idx = Rand.RandBool() ? 0 : Size;
    // Insert new values at Data[Idx].
    memmove(Data + Idx + N, Data + Idx, Size - Idx);
    // Give preference to ASCII
    uint8_t Byte = Rand.RandBool() ? Rand(256) : Rand(128);
    for (size_t i = 0; i < N; i++)
        Data[Idx + i] = Byte;
    return Size + N;
}

size_t MutationDispatcher::Mutate_ChangeByte(uint8_t *Data, size_t Size, size_t MaxSize) {
  size_t Idx = Rand(Size);
  Data[Idx] = RandCh(Rand);
  return Size;
}

size_t MutationDispatcher::Mutate_ChangeBit(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {
  size_t Idx = Rand(Size);
  Data[Idx] = FlipRandomBit(Data[Idx], Rand);
  return Size;
}

size_t MutationDispatcher::Mutate_ClearField(uint8_t *Data, size_t Size, size_t MaxSize) {
    memset(Data, 0, Size);
    return SIZE_MAX;
}

size_t MutationDispatcher::Mutate_AddCharAtBeginning(uint8_t *Data, size_t Size, size_t MaxSize) {
    if (Size == MaxSize) return 0;
    memmove(Data + 1, Data, Size);
    Data[0] = RandCh(Rand);
    return Size + 1;
}

size_t MutationDispatcher::Mutate_AddCharAtEnd(uint8_t *Data, size_t Size, size_t MaxSize) {
    if (Size == MaxSize) return 0;
    Data[Size] = RandCh(Rand);
    return Size + 1;
}

size_t MutationDispatcher::Mutate_SetWordFromManualDictionary(uint8_t *Data, size_t Size, size_t MaxSize) {
    Dictionary &D = ManualDictionary;
    if (D.empty()) return 0;

    DictionaryEntry &DE = D[Rand(D.size())];
    const Word &W = DE.GetW();

    if (MaxSize - Size + W.size() > MaxSize) {
        return 0;
    }
    memcpy(Data, W.data(), W.size());

    DE.IncUseCount();
    CurrentDictionaryEntrySequence.push_back(&DE);
    return W.size();
}

size_t MutationDispatcher::Mutate_AddWordFromManualDictionary(uint8_t *Data,
                                                              size_t Size,
                                                              size_t MaxSize) {
  return AddWordFromDictionary(ManualDictionary, Data, Size, MaxSize);
}

size_t MutationDispatcher::Mutate_AddWordFromTemporaryAutoDictionary(
    uint8_t *Data, size_t Size, size_t MaxSize) {
  return AddWordFromDictionary(TempAutoDictionary, Data, Size, MaxSize);
}

size_t MutationDispatcher::Mutate_AddWordFromPersistentAutoDictionary(
    uint8_t *Data, size_t Size, size_t MaxSize) {
  return AddWordFromDictionary(PersistentAutoDictionary, Data, Size, MaxSize);
}

size_t MutationDispatcher::Mutate_ChangeCase(uint8_t *Data, size_t Size, size_t MaxSize) {
    bool lower = Rand(2);
    for (int i = 0; i < Size; ++i) {
        if (isalpha(Data[i])) {
            Data[i] = lower ? tolower(Data[i]) : toupper(Data[i]);
        }
    }
    return Size;
}

size_t MutationDispatcher::AddWordFromDictionary(Dictionary &D, uint8_t *Data,
                                                 size_t Size, size_t MaxSize) {
  if (D.empty()) return 0;
  DictionaryEntry &DE = D[Rand(D.size())];
  const Word &W = DE.GetW();
  DEBUG("Mutating from dictionary using word " << (char*)W.data())

  // NEW -- only append or prepend words
  // these mutations really only matter on header names/values
  // and inserting random dictionary entries into the middle of strings doesn't make sense
  // if a broken header does something, then the other mutation types can trigger it
  // overwriting bytes is now done in SetWordFromManualDictionary
  if (Size + W.size() > MaxSize) return 0;
  size_t Idx;
  if (Rand.RandBool()) {  // Prepend W
    Idx = 0;
  } else {  // Append W
    Idx = Size;
  }

  memmove(Data + Idx + W.size(), Data + Idx, Size - Idx);
  memcpy(Data + Idx, W.data(), W.size());
  Size += W.size();

  DE.IncUseCount();
  CurrentDictionaryEntrySequence.push_back(&DE);
  return Size;
}

size_t MutationDispatcher::Mutate_ChangeASCIIInteger(uint8_t *Data, size_t Size,
                                                     size_t MaxSize) {
  size_t B = Rand(Size);
  while (B < Size && !isdigit(Data[B])) B++;
  if (B == Size) return 0;
  size_t E = B;
  while (E < Size && isdigit(Data[E])) E++;
  assert(B < E);
  // now we have digits in [B, E).
  // strtol and friends don't accept non-zero-teminated data, parse it manually.
  uint64_t Val = Data[B] - '0';
  for (size_t i = B + 1; i < E; i++)
    Val = Val * 10 + Data[i] - '0';

  // Mutate the integer value.
  switch(Rand(5)) {
    case 0: Val++; break;
    case 1: Val--; break;
    case 2: Val /= 2; break;
    case 3: Val *= 2; break;
    case 4: Val = Rand(Val * Val); break;
    default: assert(0);
  }
  // Just replace the bytes with the new ones, don't bother moving bytes.
  for (size_t i = B; i < E; i++) {
    size_t Idx = E + B - i - 1;
    assert(Idx >= B && Idx < E);
    Data[Idx] = (Val % 10) + '0';
    Val /= 10;
  }
  return Size;
}

size_t MutationDispatcher::Mutate_CrossOver(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {
  if (!Corpus || Corpus->size() < 2 || Size == 0) return 0;
  size_t Idx = Rand(Corpus->size());
  const Unit &Other = (*Corpus)[Idx];
  if (Other.empty()) return 0;
  MutateInPlaceHere.resize(MaxSize);
  auto &U = MutateInPlaceHere;
  size_t NewSize =
      CrossOver(Data, Size, Other.data(), Other.size(), U.data(), U.size());
  assert(NewSize > 0 && "CrossOver returned empty unit");
  assert(NewSize <= MaxSize && "CrossOver returned overisized unit");
  memcpy(Data, U.data(), NewSize);
  return NewSize;
}

void MutationDispatcher::StartMutationSequence() {
  CurrentMutatorSequence.clear();
  CurrentDictionaryEntrySequence.clear();
}

// Copy successful dictionary entries to PersistentAutoDictionary.
void MutationDispatcher::RecordSuccessfulMutationSequence() {
  for (auto DE : CurrentDictionaryEntrySequence) {
    // PersistentAutoDictionary.AddWithSuccessCountOne(DE);
    DE->IncSuccessCount();
    // Linear search is fine here as this happens seldom.
    if (!PersistentAutoDictionary.ContainsWord(DE->GetW()))
      PersistentAutoDictionary.push_back({DE->GetW(), 1});
  }
}

void MutationDispatcher::PrintRecommendedDictionary() {
  std::vector<DictionaryEntry> V;
  for (auto &DE : PersistentAutoDictionary)
    if (!ManualDictionary.ContainsWord(DE.GetW()))
      V.push_back(DE);
  if (V.empty()) return;
  Printf("###### Recommended dictionary. ######\n");
  for (auto &DE: V) {
    Printf("\"");
    PrintASCII(DE.GetW(), "\"");
    Printf(" # Uses: %zd\n", DE.GetUseCount());
  }
  Printf("###### End of recommended dictionary. ######\n");
}

void MutationDispatcher::PrintMutationSequence() {
  Printf("MS: %zd ", CurrentMutatorSequence.size());
  for (auto M : CurrentMutatorSequence)
    Printf("%s-", M.Name);
  if (!CurrentDictionaryEntrySequence.empty()) {
    Printf(" DE: ");
    for (auto DE : CurrentDictionaryEntrySequence) {
      Printf("\"");
      PrintASCII(DE->GetW(), "\"-");
    }
  }
}

size_t MutationDispatcher::Mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  return MutateImpl(Data, Size, MaxSize, Mutators);
}

size_t MutationDispatcher::DefaultMutate(uint8_t *Data, size_t Size,
                                         size_t MaxSize) {
  return MutateImpl(Data, Size, MaxSize, DefaultMutators);
}

// Mutates Data in place, returns new size.
size_t MutationDispatcher::MutateImpl(uint8_t *Data, size_t Size,
                                      size_t MaxSize,
                                      const std::vector<Mutator> &Mutators) {
  assert(MaxSize > 0);
  assert(Size <= MaxSize);
  // Some mutations may fail (e.g. can't insert more bytes if Size == MaxSize),
  // in which case they will return 0.
  // Try several times before returning un-mutated data.
  for (int Iter = 0; Iter < 10; Iter++) {
    auto M = Mutators[Rand(Mutators.size())];
    size_t NewSize = (this->*(M.Fn))(Data, Size, MaxSize);
    if (NewSize) {
      if (Options.OnlyASCII)
        ToASCII(Data, NewSize);
      CurrentMutatorSequence.push_back(M);
      return NewSize;
    }
  }
  return Size;
}

void MutationDispatcher::AddWordToManualDictionary(const Word &W) {
  ManualDictionary.push_back(
      {W, std::numeric_limits<size_t>::max()});
}

void MutationDispatcher::AddWordToAutoDictionary(DictionaryEntry DE) {
  static const size_t kMaxAutoDictSize = 1 << 14;
  if (TempAutoDictionary.size() >= kMaxAutoDictSize) return;
  TempAutoDictionary.push_back(DE);
}

void MutationDispatcher::ClearAutoDictionary() {
  TempAutoDictionary.clear();
}

}  // namespace fuzzer
