
#pragma once

class Random {
public:
    Random(unsigned int seed) : R(seed) {}
    size_t Rand() { return R(); }
    size_t RandBool() { return Rand() % 2; }
    size_t operator()(size_t n) { return n ? Rand() % n : 0; }
    std::mt19937 &Get_mt19937() { return R; }
private:
    std::mt19937 R;
};

class LibFuzz_Mut;

typedef size_t (LibFuzz_Mut::*Mutator)(uint8_t *Data, size_t Size, size_t Max);

class LibFuzz_Mut {
public:
    LibFuzz_Mut(Random &Rand) : Rand(Rand) {
        Mutators.insert(
                Mutators.begin(),
                {
                        &LibFuzz_Mut::Mutate_EraseByte,
                        &LibFuzz_Mut::Mutate_InsertByte,
                        &LibFuzz_Mut::Mutate_ChangeByte,
                        &LibFuzz_Mut::Mutate_ChangeBit,
                        &LibFuzz_Mut::Mutate_ShuffleBytes,
                        &LibFuzz_Mut::Mutate_ChangeASCIIInteger
                        //&LibFuzz_Mut::Mutate_AddWordFromManualDictionary,
                });
    }

    /// Mutates data by shuffling bytes.
    size_t Mutate_ShuffleBytes(uint8_t *Data, size_t Size, size_t MaxSize) {
        assert(Size);
        size_t ShuffleAmount =
                Rand(std::min(Size, (size_t)8)) + 1; // [1,8] and <= Size.
        size_t ShuffleStart = Rand(Size - ShuffleAmount);
        assert(ShuffleStart + ShuffleAmount <= Size);
        std::random_shuffle(Data + ShuffleStart, Data + ShuffleStart + ShuffleAmount,Rand);
        return Size;
    }

    /// Mutates data by erasing a byte.
    size_t Mutate_EraseByte(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size == 0) return 0;
        if (Size == 1) return SIZE_MAX;
        size_t Idx = Rand(Size);
        // Erase Data[Idx].
        memmove(Data + Idx, Data + Idx + 1, Size - Idx - 1);
        return Size - 1;
    }

    /// Mutates data by inserting a byte.
    size_t Mutate_InsertByte(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size == MaxSize) return 0;
        size_t Idx = Rand(Size + 1);
        // Insert new value at Data[Idx].
        memmove(Data + Idx + 1, Data + Idx, Size - Idx);
        Data[Idx] = (uint8_t) RandCh(Rand);
        return Size + 1;
    }

    /// Mutates data by chanding one byte.
    size_t Mutate_ChangeByte(uint8_t *Data, size_t Size, size_t MaxSize) {
        size_t Idx = Rand(Size);
        Data[Idx] = (uint8_t) RandCh(Rand);
        return Size;
    }

    /// Mutates data by chanding one bit.
    size_t Mutate_ChangeBit(uint8_t *Data, size_t Size, size_t MaxSize) {
        size_t Idx = Rand(Size);
        Data[Idx] = FlipRandomBit(Data[Idx], Rand);
        return Size;
    }

    /// Mutates data by adding a word from the manual dictionary.
    size_t Mutate_AddWordFromManualDictionary(uint8_t *Data, size_t Size,
                                              size_t MaxSize);

    /// Tries to find an ASCII integer in Data, changes it to another ASCII int.
    size_t Mutate_ChangeASCIIInteger(uint8_t *Data, size_t Size, size_t MaxSize) {
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

    /// CrossOver Data with some other element of the corpus.
    size_t Mutate_CrossOver(uint8_t *Data, size_t Size, size_t MaxSize);

    /// Applies one of the default mutations. Provided as a service
    /// to mutation authors.
    size_t DefaultMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
        assert(MaxSize > 0);
        assert(Size <= MaxSize);

        // Some mutations may fail (e.g. can't insert more bytes if Size == MaxSize),
        // in which case they will return 0.
        // Try several times before returning un-mutated data.
        for (int Iter = 0; Iter < 10; Iter++) {
            auto M = Mutators[Rand(Mutators.size())];
            size_t NewSize = (this->*M)(Data, Size, MaxSize);
            if (NewSize) {
                return NewSize;
            }
        }
        return Size;
    }

    /// Creates a cross-over of two pieces of Data, returns its size.
    size_t CrossOver(const uint8_t *Data1, size_t Size1, const uint8_t *Data2,
                     size_t Size2, uint8_t *Out, size_t MaxOutSize);

    //void AddWordToManualDictionary(const Word &W);

    //void AddWordToAutoDictionary(DictionaryEntry DE);

private:
    Random Rand;

    static char RandCh(Random &Rand) {
        if (Rand.RandBool()) return (char) Rand(256);
        const char *Special = "!*'();:@&=+$,/?%#[]123ABCxyz-`~.";
        return Special[Rand(sizeof(Special) - 1)];
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

    std::vector<Mutator> Mutators;
};

