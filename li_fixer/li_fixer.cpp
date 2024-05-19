// Include first because Windows.h has some amazing #defines that break things.
#include "argparse/argparse.hpp"

#include <iostream>
#include <fstream>
#include <Windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include "loguru/loguru.hpp"

#define PE_FILE_BUFFER char*
#define LIFX_SECTION_SIZE 0x16000

// Global variables.
bool LoguruSetup = false;
bool ParamsSetup = false;
size_t GlobalFunctionCount = 0;

// Global input arguments.
std::string InFilePath;
std::string OutFilePath;
std::string FunctionFilePath;
bool Verbose;

// Functions for IDA Python script.
struct FunctionName
{
    std::string Name;
    size_t VirtualAddress;
    //size_t Address;
};
std::vector<FunctionName> DecryptedFunctions; // We will save this to a file, then read it with a IDA Python script to rename all the created functions.



// Utility functions.
void Error(const std::string& Message)
{
    if (LoguruSetup)
        LOG_F(ERROR, "%s", Message.c_str());

    MessageBoxA(NULL, Message.c_str(), "Error", MB_ICONERROR);

    exit(1);
}
char* ReadFile(const std::string& FilePath, size_t* BufferSize)
{
    std::ifstream File(FilePath, std::ios::binary);
    if (File.is_open() == false)
    {
        std::string ErrorMessage = "Failed to open file: " + FilePath;
        Error(ErrorMessage);
    }

    // Get the size of the file.
    File.seekg(0, std::ios::end);
    size_t FileSize = File.tellg();
    File.seekg(0, std::ios::beg);

    // Read the file into a buffer.
    char* FileBuffer = (char*)malloc(FileSize);
    File.read(FileBuffer, FileSize);
    File.close();

    *BufferSize = FileSize;
    return FileBuffer;
}
void WriteFile(const std::string& FilePath, char* Buffer, size_t BufferSize)
{
    std::ofstream File(FilePath, std::ios::binary);
    if (File.is_open() == false)
    {
        std::string ErrorMessage = "Failed to open file: " + FilePath;
        Error(ErrorMessage);
    }

    File.write(Buffer, BufferSize);
    File.close();
}

// PE Helper functions.
size_t CreateNewSection(PE_FILE_BUFFER* Buffer, size_t SectionSize, std::string SectionName, size_t* VirtualOffset)
{
    PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(*Buffer);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "Invalid DOS signature" << std::endl;
        return -1;
    }

    PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(*Buffer) + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Invalid NT signature" << std::endl;
        return -1;
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    WORD NumberOfSections = NtHeader->FileHeader.NumberOfSections;

    PIMAGE_SECTION_HEADER LastSectionHeader = &SectionHeader[NumberOfSections - 1];

    DWORD NewSectionRawOffset = LastSectionHeader->PointerToRawData + LastSectionHeader->SizeOfRawData;
    DWORD NewSectionVirtualOffset = LastSectionHeader->VirtualAddress + LastSectionHeader->Misc.VirtualSize;

    DWORD SectionAlignment = NtHeader->OptionalHeader.SectionAlignment;
    DWORD FileAlignment = NtHeader->OptionalHeader.FileAlignment;

    NewSectionVirtualOffset = (NewSectionVirtualOffset + SectionAlignment - 1) & ~(SectionAlignment - 1);
    NewSectionRawOffset = (NewSectionRawOffset + FileAlignment - 1) & ~(FileAlignment - 1);

    PIMAGE_SECTION_HEADER NewSectionHeader = &SectionHeader[NumberOfSections];
    memset(NewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    strncpy_s(reinterpret_cast<char*>(NewSectionHeader->Name), sizeof(NewSectionHeader->Name), SectionName.c_str(), _TRUNCATE);
    NewSectionHeader->Misc.VirtualSize = SectionSize;
    NewSectionHeader->VirtualAddress = NewSectionVirtualOffset;
    NewSectionHeader->SizeOfRawData = (SectionSize + FileAlignment - 1) & ~(FileAlignment - 1);
    NewSectionHeader->PointerToRawData = NewSectionRawOffset;
    NewSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

    NtHeader->FileHeader.NumberOfSections++;
    NtHeader->OptionalHeader.SizeOfImage = NewSectionVirtualOffset + ((SectionSize + SectionAlignment - 1) & ~(SectionAlignment - 1));

    size_t NewBufferSize = NewSectionRawOffset + NewSectionHeader->SizeOfRawData;
    PE_FILE_BUFFER NewBuffer = reinterpret_cast<PE_FILE_BUFFER>(realloc(*Buffer, NewBufferSize));
    if (NewBuffer == nullptr)
    {
        std::cout << "Failed to reallocate memory" << std::endl;
        return -1;
    }

    // Clear the new section.
    //memset(NewBuffer + NewSectionRawOffset, 0, NewSectionHeader->SizeOfRawData);

    *Buffer = NewBuffer;
    if (VirtualOffset) *VirtualOffset = NewSectionVirtualOffset;

    return NewSectionRawOffset;
}
size_t GetFirstCodeSectionOffset(PE_FILE_BUFFER Buffer, size_t* SectionSize, size_t* VirtualOffset)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Buffer;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "Invalid DOS signature" << std::endl;
        return -1;
    }

    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((byte*)Buffer + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Invalid NT signature" << std::endl;
        return -1;
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    WORD NumberOfSections = NtHeader->FileHeader.NumberOfSections;

    for (int i = 0; i < NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER CurrentSection = &SectionHeader[i];
        if (CurrentSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            if (SectionSize) *SectionSize = CurrentSection->SizeOfRawData;
            if (VirtualOffset) *VirtualOffset = CurrentSection->VirtualAddress;

            return CurrentSection->PointerToRawData;
        }
    }

    return -1;
}
size_t CreateEmptyFunction(PE_FILE_BUFFER Buffer, size_t SectionOffset, size_t SectionSize)
{
    uint8_t Function[] = {
        0x57,   // push rdi
        0x5F,   // pop rdi
        0xC3    // retn
    };

    size_t FunctionOffset = SectionOffset + ((uint8_t)GlobalFunctionCount * sizeof(Function));
    char* FunctionAddress = Buffer + FunctionOffset;
    if (FunctionOffset + sizeof(Function) > SectionOffset + SectionSize)
        return -1;

    memcpy(FunctionAddress, Function, sizeof(Function));

    GlobalFunctionCount++;

    return FunctionOffset;
}

// Initialization functions.
void SetupCapstone(csh* Capstone)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, Capstone) != CS_ERR_OK)
    {
        std::string strerror = cs_strerror(cs_errno(*Capstone));
        std::string ErrorMessage = "Failed to disassemble instruction! Error: " + strerror;
        Error(ErrorMessage);
    }

    cs_option(*Capstone, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(*Capstone, CS_OPT_SKIPDATA, CS_OPT_ON);
}
void SetupKeystone(ks_engine** Keystone)
{
    if (ks_open(KS_ARCH_X86, KS_MODE_64, Keystone) != KS_ERR_OK)
    {
        std::string strerror = ks_strerror(ks_errno(*Keystone));
        std::string ErrorMessage = "Failed to assemble instruction! Error: " + strerror;
        Error(ErrorMessage);
    }
}
void SetupLoguru()
{
    if (ParamsSetup == false)
        Error("You must setup parameters before calling SetupLoguru()!");

    // Don't show the log file path in the console.
    loguru::Verbosity Verbosity = Verbose ? loguru::Verbosity_MAX : loguru::Verbosity_INFO;

    loguru::g_colorlogtostderr = false;

    loguru::g_preamble_date = false;
    loguru::g_preamble_time = true;
    loguru::g_preamble_uptime = false;
    loguru::g_preamble_thread = false;
    loguru::g_preamble_file = false;
    loguru::g_preamble_verbose = false;
    loguru::g_preamble_pipe = true;

    // Disable logging (just so we don't get the loguru startup message).
    loguru::g_internal_verbosity = loguru::Verbosity_MAX;
    loguru::add_file("li_fixer.log", loguru::Append, Verbosity);
    loguru::g_internal_verbosity = loguru::Verbosity_0;

    // Set the verbosity level.
    loguru::g_stderr_verbosity = Verbosity;

    LoguruSetup = true;
}
void ParseArguments(int argc, char** argv)
{
    argparse::ArgumentParser Parser("li_fixer");
    Parser.add_argument("-infile")
        .help("Path to binary with LazyImports.")
        .required();
    Parser.add_argument("-output")
        .help("Path to save the patched binary to.")
        .required();
    Parser.add_argument("-functions")
        .help("Path to save function rename data. (Interpreted by IDA Python script to rename functions)")
        .required();
    Parser.add_argument("-verbose")
        .help("Enable verbose logging.")
        .default_value(false)
        .implicit_value(true);

    try
    {
        Parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        std::string ErrorMessage = "Failed to parse arguments! Error: " + std::string(err.what());
        Error(ErrorMessage);
    }

    InFilePath = Parser.get<std::string>("-infile");
    OutFilePath = Parser.get<std::string>("-output");
    FunctionFilePath = Parser.get<std::string>("-functions");
    Verbose = Parser.get<bool>("-verbose");

    if (InFilePath.empty()) Error("Input file path is empty!");
    if (OutFilePath.empty()) Error("Output file path is empty!");
    if (FunctionFilePath.empty()) Error("Function file path is empty!");

    ParamsSetup = true;
}

// FNV-1a hash function.
bool FNV(const char* PotentialFunctionName, int MagicNum1, int MagicNum2, int MagicNum3)
{
    int v8; // edx
    const char* v9; // rax
    char v10; // cl
    BYTE* v11; // rax

    v8 = MagicNum1;
    v9 = PotentialFunctionName;
    v10 = *v9;
    v11 = (BYTE*)(v9 + 1);

    do
    {
        ++v11;
        v8 = MagicNum2 * (v8 ^ v10);
        v10 = *(v11 - 1);
    } while (v10);
    if (v8 == MagicNum3)
        return true;

    return false;
}
std::string DecrpytLazyImport(int MagicNum1, int MagicNum2)
{
    static bool Setup = false;
    static std::vector<std::string> files;
    if (Setup == false)
    {
        // output the current directory
        char currentDirectory[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, currentDirectory);
        std::cout << "Current directory: " << currentDirectory << std::endl;

        // Get every .txt file in the current directory
        WIN32_FIND_DATAA FindFileData;
        HANDLE hFind = FindFirstFileA("*.txt", &FindFileData);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            std::cout << "No .txt files found in the current directory" << std::endl;
            return "";
        }

        do
        {
            files.push_back(FindFileData.cFileName);
        } while (FindNextFileA(hFind, &FindFileData));

        FindClose(hFind);

        Setup = true;
    }

    // Itterate over ever .txt file and then every line in the file,
    // and check if the line is the correct password
    for (const auto& file : files)
    {
        std::ifstream fileStream(file);
        if (fileStream.is_open() == false)
        {
            std::cout << "Failed to open file: " << file << std::endl;
            continue;
        }

        std::string line;
        while (std::getline(fileStream, line))
        {
            if (FNV(line.c_str(), MagicNum1, 16777619, MagicNum2))
            {
                return line;
            }
        }
    }
}

// Instruction matching functions.
bool IsNtCurrentPeb(cs_insn* Instruction)
{
    // Target instruction:
    // mov rax, gs:60h

    if (Instruction->id != X86_INS_MOV) return false;                                   // Is instruction mov?
    if (Instruction->detail->x86.operands[0].type != X86_OP_REG) return false;          // Is first operand a register?
    if (Instruction->detail->x86.operands[1].type != X86_OP_MEM) return false;          // Is second operand a memory address?
    if (Instruction->detail->x86.operands[1].reg != X86_REG_GS) return false;           // Is the segment register GS?
    if (Instruction->detail->x86.operands[1].mem.disp != 0x60) return false;            // Is the displacement 0x60?

    return true;
}
bool IsCallRegister(cs_insn* Instruction)
{
    // Target instruction:
    // call REGISTER

    if (Instruction->id != X86_INS_CALL) return false;                                  // Is instruction call?
    if (Instruction->detail->x86.operands[0].type != X86_OP_REG) return false;          // Is first operand a register?

    return true;
}
bool IsJnz(cs_insn* Instruction)
{
    // Target instruction:
    // jnz

    if (Instruction->id != X86_INS_JNE) return false;                                   // Is instruction jnz?

    return true;
}
bool IsMovRegisterImm(cs_insn* Instruction)
{
    // Target instruction:
    // mov REGISTER, IMMEDIATE

    if (Instruction->id != X86_INS_MOV) return false;                                   // Is instruction mov?
    if (Instruction->detail->x86.operands[0].type != X86_OP_REG) return false;          // Is first operand a register?
    if (Instruction->detail->x86.operands[1].type != X86_OP_IMM) return false;          // Is second operand an immediate?

    return true;
}





int main(int argc, char** argv)
{
    ParseArguments(argc, argv);
    SetupLoguru();

    LOG_F(INFO, "Input file: %s", InFilePath.c_str());
    LOG_F(INFO, "Output file: %s", OutFilePath.c_str());
    LOG_F(INFO, "Function file: %s", FunctionFilePath.c_str());
    LOG_F(INFO, "Verbose: %s", Verbose ? "true" : "false");
    LOG_F(INFO, "");

    size_t InFileSize;
    PE_FILE_BUFFER InFileBuffer = ReadFile(InFilePath, &InFileSize);
    if (InFileBuffer == nullptr)
        Error("Failed to read file!");

    // Add a new section to the file.
    // This section will be used to store the dummies for LazyImports.
    // The reason we do this over just making a note in IDA, is because
    // this way we can easily see all XREFs to the LazyImports.
    size_t LazyFixerSectionOffset;
    size_t LazyFixerVirtualSectionOffset;
    if ((LazyFixerSectionOffset = CreateNewSection(&InFileBuffer, LIFX_SECTION_SIZE, ".lifx", &LazyFixerVirtualSectionOffset)) == -1)
        Error("Failed to create new section!");

    // Adjust the file size to account for the new section.
    InFileSize += LIFX_SECTION_SIZE;

    LOG_F(MAX, "Created new section at offset: 0x%08X (Virtual Offset: 0x%08X", LazyFixerSectionOffset, LazyFixerVirtualSectionOffset);

    // Find the first code section.
    // This will be used to find LazyImports.
    size_t CodeSectionOffset;
    size_t CodeSectionSize;
    size_t CodeSectionVirtualOffset;
    if ((CodeSectionOffset = GetFirstCodeSectionOffset(InFileBuffer, &CodeSectionSize, &CodeSectionVirtualOffset)) == -1)
        Error("Failed to find code section!");

    LOG_F(MAX, "Found code section at offset: 0x%08X (Virtual Offset: 0x%08X, Size: 0x%08X)", CodeSectionOffset, CodeSectionVirtualOffset, CodeSectionSize);

    // Setup the disassembler and assembler.
    csh Capstone;
    ks_engine* Keystone;
    SetupCapstone(&Capstone);
    SetupKeystone(&Keystone);

    // Disassemble the code section.
    cs_insn* Instructions;
    size_t InstructionCount = cs_disasm(Capstone, (uint8_t*)(InFileBuffer + CodeSectionOffset), CodeSectionSize, 0, 0, &Instructions);
    if (InstructionCount <= 0)
    {
        std::string strerror = cs_strerror(cs_errno(Capstone));
        std::string ErrorMessage = "Failed to disassemble instructions! Error: " + strerror;
        Error(ErrorMessage);
    }

    LOG_F(MAX, "Disassembled %d instructions", InstructionCount);
    LOG_F(INFO, "Starting disassembly...");
    LOG_F(INFO, "");

    // If verbose is disabled, then the lines in the loop won't be printed, so print a line here.
    // This is to make the output easier to read.
    if (Verbose == false) LOG_F(INFO, "-------------------------------------------------");

    // Iterate over every instruction and find the LazyImport functions.
    for (int MainInstructionIt = 0; MainInstructionIt < InstructionCount; MainInstructionIt++)
    {
        cs_insn* Instruction = &Instructions[MainInstructionIt];

        // NtCurrentPeb instruction.
        uint64_t NOPStartBoundIndex = 0; cs_insn* NOPStartBoundInstruction = nullptr;

        // jnz instruction, or two instructions after the jnz instruction.
        uint64_t NOPEndBoundIndex = 0; cs_insn* NOPEndBoundInstruction = nullptr;

        // Call instruction (calls LazyImported function).
        uint64_t CallRegisterIndex = 0;  cs_insn* CallRegisterInstruction = nullptr;

        size_t DummyFunctionVirtualOffset = 0;
        std::string DecryptedFunctionName = "";



        // Section 1: Find the NOP bounds and call instruction.
        if (IsNtCurrentPeb(Instruction) == false) continue;
        NOPStartBoundIndex = MainInstructionIt;
        NOPStartBoundInstruction = Instruction;

        // Log a line to signify we are on a new instruction.
        LOG_F(MAX, "-------------------------------------------------");
        LOG_F(MAX, "Found NtCurrentPeb (%s %s) at 0x%08X", NOPStartBoundInstruction->mnemonic, NOPStartBoundInstruction->op_str, (NOPStartBoundInstruction->address + CodeSectionVirtualOffset));

        for (int It = NOPStartBoundIndex; It < InstructionCount; It++)
        {
            cs_insn* NextInstruction = &Instructions[It];

            // The call function must call a register.
            // The opcode will only ever be 2 or 3 bytes long.
            if (IsCallRegister(NextInstruction) == false) continue;

            // Check if the call register instruction is too far away from the NtCurrentPeb instruction.
            // This is to avoid incorrectly NOPing instructions that are different functions, or not LazyImports.
            if (NextInstruction->address - NOPStartBoundInstruction->address > 1000)
            {
                break;
            }
            else
            {
                CallRegisterInstruction = NextInstruction;
                CallRegisterIndex = It;
            }

            break;
        }
        if (CallRegisterInstruction == nullptr) continue;

        LOG_F(MAX, "Found call register (%s %s) at 0x%08X", CallRegisterInstruction->mnemonic, CallRegisterInstruction->op_str, (CallRegisterInstruction->address + CodeSectionVirtualOffset));

        for (int It = CallRegisterIndex; It > NOPStartBoundIndex; It--)
        {
            cs_insn* LoopInstruction = &Instructions[It];

            if (IsJnz(LoopInstruction) == false) continue;

            // Sometimes in LazyImporter, there are 2 extra junk instructions after the jnz instruction.
            // Check if there is a
            // mov ???
            // jmp ???
            // after the jnz instruction.
            cs_insn* InstructionOne = &Instructions[It + 1];
            cs_insn* InstructionTwo = &Instructions[It + 2];

            if (InstructionOne->id == X86_INS_MOV
                && InstructionTwo->id == X86_INS_JMP)
            {
                NOPEndBoundInstruction = InstructionTwo;
                NOPEndBoundIndex = It + 2;
            }
            else
            {
                NOPEndBoundInstruction = LoopInstruction;
                NOPEndBoundIndex = It;
            }

            break;
        }
        if (NOPEndBoundInstruction == nullptr) continue;

        LOG_F(MAX, "Found jnz (%s %s) at 0x%08X", NOPEndBoundInstruction->mnemonic, NOPEndBoundInstruction->op_str, (NOPEndBoundInstruction->address + CodeSectionVirtualOffset));


        // Section 2: Decrypt the LazyImport function.
        for (int It = NOPStartBoundIndex; It < NOPEndBoundIndex; It++)
        {
            cs_insn* LoopInstruction = &Instructions[It];

            // To decrypt the LazyImport function, we need to find two instructions:
            // 1. The first mov instruction that moves a constant value into a register.
            if (IsMovRegisterImm(LoopInstruction) == false) continue;

            // 2. The first cmp instruction after the mov instruction.
            int MaxSubIt = It + 50;
            for (int SubIt = It; SubIt < MaxSubIt; SubIt++)
            {
                cs_insn* SubLoopInstruction = &Instructions[SubIt];

                if (SubLoopInstruction->id != X86_INS_CMP) continue;

                // We've now found everything we need to decrypt the LazyImport function.
                uint64_t MagicNumber1 = LoopInstruction->detail->x86.operands[1].imm;
                uint64_t MagicNumber2 = SubLoopInstruction->detail->x86.operands[1].imm;

                LOG_F(MAX, "Found MagicNumber1: %d at 0x%08X (%s %s)", MagicNumber1, (LoopInstruction->address + CodeSectionVirtualOffset), LoopInstruction->mnemonic, LoopInstruction->op_str);
                LOG_F(MAX, "Found MagicNumber2: %d at 0x%08X (%s %s)", MagicNumber2, (SubLoopInstruction->address + CodeSectionVirtualOffset), SubLoopInstruction->mnemonic, SubLoopInstruction->op_str);

                DecryptedFunctionName = DecrpytLazyImport(MagicNumber1, MagicNumber2);
                if (DecryptedFunctionName.empty())
                {
                    LOG_F(INFO, "Failed to decrypt LazyImport at 0x%08X", (NOPStartBoundInstruction->address + CodeSectionVirtualOffset));
                    DecryptedFunctionName = "sub_lifx_" + std::to_string(GlobalFunctionCount);
                }
                else
                {
                    LOG_F(INFO, "Decrypted LazyImport: %s", DecryptedFunctionName.c_str());
                }

                // Now we can insert the decrypted function into the .lifx section
                // and the vector of decrypted functions.
                bool FunctionExists = false;
                for (const auto& Function : DecryptedFunctions)
                {
                    if (Function.Name == DecryptedFunctionName)
                    {
                        FunctionExists = true;
                        DummyFunctionVirtualOffset = Function.VirtualAddress;

                        break;
                    }
                }

                // If we didn't find it in the DecryptedFunctions vector, that
                // means this is the first time we've decrypted this function.
                // We need to create a new dummy function for it.
                if (FunctionExists == false)
                {
                    size_t DummyFunctionOffset = CreateEmptyFunction(InFileBuffer, LazyFixerSectionOffset, LIFX_SECTION_SIZE);
                    if (DummyFunctionOffset == -1)
                        Error("Failed to create dummy function!");

                    DummyFunctionVirtualOffset = LazyFixerVirtualSectionOffset + DummyFunctionOffset - LazyFixerSectionOffset;
                    DecryptedFunctions.push_back({ DecryptedFunctionName, DummyFunctionVirtualOffset/*, DummyFunctionOffset*/ });
                }

                break;
            }

            break;
        }


        // Section 3: NOP the instructions between the NOP bounds.
        for (int It = NOPStartBoundIndex; It <= NOPEndBoundIndex; It++)
        {
            cs_insn* InstructionToNop = &Instructions[It];

            // 0x90 is NOP in x86 ASM.
            char* InstructionAddress = (char*)InFileBuffer + (InstructionToNop->address + CodeSectionOffset);
            memset(InstructionAddress, 0x90, InstructionToNop->size);
        }


        // Section 4: Write the new instructions.
        // Write the instruction to reference the dummy function.

        // Calculate the address of the call instruction
        uint64_t VirtualAddress = (uint64_t)((uint8_t*)NOPEndBoundInstruction->address + CodeSectionVirtualOffset);
        VirtualAddress -= 32;

        // Reference the dummy function (preferably without calling it)
        std::string Asm = "push rax";
        Asm += " ; lea rax, qword ptr [" + std::to_string(DummyFunctionVirtualOffset) + "]";
        Asm += " ; call rax";
        Asm += " ; pop rax";

        // Assemble the instruction
        unsigned char* Encoding;
        size_t EncodingSize;
        size_t StatCount;
        if (ks_asm(Keystone, Asm.c_str(), VirtualAddress, &Encoding, &EncodingSize, &StatCount) != KS_ERR_OK)
        {
            std::string strerror = ks_strerror(ks_errno(Keystone));
            std::string ErrorMessage = "Failed to assemble instruction! Error: " + strerror;
            Error(ErrorMessage);
        }

        LOG_F(MAX, "Assembled instruction: %s", Asm.c_str());

        // Write the new instruction to the buffer.
        memcpy((char*)InFileBuffer + (NOPEndBoundInstruction->address +  CodeSectionOffset) - 32, Encoding, EncodingSize);

        // Free the encoding.
        ks_free(Encoding);
    }

    LOG_F(INFO, "-------------------------------------------------");
    LOG_F(INFO, "");
    LOG_F(INFO, "Finished disassembly");

    // Exit clean up.
    cs_free(Instructions, InstructionCount);
    cs_close(&Capstone);
    ks_close(Keystone);

    // Write the patched file to disk.
    WriteFile(OutFilePath, InFileBuffer, InFileSize);

    LOG_F(INFO, "Patched file written to: %s", OutFilePath.c_str());

    // Write the function names and addresses to a file.
    // These will later be interpreted by a python script in IDA to rename the functions.
    std::ofstream function_file(FunctionFilePath);

    // Write a magic number to the file so the IDA Python script can verify it.
    function_file << "li_fixer" << std::endl;

    for (const auto& Function : DecryptedFunctions)
    {
        function_file << Function.Name << "_lifx" << "," << std::hex << Function.VirtualAddress << std::endl;
    }
    function_file.close();

    LOG_F(INFO, "Function file written to: %s", FunctionFilePath.c_str());
    LOG_F(INFO, "li_fixer finished!");

    return 0;
}





// IDA Python script to rename the functions.
/*
import idaapi
import ida_kernwin

def RenameFunctions(FilePath):
    with open(FilePath, 'r') as file:
        # Check if the first line is equal to the magic number
        MagicNumber = file.readline().strip()
        if MagicNumber != "li_fixer":
            ida_kernwin.error("The file is not a valid li_fixer output.")
            return

        for line in file:
            FunctionName, Address = line.strip().split(',')
            Address = int(Address, 16)
            Address += idaapi.get_imagebase()
            idaapi.set_name(Address, FunctionName)
            print(f"Renamed function at 0x{Address:08X} to {FunctionName}")

FilePath = ida_kernwin.ask_file(0, "*.txt", "Please select the functions file that li_fixer generated.")
if FilePath:
    RenameFunctions(FilePath)
else:
    ida_kernwin.error("No file selected.")
*/