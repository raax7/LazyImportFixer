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

#include "FNVDatabase.h"

#pragma comment(lib, "urlmon.lib")

#define PE_FILE_BUFFER char*

// Global variables.
bool LoguruSetup = false;
bool ParamsSetup = false;
bool FNVDatabaseSetup = false;
size_t GlobalFunctionCount = 0;
std::ifstream LiFNVDatabaseFile;

// Global input arguments.
std::string InFilePath;
std::string OutFilePath;
std::string FunctionFilePath;
std::string LiFNVDatabasePath;
bool Verbose;
int LiFNVConstant;
bool NoMissingFix;
int LifxSectionSize;

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
void SetupFNVDatabase()
{
    if (ParamsSetup == false)
        Error("You must setup parameters before calling SetupFNVDatabase()!");

    LiFNVDatabaseFile.open(LiFNVDatabasePath);
    if (LiFNVDatabaseFile.is_open() == false)
    {
        std::string ErrorMessage = "Failed to open FNV database file: " + LiFNVDatabasePath;
        ErrorMessage += "\nYou can automatically download the FNV database by removing the -nomissingfix argument.";
        Error(ErrorMessage);
    }

    FNVDatabaseSetup = true;
}
void ParseArguments(int argc, char** argv)
{
    argparse::ArgumentParser Parser("li_fixer");
    Parser.add_argument("-infile")
        .help("Path to binary with LazyImports.")
        .required();
    Parser.add_argument("-outfile")
        .help("Path to save the patched binary to.")
        .default_value("li_fixer_patched.bin");
    Parser.add_argument("-functions")
        .help("Path to save function rename data. (Interpreted by IDA Python script to rename functions)")
        .default_value("li_fixer_functions.txt");
    Parser.add_argument("-fnvdatabase")
        .help("Path to the FNV database file, contains a list of all possible FNV passwords (DLL export names). (Default: li_fnvdatabase.txt)")
        .default_value("li_fixer_fnvdatabase.txt");
    Parser.add_argument("-fnvconst")
        .help("Constant for the FNV hash function.")
        .default_value(16777619);
    Parser.add_argument("-lifxsectionsize")
        .help("Size of the .lifx section. If you're binary has many LazyImports, you should increase this size.")
        .default_value(0x1000);
    Parser.add_argument("-verbose")
        .help("Enable verbose logging.")
        .default_value(false)
        .implicit_value(true);
    Parser.add_argument("-nomissingfix")
        .help("Disables automatically writing the FNV database and IDA Python script. (if they are missing)")
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
    OutFilePath = Parser.get<std::string>("-outfile");
    FunctionFilePath = Parser.get<std::string>("-functions");
    LiFNVDatabasePath = Parser.get<std::string>("-fnvdatabase");
    LiFNVConstant = Parser.get<int>("-fnvconst");
    LifxSectionSize = Parser.get<int>("-lifxsectionsize");
    Verbose = Parser.get<bool>("-verbose");
    NoMissingFix = Parser.get<bool>("-nomissingfix");

    if (InFilePath.empty()) Error("Input file path is empty!");
    if (OutFilePath.empty()) Error("Out file path is empty!");
    if (FunctionFilePath.empty()) Error("Function file path is empty!");
    if (LiFNVDatabasePath.empty()) Error("FNV database path is empty!");

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
    if (FNVDatabaseSetup == false || LiFNVDatabaseFile.is_open() == false)
        Error("You must setup the FNV database before calling DecrpytLazyImport()!");

    // Reset the file to the beginning.
    LiFNVDatabaseFile.clear();
    LiFNVDatabaseFile.seekg(0, std::ios::beg);

    std::string CurrentLine;
    while (std::getline(LiFNVDatabaseFile, CurrentLine))
    {
        if (FNV(CurrentLine.c_str(), MagicNum1, LiFNVConstant, MagicNum2))
        {
            return CurrentLine;
        }
    }

    return "";
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

// Helper functions.
void DetectMissingFiles()
{
    if (ParamsSetup == false || LoguruSetup == false)
        Error("You must setup parameters, loguru, and the FNV database before calling DetectAndDownload()!");

    // Check if the FNV database exists.
    std::ifstream FNVDatabaseFile(LiFNVDatabasePath);
    if (FNVDatabaseFile.is_open() == false)
    {
        LOG_F(INFO, "FNV database not found, downloading...");

        std::ofstream FNVDatabaseFile(LiFNVDatabasePath, std::ios_base::binary);
        FNVDatabaseFile << RawFNVDatabase;
        FNVDatabaseFile.close();

        LOG_F(INFO, "FNV database downloaded to: %s", LiFNVDatabasePath.c_str());
    }

    // Check if the IDA Python script exists.
    std::ifstream IDAPythonScriptFile("li_fixer_ida.py");
    if (IDAPythonScriptFile.is_open() == false)
    {
        LOG_F(INFO, "IDA Python script not found, downloading...");

        // Download the IDA Python script.
        std::string IDAPythonScript = R"(
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
)";

        std::ofstream IDAPythonScriptFile("li_fixer_ida.py");
        IDAPythonScriptFile << IDAPythonScript;
        IDAPythonScriptFile.close();

        LOG_F(INFO, "IDA Python script saved to: li_fixer_ida.py");
    }
}





int main(int argc, char** argv)
{
    ParseArguments(argc, argv);
    SetupLoguru();

    LOG_F(INFO, "Input file: %s", InFilePath.c_str());
    LOG_F(INFO, "Output file: %s", OutFilePath.c_str());
    LOG_F(INFO, "Function file: %s", FunctionFilePath.c_str());
    LOG_F(INFO, "FNV database: %s", LiFNVDatabasePath.c_str());
    LOG_F(INFO, "FNV constant: %d", LiFNVConstant);
    LOG_F(INFO, "LiFx section size: 0x%08X", LifxSectionSize);
    LOG_F(INFO, "Verbose: %s", Verbose ? "true" : "false");
    LOG_F(INFO, "No missing fix: %s", NoMissingFix ? "true" : "false");
    LOG_F(INFO, "");

    if (NoMissingFix == false) DetectMissingFiles();
    SetupFNVDatabase();

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
    if ((LazyFixerSectionOffset = CreateNewSection(&InFileBuffer, LifxSectionSize, ".lifx", &LazyFixerVirtualSectionOffset)) == -1)
        Error("Failed to create new section!");

    // Adjust the file size to account for the new section.
    InFileSize += LifxSectionSize;

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
                    LOG_F(INFO, "Decrypted LazyImport: %s at 0x%08X", DecryptedFunctionName.c_str(), (NOPStartBoundInstruction->address + CodeSectionVirtualOffset));
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
                    size_t DummyFunctionOffset = CreateEmptyFunction(InFileBuffer, LazyFixerSectionOffset, LifxSectionSize);
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

        // Move everything between the NOP end bound and the call instruction BACKWARDS 32 bytes.
        // This is to make room for the new instruction that will reference the dummy function.
// Calculate the size of the block to move (from the end of NOP to the call instruction)
        size_t MoveSize = (CallRegisterInstruction->address /*+ CallRegisterInstruction->size*/) - NOPEndBoundInstruction->address;
        MoveSize += NOPEndBoundInstruction->size;


        // Calculate source and destination addresses
        char* Source = (char*)InFileBuffer + NOPEndBoundInstruction->address + CodeSectionOffset;
        char* Destination = Source - 64;

        // Move the bytes back manually
        for (size_t i = 1; i < MoveSize; i++)
        {
            Destination[i] = Source[i];
        }

        // Log the moved bytes
        for (size_t i = 0; i < MoveSize; i++)
        {
            LOG_F(INFO, "0x%02X", (unsigned char)Destination[i]);
        }

        // Fill the new space created with NOPs
        for (size_t i = 0; i < MoveSize; i++)
        {
            Source[i] = 0x90;
        }

        LOG_F(INFO, "NOPEndBoundInstruction->address: 0x%llX", NOPEndBoundInstruction->address + CodeSectionVirtualOffset);
        LOG_F(INFO, "CallRegisterInstruction->address: 0x%llX", CallRegisterInstruction->address + CodeSectionVirtualOffset);
        LOG_F(INFO, "MoveSize: 0x%llX", MoveSize);
        LOG_F(INFO, "Source: 0x%p", Source - InFileBuffer - CodeSectionOffset + CodeSectionVirtualOffset);
        LOG_F(INFO, "Destination: 0x%p", Destination - InFileBuffer - CodeSectionOffset + CodeSectionVirtualOffset);


        // Write the instruction to reference the dummy function.

        // Calculate the address of the call instruction
        uint64_t VirtualAddress = (uint64_t)((Destination - InFileBuffer) + MoveSize - CallRegisterInstruction->size);
        VirtualAddress -= CodeSectionOffset;
        VirtualAddress += CodeSectionVirtualOffset;

        LOG_F(INFO, "VirtualAddress: 0x%llX", VirtualAddress);

        // Reference the dummy function (preferably without calling it)
        std::string Asm = "call " + std::to_string(DummyFunctionVirtualOffset);

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
        memcpy(Destination + MoveSize - CallRegisterInstruction->size, Encoding, EncodingSize);

        // Free the encoding.
        ks_free(Encoding);



        // Loop over the moved instructions and adjust any relative addresses.
        for (int It = NOPEndBoundIndex; It < CallRegisterIndex; It++)
        {
            cs_insn* Instruction = &Instructions[It];

            // Check if the instruction references a memory address.
            for (int OpIt = 0; OpIt < Instruction->detail->x86.op_count; OpIt++)
            {
                if (Instruction->detail->x86.operands[OpIt].type == X86_OP_MEM)
                {
#if 0
                    if (Instruction->detail->x86.operands[OpIt].mem.base == X86_REG_RIP)
                    {
                        // Calculate the new address.
                        uint64_t NewAddress = Instruction->detail->x86.operands[OpIt].mem.disp - 64;
                        NewAddress += VirtualAddress;

                        // Write the new address to the buffer.
                        char* Address = (char*)InFileBuffer + (Instruction->address + CodeSectionOffset) - 64;
                        Address += Instruction->detail->x86.operands[OpIt].mem.disp;
                        //Address += 0x40;

                        *(uint64_t*)Address = NewAddress;

                        Address = (char*)(Address - InFileBuffer) - CodeSectionOffset + CodeSectionVirtualOffset;

                        LOG_F(INFO, "Adjusted relative address at 0x%08X to 0x%08X", Address, NewAddress);
                    }

                    // Calculate the new address.
                    uint64_t NewAddress = Instruction->detail->x86.operands[0].mem.disp - 64;
                    NewAddress += VirtualAddress;

                    // Write the new address to the buffer.
                    char* Address = (char*)InFileBuffer + (Instruction->address + CodeSectionOffset) - 64;
                    Address += Instruction->detail->x86.operands[0].mem.disp;
                    //Address += 0x40;

                    *(uint64_t*)Address = NewAddress;

                    Address = (char*)(Address - InFileBuffer) - CodeSectionOffset + CodeSectionVirtualOffset;

                    LOG_F(INFO, "Adjusted relative address at 0x%08X to 0x%08X", Address, NewAddress);
#endif
                }
            }
        }
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

    LiFNVDatabaseFile.close();

    LOG_F(INFO, "li_fixer finished!");

    return 0;
}