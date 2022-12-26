// translator.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <windows.h>
#include <WinNT.h>

#include <cassert>
#include <cstdint>
#include <iostream> 
#include <map> 
#include <string> 
#include <vector> 

using std::cerr;
using std::map;
using std::string;
using std::vector;

struct UNWIND_INFO_
{
    BYTE Ver3_Flags; // versions and flags
    BYTE PrologSize;
    BYTE CntUnwindCodes;
    BYTE FrReg_FrRegOff; // frame register and offsets
    // dd ExceptionHandler or FunctionEntry
    // ExceptionData
};

#ifndef UNW_FLAG_EHANDLER
enum { UNW_FLAG_EHANDLER = 1 };
#endif

struct RUNTIME_FUNCTION_
{
    uint32_t FunctionStart;
    uint32_t FunctionEnd;
    uint32_t UnwindInfo;
};

void trace(const char *format, ...)
{
    char buffer[4000];

    va_list vl;
    va_start(vl, format);

    vsnprintf_s(buffer, _countof(buffer), _TRUNCATE, format, vl);

    va_end(vl);
    OutputDebugStringA(buffer);
}

class MemoryMappedFile
{
public:
    MemoryMappedFile() 
        : hFile(INVALID_HANDLE_VALUE)   
    {}
    ~MemoryMappedFile() 
    {
        if (pData) {
            UnmapViewOfFile(pData);
        }
        if (hFileMapping) {
            CloseHandle(hFileMapping);
        }
        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }
    }

    bool MapFlie(LPCTSTR szFile)
    {
        hFile = CreateFile(
            szFile,					    // pointer to name of the file
            GENERIC_READ,               // access (read-write) mode
            0,							// share mode 
            nullptr,						// pointer to security attributes 
            OPEN_EXISTING,				// how to create 
            FILE_ATTRIBUTE_NORMAL,		// file attributes 
            nullptr						// handle to file with attributes to copy
        ); 
        if (INVALID_HANDLE_VALUE != hFile && GetFileSizeEx(hFile, &fileSize))
        { 
            hFileMapping = CreateFileMapping(
                hFile,			    // handle to file to map 
                nullptr,				// optional security attributes 
                PAGE_READONLY,      // protection for mapping object 
                fileSize.HighPart,	// high-order 32 bits of object size 
                fileSize.LowPart,	// low-order 32 bits of object size 
                nullptr				// name of file-mapping object 
            ); 
            if (nullptr != hFileMapping)
            {
                pData = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, (SIZE_T)fileSize.QuadPart);
                return pData != nullptr;
            }
        }

        return false;
    }

    LPVOID data() const { return pData; }
    LONGLONG size() const { return fileSize.QuadPart; }

private:
    HANDLE hFile;
    LARGE_INTEGER fileSize;
    HANDLE hFileMapping{NULL};
    LPVOID pData{NULL};
};

//////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)

struct Header { 
    union {
        char magic[8]; 
        uint64_t signature;
    };
    uint32_t codeSize; 
    uint32_t dataSize; 
    uint32_t initialDataSize; 
};

struct Instruction {
    BYTE Opcode;
    signed char Destination;
    signed char Source;
};

#pragma pack(pop)

const uint64_t SIGNATURE_ESET_VM1 = 0x314d562d54455345;

static_assert(sizeof(Instruction) == 3, "Every instruction is 3 bytes long");

enum {
    IMAGEBASE = 0x400000,

    SECTIONALIGN = 0x1000,
    FILEALIGN = 0x200,

    NUMBEROFSECTIONS = 2,

    REGISTER_SIZE = 8,
    REGISTERS_NUMBER = 32,
    REGISTER_TABLE_SIZE = REGISTER_SIZE * REGISTERS_NUMBER,
};

struct Headers64
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    IMAGE_SECTION_HEADER sectionHeaders[NUMBEROFSECTIONS];
};

size_t Align(size_t size, size_t align)
{
    return (size + align - 1) & ~(align - 1);
}

void Align(vector<BYTE>& section, size_t align, BYTE code)
{
    section.resize((section.size() + align - 1) & ~(align - 1), code);
}

class InstructionContext
{
public:
    bool TranslateEvmFile(LPCTSTR szInFile, LPCTSTR szOutFile);

private:
    bool AddInstruction(
        BYTE instruction, 
        signed char dst, 
        signed char src, 
        size_t instructionNumber,
        uint32_t dataSize);
    bool MakeExecutable(
        LPCTSTR szFile, 
        const void* data, 
        size_t dataSize, 
        size_t dataSpaceSize);

private:
    vector<BYTE> section;
    map<string, map<string, vector<size_t>>> imports;
    map<string, vector<size_t>> strings;
    map<size_t, map<size_t, vector<size_t>>> dataMappings;
    map<size_t, vector<size_t>> jumps;
};

bool InstructionContext::TranslateEvmFile(LPCTSTR szInFile, LPCTSTR szOutFile)
{
    MemoryMappedFile mmf;
    if (!mmf.MapFlie(szInFile))
    {
        cerr << "Cannot open evm file.\n";
        return false;
    }

    auto* header = (Header*) mmf.data();
    trace("Header codeSize = %u, dataSize = %u, initialDataSize = %u\n", 
        header->codeSize, header->dataSize, header->initialDataSize);
    // verify
    if (header->signature != SIGNATURE_ESET_VM1 
        || header->dataSize < header->initialDataSize
        || header->codeSize * 3 + header->initialDataSize + 20 != mmf.size())
    {
        cerr << "Invalid evm file.\n";
        return false;
    }

    auto* instruction = (Instruction*)(header + 1);

    //section.push_back(0xCC); // Debug

    vector<size_t> instructionOffsets;
    instructionOffsets.resize(header->codeSize);
    for (uint32_t i = 0; i < header->codeSize; ++i, ++instruction)
    {
        instructionOffsets[i] = section.size();
        if (!AddInstruction(
                instruction->Opcode, 
                instruction->Destination, 
                instruction->Source, 
                i, 
                header->dataSize))
        {
            return false;
        }
    }

    // Handle jumps
    for (auto & jump : jumps)
    {
        for (auto offset : jump.second)
        {
            auto* pos = (uint32_t*) &section[offset];
            size_t instructionIndex = jump.first + 1;
            if (instructionIndex >= instructionOffsets.size())
            {
                cerr << "Error: Jump address out of bounds\n";
                return false;
            }
            *pos = instructionOffsets[instructionIndex] - sizeof(uint32_t) - offset;
        }
    }

    return MakeExecutable(szOutFile, instruction, header->initialDataSize, header->dataSize);
}

#define VERIFY_REGISTER_IDX(param) \
    do { \
        if ((param) < 0 || (param) >= REGISTERS_NUMBER) { \
            cerr << "Error: Instruction register index out of bounds\n"; return false; \
        } \
    } while (false)

bool InstructionContext::AddInstruction(
    BYTE instruction, 
    signed char dst, 
    signed char src, 
    size_t instructionNumber,
    uint32_t dataSize)
{
    const size_t offset = section.size();
    trace("%4d ", instructionNumber);
    switch (instruction)
    {
    case 32:
        trace("NOP\n");
        break; // nop

    case 40: // IN reg read hexadecimal value from standard input, and store in registry reg reg <- stdin
        {
            trace("IN reg%d <- stdin\n", dst);
            VERIFY_REGISTER_IDX (dst);
            const BYTE scanCode[] = {
                0x48, 0x8D, 0x15, 0x18, 0x81, 0x00, 0x00, //lea         rdx,[]  
                0x48, 0x8D, 0x0D, 0x51, 0x57, 0x00, 0x00, //lea         rcx,[]  
                0xFF, 0x15, 0x0B, 0xA5, 0x00, 0x00,		  //call        qword ptr []  
                0x85, 0xC0,             //test        eax,eax  
                0x75, 0x15,             //jne
                0x48, 0x8D, 0x0D, 0x45, 0x57, 0x00, 0x00, //lea         rcx,[]  
                0xFF, 0x15, 0xFF, 0xA4, 0x00, 0x00,       //call        qword ptr []  
                0x31, 0xC9, 			//xor ecx, ecx
                0xFF, 0x15, 0, 0, 0, 0,	//call []
            };
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 3);

            imports["msvcrt.dll"]["scanf"].push_back(offset + 16);
            strings["%I64X"].push_back(offset + 10);

            imports["msvcrt.dll"]["printf"].push_back(offset + 9 + 24);
            imports["kernel32.dll"]["ExitProcess"].push_back(offset + 17 + 24);
            strings["Error: Unable to read stdin\n"].push_back(offset + 3 + 24);

            section.insert(section.end(), std::begin(scanCode), std::end(scanCode));
        }
        break;

    case 41: // OUT reg write hexadecimal value in registry reg to standard output stdout <- reg
        {
            trace("OUT stdout <- reg%d\n", dst);
            VERIFY_REGISTER_IDX (dst);
            const BYTE printCode[] = {
                0x48, 0x8B, 0x15, 0x04, 0x81, 0x00, 0x00, //mov         rdx,qword ptr []  
                0x48, 0x8D, 0x0D, 0x45, 0x57, 0x00, 0x00, //lea         rcx,[]  
                0xFF, 0x15, 0xFF, 0xA4, 0x00, 0x00,       //call        qword ptr []  
            };
            imports["msvcrt.dll"]["printf"].push_back(offset + 16);
            strings["%016I64X\n"].push_back(offset + 10);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 3);
            section.insert(section.end(), std::begin(printCode), std::end(printCode));
        }
        break;

    case 48: // STORE reg1,reg2 store value of reg2 in memory cell pointed by reg1 [reg1] = reg2
        {
            trace("STORE [reg%d] = reg%d\n", dst, src);
            if (dataSize < REGISTER_SIZE)
            {
                cerr << "Error: dataSize is too small\n"; 
                return false;
            }
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8D, 0x05, 0x0D, 0x81, 0x00, 0x00, //lea         rax,[]  
                0x48, 0x8B, 0x0D, 0x0E, 0x85, 0x00, 0x00, //mov         rcx,qword ptr []

                0x48, 0x81, 0xF9, 0x10, 0x27, 0x00, 0x00, //cmp    rcx,0x2710
                0x7E, 0x15,                //jle

                0x48, 0x8D, 0x0D, 0x45, 0x57, 0x00, 0x00, //lea         rcx,[]  
                0xFF, 0x15, 0xFF, 0xA4, 0x00, 0x00,       //call        qword ptr []  
                0x31, 0xC9, 			//xor ecx, ecx
                0xFF, 0x15, 0, 0, 0, 0,	//call []

                0x48, 0x8B, 0x15, 0xFF, 0x84, 0x00, 0x00, //mov         rdx,qword ptr []  
                0x48, 0x89, 0x14, 0x08,                   //mov         qword ptr [rax+rcx],rdx  
            };
            dataMappings[0][REGISTER_TABLE_SIZE].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 10);

            imports["msvcrt.dll"]["printf"].push_back(offset + 9 + 23);
            imports["kernel32.dll"]["ExitProcess"].push_back(offset + 17 + 23);
            strings["Error: Runtime memory offset out of bounds\n"].push_back(offset + 3 + 23);

            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 17 + 30);
            section.insert(section.end(), std::begin(code), std::end(code));
            auto* pos = (uint32_t*) &section[offset + 17];
            *pos = dataSize - REGISTER_SIZE;
        }
        break;

    case 49: // LOAD reg1, reg2  load value from memory cell pointed by reg1 into register reg2 reg1 = [reg2]
        {
            trace("LOAD reg%d = [reg%d]\n", dst, src);
            if (dataSize < REGISTER_SIZE)
            {
                cerr << "Error: dataSize is too small\n"; 
                return false;
            }
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8D, 0x05, 0x0D, 0x81, 0x00, 0x00, //lea         rax,[]  
                0x48, 0x8B, 0x0D, 0x0E, 0x85, 0x00, 0x00, //mov         rcx,qword ptr []  

                0x48, 0x81, 0xF9, 0x10, 0x27, 0x00, 0x00, //cmp    rcx,0x2710
                0x7E, 0x15,                //jle

                0x48, 0x8D, 0x0D, 0x45, 0x57, 0x00, 0x00, //lea         rcx,[]  
                0xFF, 0x15, 0xFF, 0xA4, 0x00, 0x00,       //call        qword ptr []  
                0x31, 0xC9, 			//xor ecx, ecx
                0xFF, 0x15, 0, 0, 0, 0,	//call []

                0x48, 0x8B, 0x04, 0x08,                   //mov         rax,qword ptr [rax+rcx]  
                0x48, 0x89, 0x05, 0xFB, 0x84, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_TABLE_SIZE].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 10);

            imports["msvcrt.dll"]["printf"].push_back(offset + 9 + 23);
            imports["kernel32.dll"]["ExitProcess"].push_back(offset + 17 + 23);
            strings["Error: Runtime memory offset out of bounds\n"].push_back(offset + 3 + 23);

            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 21 + 30);
            section.insert(section.end(), std::begin(code), std::end(code));
            auto* pos = (uint32_t*) &section[offset + 17];
            *pos = dataSize - REGISTER_SIZE;
        }
        break;

    case 50: // LDC reg, imm8 load 8-bit immediate value to reg reg = imm8 (unsigned)
        {
            const uint32_t imm = static_cast<unsigned char>(src);
            trace("LDC reg%d = %d\n", dst, imm);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0xC7, 0x05, 0xDC, 0x66, 0x00, 0x00, //mov         qword ptr [value (140009558h)], ...  
            };
            dataMappings[4][REGISTER_SIZE * dst].push_back(offset + 3);
            section.insert(section.end(), std::begin(code), std::end(code));
            section.insert(section.end(), (const BYTE*)&imm, (const BYTE*)(&imm + 1));
        }
        break;

    case 64: // MOV reg1, reg2  copy value from register2 to register1 reg1 = reg2
        {
            trace("MOV reg%d = reg%d\n", dst, src);
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8B, 0x05, 0xD5, 0x66, 0x00, 0x00, //mov         rax,qword ptr []  
                0x48, 0x89, 0x05, 0xC6, 0x66, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 10);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 65: // ADD reg1, reg2 add value of reg2 to reg1, and save result in reg1 reg1 = reg1 + reg2
        {
            trace("ADD reg%d += reg%d\n", dst, src);
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8B, 0x05, 0xD5, 0x66, 0x00, 0x00, //mov         rax,qword ptr []  
                0x48, 0x8B, 0x0D, 0xC6, 0x66, 0x00, 0x00, //mov         rcx,qword ptr []  
                0x48, 0x03, 0xC8,                         //add         rcx,rax  
                0x48, 0x8B, 0xC1,                         //mov         rax,rcx  
                0x48, 0x89, 0x05, 0xB9, 0x66, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 10);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 23);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 66: // SUB reg1, reg2 subtract value of reg2 from reg1, and save result in reg1
        {
            trace("SUB reg%d -= reg%d\n", dst, src);
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8B, 0x05, 0xD5, 0x66, 0x00, 0x00, //mov         rax,qword ptr []  
                0x48, 0x8B, 0x0D, 0xC6, 0x66, 0x00, 0x00, //mov         rcx,qword ptr []  
                0x48, 0x2B, 0xC8,                         //sub         rcx,rax
                0x48, 0x8B, 0xC1,                         //mov         rax,rcx  
                0x48, 0x89, 0x05, 0xB9, 0x66, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 10);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 23);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 67: // MUL reg1, reg2 multiplies value of reg1 by value of reg2 and save result in reg1 reg1 = reg1 * reg2
        {
            trace("MUL reg%d *= reg%d\n", dst, src);
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8B, 0x05, 0x97, 0x66, 0x00, 0x00, //mov         rax,qword ptr []  
                0x48, 0x0F, 0xAF, 0x05, 0x97, 0x66, 0x00, 0x00, //imul  rax,qword ptr []  
                0x48, 0x89, 0x05, 0x88, 0x66, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 11);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 18);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 68: // DIV reg1, reg2 divides value of reg1 by value of reg2 and save result in reg1 reg1 = reg1 / reg2
        {
            trace("DIV reg%d /= reg%d\n", dst, src);
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8B, 0x05, 0x81, 0x66, 0x00, 0x00, //mov         rax,qword ptr []  
                0x48, 0x99,							      //cqo  
                0x48, 0xF7, 0x3D, 0x80, 0x66, 0x00, 0x00, //idiv        rax,qword ptr []  
                0x48, 0x89, 0x05, 0x71, 0x66, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 12);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 19);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 69: // MOD reg1, reg2 calculates reminder of division of reg1 by reg2 and save result in reg1 reg1 = reg1 % reg2
        {
            trace("MOD reg%d %%= reg%d\n", dst, src);
            VERIFY_REGISTER_IDX (src);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x8B, 0x05, 0x6A, 0x66, 0x00, 0x00, //mov         rax,qword ptr []  
                0x48, 0x99,					              //cqo  
                0x48, 0xF7, 0x3D, 0x69, 0x66, 0x00, 0x00, //idiv        rax,qword ptr []  
                0x48, 0x8B, 0xC2,						  //mov         rax,rdx  
                0x48, 0x89, 0x05, 0x57, 0x66, 0x00, 0x00, //mov         qword ptr [],rax  
            };
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 3);
            dataMappings[0][REGISTER_SIZE * src].push_back(offset + 12);
            dataMappings[0][REGISTER_SIZE * dst].push_back(offset + 22);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 97: //JZ reg, imm8  if value of reg is zero, does relative jump. if reg1 == 0: IP = IP + imm8
        {
            trace("JZ reg%d, %d\n", dst, src + instructionNumber + 1);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x83, 0x3D, 0xCC, 0x66, 0x00, 0x00, 0x00, //cmp         qword ptr [],0  
                0x75, 0x05,							            //jne
                0xE9, 0x45, 0x01, 0x00, 0x00,                   //jmp         $
            };
            dataMappings[1][REGISTER_SIZE * dst].push_back(offset + 3);
            jumps[instructionNumber + src].push_back(offset + 11);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 98: //JL reg, imm8 if value of reg is less then zero, does relative jump. if reg1 < 0: IP = IP + imm8
        {
            trace("JL reg%d, %d\n", dst, src + instructionNumber + 1);
            VERIFY_REGISTER_IDX (dst);
            const BYTE code[] = {
                0x48, 0x83, 0x3D, 0xCC, 0x66, 0x00, 0x00, 0x00, //cmp         qword ptr [],0  
                0x7D, 0x05,							            //jge  
                0xE9, 0x45, 0x01, 0x00, 0x00,                   //jmp         $
            };
            dataMappings[1][REGISTER_SIZE * dst].push_back(offset + 3);
            jumps[instructionNumber + src].push_back(offset + 11);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 99: //JUMP imm16 unconditional relative jump by imm16. IP = IP + imm16
        {
            auto imm16 = (short)MAKEWORD(dst, src);
            trace("JUMP %d\n", imm16 + instructionNumber + 1);

            const BYTE code[] = {
                0xE9, 0x45, 0x01, 0x00, 0x00,       //jmp         $
            };
            jumps[instructionNumber + imm16].push_back(offset + 1);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 100:	// CALL imm16 stores next instruction pointer on internal stack and jumps by imm16. 
                // save IP of next instruction to call stack JMP imm16
        {
            auto imm16 = (short)MAKEWORD(dst, src);
            trace("CALL %d\n", imm16 + instructionNumber + 1);

            const BYTE code[] = {
                0xE8, 0x12, 0x00, 0x00, 0x00,       //call
            };
            jumps[instructionNumber + imm16].push_back(offset + 1);
            section.insert(section.end(), std::begin(code), std::end(code));
        }
        break;

    case 101:	//RET reads absolute instruction pointer from stack and jumps to it (returns to next instruction after corresponding CALL)
                // restore IP from call stack IP = saved_IP
        {
            trace("RET\n");
            section.push_back(0xC3); //                   ret
        }
        break;

    case 126: // HLT ends program, terminates execution
        {
            trace("HLT\n");
            const BYTE exitCode[] = {
                0x31, 0xC9, 			//xor ecx, ecx
                0xFF, 0x15, 0, 0, 0, 0,	//call []
            };
            imports["kernel32.dll"]["ExitProcess"].push_back(offset + 4);
            section.insert(section.end(), std::begin(exitCode), std::end(exitCode));
        }
        break;

    default:
        cerr << "Invalid instruction code.\n";
        return false;
    }

    return true;
}

#undef VERIFY_REGISTER_IDX

bool InstructionContext::MakeExecutable(LPCTSTR szFile, const void* data, size_t dataSize, size_t dataSpaceSize)
{
    //////////////////////////////////////////////////////////////////////////
    // Finalizing code section

    { // safety net
        const BYTE exitCode[] = {
            0x31, 0xC9, 			//xor ecx, ecx
            0xFF, 0x15, 0, 0, 0, 0,	//call []
        };
        imports["kernel32.dll"]["ExitProcess"].push_back(section.size() + 4);
        section.insert(section.end(), std::begin(exitCode), std::end(exitCode));
    }

    const size_t codeEnd = section.size();

    section.push_back(0xCC);
    Align(section, 4, 0xCC);

    const size_t exceptionHandler = section.size();
    { // exception handler
        const BYTE exitCode[] = {
            0x48, 0x8D, 0x0D, 0x45, 0x57, 0x00, 0x00, //lea         rcx,[]  
            0xFF, 0x15, 0xFF, 0xA4, 0x00, 0x00,       //call        qword ptr []  
            0x31, 0xC9, 			//xor ecx, ecx
            0xFF, 0x15, 0, 0, 0, 0,	//call []
        };
        const size_t offset = section.size();
        imports["msvcrt.dll"]["printf"].push_back(offset + 9);
        imports["kernel32.dll"]["ExitProcess"].push_back(offset + 17);
        strings["Error: exception catched\n"].push_back(offset + 3);
        section.insert(section.end(), std::begin(exitCode), std::end(exitCode));
    }

    section.push_back(0xCC);
    Align(section, 4, 0xCC);

    // strings
    for (auto & string : strings)
    {
        for (auto offset : string.second)
        {
            auto* pos = (uint32_t*) &section[offset];
            *pos = section.size() - sizeof(uint32_t) - offset;
        }
        BYTE* data = (BYTE*) string.first.c_str();
        section.insert(section.end(), data, data + string.first.length() + 1);
    }
    section.push_back(0);
    Align(section, 16, 0);

    // imports
    map<vector<size_t>*, size_t>  importNames;

    vector<IMAGE_IMPORT_DESCRIPTOR> importDescriptors(imports.size());

    auto itDescriptor = importDescriptors.begin();
    for (auto itModule(imports.begin()); itModule != imports.end(); ++itModule, ++itDescriptor)
    {
        for (auto & it : itModule->second)
        {
            importNames[&it.second] = SECTIONALIGN + section.size();

            section.push_back(0);
            section.push_back(0);
            BYTE* data = (BYTE*) it.first.c_str();
            section.insert(section.end(), data, data + it.first.length() + 1);
        }
    }
    Align(section, 16, 0);

    itDescriptor = importDescriptors.begin();
    for (auto itModule(imports.begin()); itModule != imports.end(); ++itModule, ++itDescriptor)
    {
        itDescriptor->OriginalFirstThunk = SECTIONALIGN + section.size();

        for (auto & it : itModule->second)
        {
            uint64_t th = importNames[&it.second];
            section.insert(section.end(), (BYTE*)&th, (BYTE*)(&th + 1));
        }

        section.insert(section.end(), sizeof(uint64_t), 0);
    }
    Align(section, 16, 0);

    itDescriptor = importDescriptors.begin();
    for (auto itModule(imports.begin()); itModule != imports.end(); ++itModule, ++itDescriptor)
    {
        itDescriptor->FirstThunk = SECTIONALIGN + section.size();

        for (auto & it : itModule->second)
        {

            for (auto offset : it.second)
            {
                auto* pos = (uint32_t*) &section[offset];
                *pos = section.size() - sizeof(uint32_t) - offset;
            }

            uint32_t th = importNames[&it.second];
            section.insert(section.end(), (BYTE*)&th, (BYTE*)(&th + 1));

            section.insert(section.end(), 4, 0);
        }
    }
    Align(section, 16, 0);

    itDescriptor = importDescriptors.begin();
    for (auto itModule(imports.begin()); itModule != imports.end(); ++itModule, ++itDescriptor)
    {
        itDescriptor->Name = SECTIONALIGN + section.size();
        BYTE* data = (BYTE*) itModule->first.c_str();
        section.insert(section.end(), data, data + itModule->first.length() + 1);
    }
    Align(section, 16, 0);

    // Exceptions
    UNWIND_INFO_ unwindInfo = {};
    unwindInfo.Ver3_Flags = 1 + (UNW_FLAG_EHANDLER << 3);
    const size_t unwindData = section.size();
    section.insert(section.end(), (BYTE*)&unwindInfo, (BYTE*)(&unwindInfo + 1));
    Align(section, 4, 0);
    uint64_t th = SECTIONALIGN + exceptionHandler;
    section.insert(section.end(), (BYTE*)&th, (BYTE*)(&th + 1));
    section.insert(section.end(), sizeof(uint64_t), 0);

    Align(section, 16, 0);

    RUNTIME_FUNCTION_ runtimeFunction = {};
    runtimeFunction.FunctionStart = SECTIONALIGN; // AddressOfEntryPoint
    runtimeFunction.FunctionEnd = SECTIONALIGN + codeEnd;
    runtimeFunction.UnwindInfo = SECTIONALIGN + unwindData;
    const size_t exceptionRuntimeFunction = section.size();
    section.insert(section.end(), (BYTE*)&runtimeFunction, (BYTE*)(&runtimeFunction + 1));

    Align(section, 16, 0);

    // Done with code section

    const size_t codeSectionSize = section.size() + importDescriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const size_t codeSectionVirtualSize = Align(codeSectionSize, SECTIONALIGN);

    // Data
    //dataMappings
    for (auto & dataMapping : dataMappings)
    {
        for (auto it(dataMapping.second.begin()), itEnd(dataMapping.second.end()); it != itEnd; ++it)
        {
            const size_t dataOffset = codeSectionVirtualSize + it->first;
            for (auto offset : it->second)
            {
                auto* pos = (uint32_t*) &section[offset];
                *pos = dataOffset - sizeof(uint32_t) - offset - dataMapping.first;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////
    // Preparing executable header structures

    Headers64 headers64 = {};

    headers64.dosHeader.e_magic = 'ZM';
    headers64.dosHeader.e_lfanew = offsetof(Headers64, ntHeaders);

    headers64.ntHeaders.Signature = 'EP';

    auto& fileHeader = headers64.ntHeaders.FileHeader;
    fileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    fileHeader.NumberOfSections = NUMBEROFSECTIONS;
    fileHeader.SizeOfOptionalHeader = sizeof(headers64.ntHeaders.OptionalHeader);
    fileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;

    auto& optionalHeader = headers64.ntHeaders.OptionalHeader;
    optionalHeader.Magic                 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    //optionalHeader.AddressOfEntryPoint   = EntryPoint - IMAGEBASE;

    optionalHeader.ImageBase             = IMAGEBASE;
    optionalHeader.SectionAlignment      = SECTIONALIGN;
    optionalHeader.FileAlignment         = FILEALIGN;
    optionalHeader.MajorSubsystemVersion = 4;
    optionalHeader.SizeOfImage           = 2 * SECTIONALIGN;
    optionalHeader.SizeOfHeaders         = sizeof(Headers64);
    optionalHeader.Subsystem             = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    optionalHeader.NumberOfRvaAndSizes   = 16;

    headers64.sectionHeaders[0].Misc.VirtualSize = SECTIONALIGN;
    headers64.sectionHeaders[0].VirtualAddress   = SECTIONALIGN;
    headers64.sectionHeaders[0].SizeOfRawData    = FILEALIGN;
    headers64.sectionHeaders[0].PointerToRawData = FILEALIGN;

    headers64.sectionHeaders[0].Characteristics  = IMAGE_SCN_MEM_EXECUTE;// | IMAGE_SCN_MEM_WRITE;

    headers64.sectionHeaders[1].Misc.VirtualSize = SECTIONALIGN;
    headers64.sectionHeaders[1].VirtualAddress   = SECTIONALIGN;
    headers64.sectionHeaders[1].SizeOfRawData    = FILEALIGN;
    headers64.sectionHeaders[1].PointerToRawData = FILEALIGN;

    headers64.sectionHeaders[1].Characteristics  = IMAGE_SCN_MEM_WRITE;

    optionalHeader.AddressOfEntryPoint   = SECTIONALIGN;// + section.size();

    optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
        = section.size() + SECTIONALIGN;

    optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress 
        = exceptionRuntimeFunction + SECTIONALIGN;
    optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = sizeof(RUNTIME_FUNCTION_);

    // Fixing sizes

    headers64.sectionHeaders[0].Misc.VirtualSize = codeSectionVirtualSize; //
    headers64.sectionHeaders[0].SizeOfRawData    = Align(codeSectionSize, FILEALIGN);

    headers64.sectionHeaders[1].VirtualAddress 
        = headers64.sectionHeaders[0].VirtualAddress + headers64.sectionHeaders[0].Misc.VirtualSize;
    headers64.sectionHeaders[1].PointerToRawData 
        = headers64.sectionHeaders[0].PointerToRawData + headers64.sectionHeaders[0].SizeOfRawData;

    assert(dataSize <= dataSpaceSize);
    headers64.sectionHeaders[1].Misc.VirtualSize = Align(REGISTER_TABLE_SIZE + dataSpaceSize, SECTIONALIGN); //
    headers64.sectionHeaders[1].SizeOfRawData    = (dataSize > 0) ? Align(REGISTER_TABLE_SIZE + dataSize, FILEALIGN) : 0;

    optionalHeader.SizeOfImage
        = SECTIONALIGN + headers64.sectionHeaders[0].Misc.VirtualSize + headers64.sectionHeaders[1].Misc.VirtualSize;

    //////////////////////////////////////////////////////////////////////////
    // Writing exe image

    HANDLE handle = CreateFile(
        szFile,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        cerr << "Cannot create exe file.\n";
        return false;
    }

    LARGE_INTEGER size;
    size.QuadPart 
        = FILEALIGN + headers64.sectionHeaders[0].SizeOfRawData 
        + headers64.sectionHeaders[1].SizeOfRawData;
    SetFilePointerEx(handle, size, nullptr, FILE_BEGIN);
    SetEndOfFile(handle);
    SetFilePointer(handle, 0, nullptr, FILE_BEGIN);

    DWORD numberOfBytesWritten = 0;
    WriteFile(handle, &headers64, sizeof(headers64), &numberOfBytesWritten, nullptr);

    SetFilePointer(handle, FILEALIGN, nullptr, FILE_BEGIN);
    WriteFile(handle, section.data(), section.size(), &numberOfBytesWritten, nullptr); 
    WriteFile(
            handle, 
            importDescriptors.data(), 
            importDescriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR), 
            &numberOfBytesWritten, 
            nullptr); 

    // handle data
    if (dataSize > 0)
    {
        SetFilePointer(handle, FILEALIGN + headers64.sectionHeaders[0].SizeOfRawData + REGISTER_TABLE_SIZE, nullptr, FILE_BEGIN);
        WriteFile(handle, data, dataSize, &numberOfBytesWritten, nullptr);
    }

    CloseHandle(handle);

    return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc != 3 && argc != 2)
    {
        cerr << "Usage: translator input_file output_file\n";
        return 1;
    }

    InstructionContext context;
    return !context.TranslateEvmFile(argv[1], (argc == 3)? argv[2] : _T("goal.exe"));
}
