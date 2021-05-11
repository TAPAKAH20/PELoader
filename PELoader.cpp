// PELoader.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <Windows.h>

typedef struct _REALOCATIONS {
    WORD offset : 12;
    WORD type : 4;
} REALOCATIONS, *PREALOCATIONS;

#define RVA_TO_VA(ptype, base, offset) (ptype)(((DWORD_PTR)(base)) + (offset))

int main(int argc, char** argv)
{
    const char* path = "C:\\Users\\R0ACH\\Downloads\\simple.exe";

    if (argc == 2) {
        path = argv[1];
    }

    printf("Executable:\n%s\n", path);

    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    DWORD size = GetFileSize(file, NULL);

    HANDLE mapping = CreateFileMappingA(file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);

    LPVOID pImageBase = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pImageNtHeader = RVA_TO_VA(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);



    LPVOID peImage = VirtualAlloc(NULL, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    MoveMemory(peImage, pImageBase, pImageNtHeader->OptionalHeader.SizeOfHeaders);


    // Sections

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeader);
    DWORD nSections = pImageNtHeader->FileHeader.NumberOfSections;


    printf("\nSections:\n");
    for (DWORD i = 0; i < nSections; i++, pSection++) {
        LPVOID pDst = RVA_TO_VA(LPVOID, peImage, pSection->VirtualAddress);
        LPVOID pSrc = RVA_TO_VA(LPVOID, pImageBase, pSection->VirtualAddress);
        DWORD dwSize = pSection->SizeOfRawData;

        if (dwSize > 0) {
            MoveMemory(pDst, pSrc, dwSize);
        }

        printf("\t%s\n", pSection->Name);
    }




    //Import table

    printf("\nImports:\n");
    DWORD rvaImport = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD sizeImports = pImageNtHeader->OptionalHeader.DataDirectory[1].Size;

    PIMAGE_IMPORT_DESCRIPTOR imageImportDesc = RVA_TO_VA(PIMAGE_IMPORT_DESCRIPTOR, peImage, rvaImport);

    for (PIMAGE_IMPORT_DESCRIPTOR cDesc = imageImportDesc; cDesc->Characteristics != NULL; cDesc++) {
        PTCHAR dllName = RVA_TO_VA(PTCHAR, peImage, cDesc->Name);

        HMODULE dllModule = LoadLibrary(dllName);

        printf("\t%s\n", dllName);

        //functions in dll
        PIMAGE_THUNK_DATA pFirstThunk = RVA_TO_VA(PIMAGE_THUNK_DATA, peImage, cDesc->FirstThunk);
        for (PIMAGE_THUNK_DATA pThunk = pFirstThunk; *(DWORD*)pThunk != NULL; pThunk++) {
            PIMAGE_IMPORT_BY_NAME pImportByName = RVA_TO_VA(PIMAGE_IMPORT_BY_NAME, peImage, pThunk->u1.AddressOfData);

            printf("\t\t%s\n", pImportByName->Name);
            
            DWORD funcAddr = (DWORD)GetProcAddress(dllModule, pImportByName->Name);
            pThunk->u1.AddressOfData = funcAddr;
        }

    }


    //Realocation table

    DWORD imageRelocBaseVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    PIMAGE_BASE_RELOCATION pImageBaseReloc = RVA_TO_VA(PIMAGE_BASE_RELOCATION, peImage, imageRelocBaseVA);
    while(pImageBaseReloc->VirtualAddress != NULL) {
        DWORD relocCount = (pImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PREALOCATIONS pRelocs = RVA_TO_VA(PREALOCATIONS, pImageBaseReloc, sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD j = 0; j < relocCount; j++) {
            if (pRelocs[j].type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* addr = RVA_TO_VA(DWORD*, peImage, pImageBaseReloc->VirtualAddress + pRelocs[j].offset);
                DWORD oldAddr = *addr;
                DWORD newAddr = oldAddr - pImageNtHeader->OptionalHeader.ImageBase + (DWORD)peImage;
                *addr = newAddr;
            }
        }

        pImageBaseReloc = RVA_TO_VA(PIMAGE_BASE_RELOCATION, pImageBaseReloc, pImageBaseReloc->SizeOfBlock);
    }



    //Export table

    //printf("\nExports:\n");
    //DWORD rvaExport = pImageNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
    //DWORD sizeExports = pImageNtHeader->OptionalHeader.DataDirectory[0].Size;

    //PIMAGE_IMPORT_DESCRIPTOR imageExport = RVA_TO_VA(PIMAGE_IMPORT_DESCRIPTOR, pImageDosHeader, rvaExport);

    //PCHAR exportName = RVA_TO_VA(PCHAR, pImageDosHeader, imageExport[0].Name);
    //for (DWORD i = 1; sizeExports > 0 && imageExport[i].Name != NULL; i++) {

    //    printf("%s\n", exportName);
    //    exportName = RVA_TO_VA(PCHAR, pImageDosHeader, imageExport[i].Name);
    //}




    //jmp to entry
    DWORD peEntry = RVA_TO_VA(DWORD, peImage, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

    _asm {
        mov eax, [peEntry]
        jmp eax
    }


    //did not jumped correctly
    return 1;

}


