GIT: https://github.com/TAPAKAH20/PELoader


>debug.exe C:\path\to\exec.exe

Выводит в консоль секции и список импортированных функций. Убрал +2 когда получали имя функций из pThunk->u1.Function

решилось так

PIMAGE_IMPORT_BY_NAME pImportByName = RVA_TO_VA(PIMAGE_IMPORT_BY_NAME, peImage, pThunk->u1.AddressOfData);
printf("\t\t%s\n", pImportByName->Name);





пример вывода для simple.exe:



Executable:
C:\Users\R0ACH\Downloads\simple.exe

Sections:
        .text
        .idata
        .reloc

Imports:
        KERNEL32.DLL
                ExitProcess
                GetCommandLineA
        USER32.DLL
                MessageBoxA