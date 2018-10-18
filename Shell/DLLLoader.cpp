#include <windows.h>
#include "DLLLoader.h"

//系统结构体声明

typedef struct _PEB { // Size: 0x1D8  
	/*000*/ UCHAR InheritedAddressSpace;  
	/*001*/ UCHAR ReadImageFileExecOptions;  
	/*002*/ UCHAR BeingDebugged;  
	/*003*/ UCHAR SpareBool; // Allocation size  
	/*004*/ HANDLE Mutant;  
	/*008*/ DWORD ImageBaseAddress; // Instance  
	/*00C*/ DWORD DllList;  
	/*010*/ DWORD ProcessParameters;  
	/*014*/ ULONG SubSystemData;  
	/*018*/ HANDLE DefaultHeap;  
	/*01C*/ KSPIN_LOCK FastPebLock;  
	/*020*/ ULONG FastPebLockRoutine;  
	/*024*/ ULONG FastPebUnlockRoutine;  
	/*028*/ ULONG EnvironmentUpdateCount;  
	/*02C*/ ULONG KernelCallbackTable;  
	/*030*/ LARGE_INTEGER SystemReserved;  
	/*038*/ ULONG FreeList;  
	/*03C*/ ULONG TlsExpansionCounter;  
	/*040*/ ULONG TlsBitmap;  
	/*044*/ LARGE_INTEGER TlsBitmapBits;  
	/*04C*/ ULONG ReadOnlySharedMemoryBase;  
	/*050*/ ULONG ReadOnlySharedMemoryHeap;  
	/*054*/ ULONG ReadOnlyStaticServerData;  
	/*058*/ ULONG AnsiCodePageData;  
	/*05C*/ ULONG OemCodePageData;  
	/*060*/ ULONG UnicodeCaseTableData;  
	/*064*/ ULONG NumberOfProcessors;  
	/*068*/ LARGE_INTEGER NtGlobalFlag; // Address of a local copy  
	/*070*/ LARGE_INTEGER CriticalSectionTimeout;  
	/*078*/ ULONG HeapSegmentReserve;  
	/*07C*/ ULONG HeapSegmentCommit;  
	/*080*/ ULONG HeapDeCommitTotalFreeThreshold;  
	/*084*/ ULONG HeapDeCommitFreeBlockThreshold;  
	/*088*/ ULONG NumberOfHeaps;  
	/*08C*/ ULONG MaximumNumberOfHeaps;  
	/*090*/ ULONG ProcessHeaps;  
	/*094*/ ULONG GdiSharedHandleTable;  
	/*098*/ ULONG ProcessStarterHelper;  
	/*09C*/ ULONG GdiDCAttributeList;  
	/*0A0*/ KSPIN_LOCK LoaderLock;  
	/*0A4*/ ULONG OSMajorVersion;  
	/*0A8*/ ULONG OSMinorVersion;  
	/*0AC*/ USHORT OSBuildNumber;  
	/*0AE*/ USHORT OSCSDVersion;  
	/*0B0*/ ULONG OSPlatformId;  
	/*0B4*/ ULONG ImageSubsystem;  
	/*0B8*/ ULONG ImageSubsystemMajorVersion;  
	/*0BC*/ ULONG ImageSubsystemMinorVersion;  
	/*0C0*/ ULONG ImageProcessAffinityMask;  
	/*0C4*/ ULONG GdiHandleBuffer[0x22];  
	/*14C*/ ULONG PostProcessInitRoutine;  
	/*150*/ ULONG TlsExpansionBitmap;  
	/*154*/ UCHAR TlsExpansionBitmapBits[0x80];  
	/*1D4*/ ULONG SessionId;  
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA  
{  
	ULONG Length; // +0x00  
	BOOLEAN Initialized; // +0x04  
	PVOID SsHandle; // +0x08  
	LIST_ENTRY InLoadOrderModuleList; // +0x0c  
	LIST_ENTRY InMemoryOrderModuleList; // +0x14  
	LIST_ENTRY InInitializationOrderModuleList;// +0x1c  
} PEB_LDR_DATA,*PPEB_LDR_DATA; // +0x24

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING,*PUNICODE_STRING;

/*+0x000 InLoadOrderLinks : _LIST_ENTRY
+0x008 InMemoryOrderLinks : _LIST_ENTRY
+0x010 InInitializationOrderLinks : _LIST_ENTRY
+0x018 DllBase          : Ptr32 Void
+0x01c EntryPoint       : Ptr32 Void
+0x020 SizeOfImage      : Uint4B
+0x024 FullDllName      : _UNICODE_STRING
+0x02c BaseDllName      : _UNICODE_STRING
+0x034 Flags            : Uint4B
+0x038 LoadCount        : Uint2B
+0x03a TlsIndex         : Uint2B
+0x03c HashLinks        : _LIST_ENTRY
+0x03c SectionPointer   : Ptr32 Void
+0x040 CheckSum         : Uint4B
+0x044 TimeDateStamp    : Uint4B
+0x044 LoadedImports    : Ptr32 Void
+0x048 EntryPointActivationContext : Ptr32 Void
+0x04c PatchInformation : Ptr32 Void*/
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	DWORD  DllBase;
	DWORD EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;

	union{
		LIST_ENTRY HashLinks;
		DWORD SectionPointer;
	};

	DWORD CheckSum;

	union{
		DWORD TimeDateStamp;
		DWORD LoadedImports;
	};

	DWORD EntryPointActivationContext;
	DWORD PatchInformation; 
	
} LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;

typedef BOOL (WINAPI *FuncDLLMain)(HINSTANCE,DWORD,LPVOID);//DLLMain函数声明

char* FileBuf;//DLL文件缓冲区
DWORD FileBufSize;//DLL文件缓冲区大小
char* MemBuf;//DLL内存缓冲区
DWORD MemBufSize;//DLL内存缓冲区大小

//PE文件结构体指针变量声明
IMAGE_DOS_HEADER *File_DOS_Header,*Mem_DOS_Header;//DOS头
IMAGE_NT_HEADERS *File_NT_Headers,*Mem_NT_Headers;//NT头
IMAGE_SECTION_HEADER *File_Section_Header,*Mem_Section_Header;//节头
IMAGE_IMPORT_DESCRIPTOR *Mem_Import_Descriptor;//导入描述符
IMAGE_BASE_RELOCATION *Mem_Base_Relocation;//重定向表

DWORD Mem_Import_Descriptorn;//重定向表项数

FuncDLLMain pDLLMain = NULL;//DLLMain函数指针

LDR_DATA_TABLE_ENTRY *Mem_LDR_Data_Table_Entry;//PEB中LDR所指的结构体指针变量

LPWSTR Mem_DLLBaseName = NULL;//DLL基本名（Unicode）
LPWSTR Mem_DLLFullName = NULL;//DLL全名（Unicode）

void LoadPEHeader()//加载PE头
{
	File_DOS_Header = (PIMAGE_DOS_HEADER)FileBuf;//获取DOS头地址
	File_NT_Headers = (PIMAGE_NT_HEADERS)((DWORD)FileBuf + File_DOS_Header -> e_lfanew);//获取NT头地址
	MemBufSize = File_NT_Headers -> OptionalHeader.SizeOfImage;//获取DLL内存映像大小
	MemBuf = (char *)VirtualAlloc(NULL,MemBufSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);//分配DLL内存
	Mem_DOS_Header = (PIMAGE_DOS_HEADER)MemBuf;//获取DLL内存中DOS头地址
	CopyMemory(Mem_DOS_Header,File_DOS_Header,File_NT_Headers -> OptionalHeader.SizeOfHeaders);//将PE头加载进内存
	Mem_NT_Headers = (PIMAGE_NT_HEADERS)((DWORD)MemBuf + Mem_DOS_Header -> e_lfanew);//获取DLL内存中NT头地址
	File_Section_Header =  (PIMAGE_SECTION_HEADER)((DWORD)File_NT_Headers + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER32) + File_NT_Headers -> FileHeader.SizeOfOptionalHeader);//获取节头基址
	Mem_Section_Header = (PIMAGE_SECTION_HEADER)((DWORD)Mem_NT_Headers + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER32) + Mem_NT_Headers -> FileHeader.SizeOfOptionalHeader);//获取DLL内存中节头基址
}

void LoadSectionData()//加载节数据
{
	int i;

	for(i = 0;i < Mem_NT_Headers -> FileHeader.NumberOfSections;i++)//将文件中长度不为0的节中的数据拷贝到DLL内存中
	{
		if(Mem_Section_Header[i].SizeOfRawData > 0)
		{
			CopyMemory((LPVOID)((DWORD)MemBuf + Mem_Section_Header[i].VirtualAddress), (LPVOID)((DWORD)FileBuf + ((File_Section_Header[i].PointerToRawData % File_NT_Headers -> OptionalHeader.FileAlignment == 0) ? File_Section_Header[i].PointerToRawData : 0)), File_Section_Header[i].SizeOfRawData);
		}
	}
}

void RepairIAT()//修复导入表
{
	int i;
	PIMAGE_THUNK_DATA32 INT;//INT基址
	LPDWORD IAT;//IAT基址
	HMODULE hMod;//DLL句柄
	LPCSTR LibraryName;//库名称
	PIMAGE_IMPORT_BY_NAME IIN;//函数名称结构体
	LPVOID FuncAddress;//函数地址

	Mem_Import_Descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)MemBuf + Mem_NT_Headers -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);//获取DLL内存中导入描述符基址
	Mem_Import_Descriptorn = Mem_NT_Headers -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);//获取导入描述符数量

	for(i = 0;i < Mem_Import_Descriptorn;i++)//遍历导入描述符
	{
		INT = (PIMAGE_THUNK_DATA32)((DWORD)MemBuf + Mem_Import_Descriptor[i].OriginalFirstThunk);//获取DLL内存中INT地址
		IAT = (LPDWORD)((DWORD)MemBuf + Mem_Import_Descriptor[i].FirstThunk);//获取DLL内存中IAT地址

		if(Mem_Import_Descriptor[i].OriginalFirstThunk == NULL)//若INT地址为NULL，则认为INT的地址和IAT的地址相等
		{
			INT = (PIMAGE_THUNK_DATA32)IAT;
		}

		if(Mem_Import_Descriptor[i].FirstThunk != NULL)//若IAT的地址不为NULL，即有效描述符
		{
			LibraryName = (LPCSTR)((DWORD)MemBuf + Mem_Import_Descriptor[i].Name);//获取库文件名
			hMod = GetModuleHandle(LibraryName);//获取库句柄

			if(hMod == NULL)//若库未被加载，则加载库
			{
				hMod = LoadLibrary(LibraryName);
			}

			while(INT -> u1.AddressOfData != NULL)//遍历INT，直到遇到NULL项
			{
				if((INT -> u1.AddressOfData & 0x80000000) == NULL)//需要使用名称获取函数地址
				{
					IIN = (PIMAGE_IMPORT_BY_NAME)((DWORD)MemBuf + INT -> u1.AddressOfData);//获取函数名称结构体
					FuncAddress = GetProcAddress(hMod, (LPCSTR)IIN->Name);
				}
				else//需要使用序号获取函数地址
				{
					FuncAddress = GetProcAddress(hMod,(LPCSTR)(INT -> u1.Ordinal & 0x000000FF));
				}

				*IAT = (DWORD)FuncAddress;//将更正后的函数地址写入IAT

				//让INT和IAT指向下一项
				INT = (PIMAGE_THUNK_DATA32)((DWORD)INT + sizeof(IMAGE_THUNK_DATA32));
				IAT = (LPDWORD)((DWORD)IAT + sizeof(DWORD));
			}
		}
	}
}

void RepairOperateAddress()//修复重定向地址
{
	int i;
	int RelocDatan;//重定向表项数
	WORD Offset;//重定向偏移
	BYTE Type;//重定向类型
	DWORD AddValue;//当前ImageBase与原ImageBase差值
	DWORD BaseAddress;//重定向块的基址
	LPDWORD pDest;//指向需要重定向地址的地方
	LPWORD pRelocData;//当前重定向块重定向表项基址
	
	Mem_Base_Relocation = (PIMAGE_BASE_RELOCATION)((DWORD)MemBuf + Mem_NT_Headers -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	while((DWORD)Mem_Base_Relocation < ((DWORD)MemBuf + Mem_NT_Headers -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + Mem_NT_Headers -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
	{
		pRelocData = (LPWORD)((DWORD)Mem_Base_Relocation + sizeof(IMAGE_BASE_RELOCATION));//获取当前重定向块重定向表项基址
		RelocDatan = (Mem_Base_Relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);//获取重定向表项数
		AddValue = (DWORD)MemBuf - Mem_NT_Headers -> OptionalHeader.ImageBase;//获取当前ImageBase与原ImageBase差值
		BaseAddress = (DWORD)MemBuf + Mem_Base_Relocation -> VirtualAddress;//获取重定向块的基址
		
		for (i = 0; i < RelocDatan; i++)//遍历重定向表项
		{
			Offset = pRelocData[i] & 0x0FFF;//获取重定向偏移
			Type = (BYTE)(pRelocData[i] >> 12);//获取重定向类型
			pDest = (DWORD *)(BaseAddress + Offset);//获取需要重定向地址的地方

			//地址重定向
			switch (Type)
			{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				case IMAGE_REL_BASED_HIGH:		
					*pDest = (((AddValue & 0xFFFF0000) + ((*pDest) & 0xFFFF0000)) & 0xFFFF0000) | ((*pDest) & 0x0000FFFF);
					break;

				case IMAGE_REL_BASED_LOW:
					*pDest += (((AddValue & 0x0000FFFF) + ((*pDest) & 0x0000FFFF)) & 0x0000FFFF) | ((*pDest) & 0xFFFF0000);
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*pDest += AddValue;
					break;

				case IMAGE_REL_BASED_HIGHADJ:
					*pDest = (((AddValue & 0xFFFF0000) + ((*pDest) & 0xFFFF0000)) & 0xFFFF0000) | ((*pDest) & 0x0000FFFF);
					break;

				default:
					break;
			}
		}

		Mem_Base_Relocation = (PIMAGE_BASE_RELOCATION)((DWORD)Mem_Base_Relocation + Mem_Base_Relocation -> SizeOfBlock);//指向下一个重定向块
	}
}

void AddDLLToPEB()//将DLL信息加入PEB的LDR中
{
	PPEB PEB;//PEB地址
	PPEB_LDR_DATA LDR;//LDR地址
	PLDR_DATA_TABLE_ENTRY EndModule;//结束模块地址
	LPDWORD PEBAddress = (LPDWORD)((DWORD)NtCurrentTeb() + 0x00000030);//计算PEB地址
	
	PEB = (PPEB)(*PEBAddress);//获取PEB地址
	LDR = (PPEB_LDR_DATA)PEB -> DllList;//获取LDR地址

	//遍历LDR.InLoadOrderModuleList以获得结束模块地址
	EndModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(EndModule -> DllBase != NULL)
	{
		EndModule = (PLDR_DATA_TABLE_ENTRY) EndModule -> InLoadOrderLinks.Flink;
	}

	Mem_LDR_Data_Table_Entry = (PLDR_DATA_TABLE_ENTRY)VirtualAlloc(NULL,sizeof(LDR_DATA_TABLE_ENTRY),MEM_COMMIT,PAGE_READWRITE);//分配LDR数据表内存

	//将DLL挂入InLoadOrderModuleList
	EndModule -> InLoadOrderLinks.Blink -> Flink = &Mem_LDR_Data_Table_Entry -> InLoadOrderLinks;
	Mem_LDR_Data_Table_Entry -> InLoadOrderLinks.Flink = &EndModule -> InLoadOrderLinks;
	Mem_LDR_Data_Table_Entry -> InLoadOrderLinks.Blink = EndModule -> InLoadOrderLinks.Blink;
	EndModule -> InLoadOrderLinks.Blink = &Mem_LDR_Data_Table_Entry -> InLoadOrderLinks;
	LDR -> InLoadOrderModuleList.Blink = &Mem_LDR_Data_Table_Entry -> InLoadOrderLinks;

	//将DLL挂入InMemoryOrderModuleList
	EndModule -> InMemoryOrderLinks.Blink -> Flink = &Mem_LDR_Data_Table_Entry -> InMemoryOrderLinks;
	Mem_LDR_Data_Table_Entry -> InMemoryOrderLinks.Flink = &EndModule -> InMemoryOrderLinks;
	Mem_LDR_Data_Table_Entry -> InMemoryOrderLinks.Blink = EndModule -> InMemoryOrderLinks.Blink;
	EndModule -> InMemoryOrderLinks.Blink = &Mem_LDR_Data_Table_Entry -> InMemoryOrderLinks;
	LDR -> InMemoryOrderModuleList.Blink = &Mem_LDR_Data_Table_Entry -> InMemoryOrderLinks;

	//将DLL挂入InInitializationOrderModuleList
	EndModule -> InInitializationOrderLinks.Blink -> Flink = &Mem_LDR_Data_Table_Entry -> InInitializationOrderLinks;
	Mem_LDR_Data_Table_Entry -> InInitializationOrderLinks.Flink = &EndModule -> InInitializationOrderLinks;
	Mem_LDR_Data_Table_Entry -> InInitializationOrderLinks.Blink = EndModule -> InInitializationOrderLinks.Blink;
	EndModule -> InInitializationOrderLinks.Blink = &Mem_LDR_Data_Table_Entry -> InInitializationOrderLinks;
	LDR -> InInitializationOrderModuleList.Blink = &Mem_LDR_Data_Table_Entry -> InInitializationOrderLinks;

	Mem_LDR_Data_Table_Entry -> DllBase = (DWORD)MemBuf;//写入DLL内存基址
	Mem_LDR_Data_Table_Entry -> EntryPoint = (DWORD)(Mem_NT_Headers -> OptionalHeader.AddressOfEntryPoint + (DWORD)MemBuf);//写入DLL入口点地址
	Mem_LDR_Data_Table_Entry -> SizeOfImage = MemBufSize;//写入DLL模块大小

	//写入DLL基本名
	Mem_LDR_Data_Table_Entry -> BaseDllName.Buffer = (PWSTR)VirtualAlloc(NULL,wcslen(Mem_DLLBaseName) * sizeof(WCHAR) + 2,MEM_COMMIT,PAGE_READWRITE);
	Mem_LDR_Data_Table_Entry -> BaseDllName.Length = wcslen(Mem_DLLBaseName) * sizeof(WCHAR);
	Mem_LDR_Data_Table_Entry -> BaseDllName.MaximumLength = Mem_LDR_Data_Table_Entry -> BaseDllName.Length;
	CopyMemory((LPVOID)Mem_LDR_Data_Table_Entry -> BaseDllName.Buffer,(LPVOID)Mem_DLLBaseName,Mem_LDR_Data_Table_Entry -> BaseDllName.Length + 2);

	//写入DLL全名
	Mem_LDR_Data_Table_Entry -> FullDllName.Buffer = (PWSTR)VirtualAlloc(NULL,wcslen(Mem_DLLFullName) * sizeof(WCHAR) + 2,MEM_COMMIT,PAGE_READWRITE);
	Mem_LDR_Data_Table_Entry -> FullDllName.Length = wcslen(Mem_DLLFullName) * sizeof(WCHAR);
	Mem_LDR_Data_Table_Entry -> FullDllName.MaximumLength = Mem_LDR_Data_Table_Entry -> FullDllName.Length;
	CopyMemory((LPVOID)Mem_LDR_Data_Table_Entry -> FullDllName.Buffer,(LPVOID)Mem_DLLFullName,Mem_LDR_Data_Table_Entry -> FullDllName.Length + 2);
	
	Mem_LDR_Data_Table_Entry -> LoadCount = 1;//将DLL加载次数置1
}

void DLLInit()//DLL初始化
{
	pDLLMain = (FuncDLLMain)(Mem_NT_Headers -> OptionalHeader.AddressOfEntryPoint + (DWORD)MemBuf);//DLL入口点即获取DLLMain函数地址
	pDLLMain((HINSTANCE)MemBuf,DLL_PROCESS_ATTACH,NULL);//执行DLLMain
}

char* DLLMemLoad(char* DLLFileBuf,DWORD DLLFileSize,char* MemDLLBaseName,char* MemDLLFullName)//DLL内存加载函数，注意为了保证一些DLL模块的正常运行，请保证MemDLLBaseName参数和MemDLLFullName参数的结尾是“.dll”（不区分大小写）
{
	//初始化相关变量
	FileBuf = DLLFileBuf;
	FileBufSize = DLLFileSize;
	Mem_DLLBaseName = (LPWSTR)VirtualAlloc(NULL,strlen(MemDLLBaseName) * sizeof(WCHAR) + 2,MEM_COMMIT,PAGE_READWRITE);
	Mem_DLLFullName = (LPWSTR)VirtualAlloc(NULL,strlen(MemDLLFullName) * sizeof(WCHAR) + 2,MEM_COMMIT,PAGE_READWRITE);
	MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED,MemDLLBaseName,-1,Mem_DLLBaseName,strlen(MemDLLBaseName) * sizeof(WCHAR) + 2);
	MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED,MemDLLFullName,-1,Mem_DLLFullName,strlen(MemDLLFullName) * sizeof(WCHAR) + 2);

	//开始执行相关过程
	LoadPEHeader();
	LoadSectionData();
	RepairIAT();
	RepairOperateAddress();
	AddDLLToPEB();
	DLLInit();

	return MemBuf;//返回DLL内存基址即DLL句柄
}

void DLLMemFree(char* DLLMemBaseAddress)//DLL内存释放函数，请在程序结束之前调用它释放加载的DLL，否则程序可能会异常退出
{
	PPEB PEB;//PEB地址
	PPEB_LDR_DATA LDR;//LDR地址
	PLDR_DATA_TABLE_ENTRY CurModule;//当前模块地址
	PLDR_DATA_TABLE_ENTRY EndModule;//结束模块地址
	LPDWORD PEBAddress = (LPDWORD)((DWORD)NtCurrentTeb() + 0x00000030);//计算PEB地址

	MemBuf = DLLMemBaseAddress;//初始化MemBuf指针变量

	PEB = (PPEB)(*PEBAddress);//获取PEB地址
	LDR = (PPEB_LDR_DATA)PEB -> DllList;//获取LDR地址

	//遍历LDR.InLoadOrderModuleList以获得DLL模块地址
	CurModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(CurModule -> DllBase != NULL)
	{
		if(CurModule -> DllBase == (DWORD)DLLMemBaseAddress)
		{
			break;
		}

		CurModule = (PLDR_DATA_TABLE_ENTRY) CurModule -> InLoadOrderLinks.Flink;
	}

	if(CurModule -> DllBase == NULL)//该DLL模块未找到
	{
		return;
	}

	//遍历LDR.InLoadOrderModuleList以获得结束模块地址
	EndModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(EndModule -> DllBase != NULL)
	{
		EndModule = (PLDR_DATA_TABLE_ENTRY) EndModule -> InLoadOrderLinks.Flink;
	}

	//将DLL从InLoadOrderModuleList中卸载
	CurModule -> InLoadOrderLinks.Flink -> Blink = CurModule -> InLoadOrderLinks.Blink;
	CurModule -> InLoadOrderLinks.Blink -> Flink = CurModule -> InLoadOrderLinks.Flink;

	//将DLL从InMemoryOrderModuleList中卸载
	CurModule -> InMemoryOrderLinks.Flink -> Blink = CurModule -> InMemoryOrderLinks.Blink;
	CurModule -> InMemoryOrderLinks.Blink -> Flink = CurModule -> InMemoryOrderLinks.Flink;

	//将DLL从InInitializationOrderModuleList中卸载
	CurModule -> InInitializationOrderLinks.Flink -> Blink = CurModule -> InInitializationOrderLinks.Blink;
	CurModule -> InInitializationOrderLinks.Blink -> Flink = CurModule -> InInitializationOrderLinks.Flink;

	//修复LDR三个链表的Blink
	LDR -> InLoadOrderModuleList.Blink = EndModule -> InLoadOrderLinks.Blink;
	LDR -> InMemoryOrderModuleList.Blink = EndModule -> InLoadOrderLinks.Blink;
	LDR -> InInitializationOrderModuleList.Blink = EndModule -> InInitializationOrderLinks.Blink;

	MemBufSize = Mem_LDR_Data_Table_Entry -> SizeOfImage;//初始化MemBufSize变量
	VirtualFree((LPVOID)MemBuf,MemBufSize,MEM_DECOMMIT);//释放DLL内存

	//释放DLL模块描述结构体所占内存空间
	VirtualFree((LPVOID)CurModule -> BaseDllName.Buffer,CurModule -> BaseDllName.Length + 2,MEM_DECOMMIT);
	VirtualFree((LPVOID)CurModule -> FullDllName.Buffer,CurModule -> FullDllName.Length + 2,MEM_DECOMMIT);
	VirtualFree((LPVOID)CurModule,sizeof(LDR_DATA_TABLE_ENTRY),MEM_DECOMMIT);
}