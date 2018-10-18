#include <cstdio>
#include <windows.h>
#include <wincon.h>
#include <stdlib.h>
#include <vector>
#include "DLLLoader.h"
#include "AES.h"
#include "CRC32.h"
#include <Nb30.h>
#include "ntdll.h"
#pragma comment(lib,"netapi32.lib")  

using namespace std;


#define uchar unsigned char
#define uint unsigned int
#define uint64 unsigned long long

typedef void (WINAPI* FUNC_RUN)(uint64, uint64);
FUNC_RUN Run = NULL;

#define BLOCK_SIZE 65536
#define BLOCK_NUM 4



#ifdef _DEBUG
#define  IS_DEBUG  1
#endif // _DEBUG

// 调试检测
#ifndef IS_DEBUG
#define DEBUGCHECK
#endif // !IS_DEBUG

//#define DEBUG

char Data1[BLOCK_SIZE] = "DLLLoaderLZRData1";
char UnknownData1[BLOCK_SIZE] = "DLLLoaderLZRUnknownData1";
char Data2[BLOCK_SIZE] = "DLLLoaderLZRData2";
char UnknownData2[BLOCK_SIZE] = "DLLLoaderLZRUnknownData2";
char Data3[BLOCK_SIZE] = "DLLLoaderLZRData3";
char UnknownData3[BLOCK_SIZE] = "DLLLoaderLZRUnknownData3";
char Data4[BLOCK_SIZE] = "DLLLoaderLZRData4";
char UnknownData4[BLOCK_SIZE] = "DLLLoaderLZRUnknownData4";
char DataInfo[BLOCK_SIZE] = "DLLoaderLZRDataInfo1";
char UnknownData5[BLOCK_SIZE] = "DLLLoaderLZRUnknownData5";
char DataInfo2[BLOCK_SIZE] = "DLLoaderLZRDataInfo2";
char CurPath[MAX_PATH];
//大于4*64K=256K的数据一律放到EXE尾部，以上所有数据均采用AES算法加密，并采用XOR二次加密

char InputVector[16] = { 0x05, 0x84, 0x63, 0x75, 0x74, 0x96, 0x75, 0x89, 0x77, 0x63, 0x59, 0x66, 0xA9, 0xF6, 0x7C, 0xFE };

#define DATAINFO_FILESIZE 1000 //4Bytes
#define DATAINFO_FILEORIGINSIZE 3564 //4Bytes
#define DATAINFO_FILEAESPASSWORD 5236 //16Bytes
#define DATAINFO_FILEXORPASSWORD 15832 //1000Bytes
#define DATAINFO_DLLVIRTUALNAME 23856 //NULL截止 必须为.dll结尾
#define DATAINFO_VERIFYMACHINECODE 25675 //1Byte
#define DATAINFO_MACHINECODE 34125 //8Bytes
#define DATAINFO_XORDATAVERIFYCODE 42578 //数据XOR校验码 1Byte
#define DATAINFO_CRC32DATAVERIFYCODE 52714 //数据CRC32校验码 4Bytes

#define XORPASSWORDLEN 1000

DWORD ExitAddress = 0xFFFFFFFF;
DWORD MainESP = 0xFFFFFFFF;
DWORD MainEBP = 0xFFFFFFFF;

typedef struct DATA_INFO
{
	DWORD FileSize;
	DWORD FileOriginSize;
	char *FileAESPassword;
	char *FileXORPassword;
	char *DLLVirtualName;
	bool VerifyMachineCode;
	uint64 MachineCode;
	char XORDataVerifyCode;
	DWORD CRC32DataVerifyCode;
}DATA_INFO;

typedef DWORD(NTAPI *Csr)(void);

Csr CsrGetProcessId;

DATA_INFO DataInfoStruct;
vector<uint64> mac;
DWORD tEAX, tEDX;
DWORD pAllocatedMem;
DWORD dwOldProtect;

int ShellExit();

inline bool ValidNumRange(int n, int min, int max)
{
	return (n >= min) && (n <= max);
}

inline bool IsInsideVMWare()
{
	bool rc = true;

	__try
	{
		__asm
		{
			push   edx
				push   ecx
				push   ebx

				mov    eax, 'VMXh'
				mov    ebx, 0  // 将ebx设置为非幻数’VMXH’的其它值
				mov    ecx, 10 // 指定功能号，用于获取VMWare版本，当它为0x14时用于获取VMware内存大小
				mov    edx, 'VX' // 端口号
				in     eax, dx // 从端口dx读取VMware版本到eax
				//若上面指定功能号为0x14时，可通过判断eax中的值是否大于0，若是则说明处于虚拟机中
				cmp    ebx, 'VMXh' // 判断ebx中是否包含VMware版本’VMXh’，若是则在虚拟机中
				setz[rc] // 设置返回值

				pop    ebx
				pop    ecx
				pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)  //如果未处于VMware中，则触发此异常
	{
		rc = false;
	}

	return rc;
}

inline bool IsVirtualPC_LDTCheck()
{
	unsigned short ldt_addr = 0;
	unsigned char ldtr[2];

	_asm sldt ldtr
	ldt_addr = *((unsigned short *)&ldtr);
	return ldt_addr != 0x00000000;
}

inline bool IsVirtualPC_GDTCheck()
{
	unsigned int gdt_addr = 0;
	unsigned char gdtr[6];

	_asm sgdt gdtr
	gdt_addr = *((unsigned int *)&gdtr[2]);
	return (gdt_addr >> 24) == 0xff;
}

inline bool IsVirtualPC_TSSCheck()
{
	unsigned char mem[4] = { 0 };

	__asm str mem;
	return (mem[0] == 0x00) && (mem[1] == 0x40);
}

inline bool DetectVM()
{
	HKEY hKey;

	char szBuffer[64];

	unsigned long hSize = sizeof(szBuffer)-1;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS\\", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{

		RegQueryValueEx(hKey, "SystemManufacturer", NULL, NULL, (unsigned char *)szBuffer, &hSize);

		if (strstr(szBuffer, "VMWARE"))
		{
			RegCloseKey(hKey);
			return true;
		}

		RegCloseKey(hKey);
	}

	return false;
}

inline void BeginCheckTimingDebug()
{
#ifdef DEBUGCHECK
	__asm
	{
		PUSHAD
			CPUID
			RDTSC
			MOV tEAX,EAX
			MOV tEDX,EDX
			POPAD
	}

#endif
}

inline void EndCheckTimingDebug(DWORD TimeDelta)
{
#ifdef DEBUGCHECK
	__asm
	{
		PUSHAD
			CPUID
			MOV ECX,tEAX
			MOV EBX,tEDX
			RDTSC
			CMP EDX,EBX
			JA Debugger_Found
			SUB EAX,ECX
			CMP EAX,TimeDelta
			JA Debugger_Found
			JMP safe

		Debugger_Found:

		POPAD
			MOV ESP,MainESP
			JMP ExitAddress

		safe:
		POPAD
	}
#endif
}

inline void CheckDebug()
{

#ifdef DEBUGCHECK
	int debuged;
	DWORD DebugPort;
	DWORD ReturnLen;

	//虚拟机检测
	(IsInsideVMWare() || IsVirtualPC_LDTCheck() || IsVirtualPC_GDTCheck() || IsVirtualPC_TSSCheck() || DetectVM()) ? ShellExit() : 0;

	__asm
	{
		PUSHAD

			;check PEB.BeingDebugged directly

			MOV EAX,DWORD PTR FS:[0x30]
			MOVZX EAX,BYTE PTR [EAX+2]
			TEST EAX,EAX
			JNZ Debugger_Found
			JMP safe

		Debugger_Found:

		POPAD
			MOV ESP,MainESP
			MOV EBP,MainEBP
			JMP ExitAddress

		safe:

		;(PEB.ProcessHeap)
			MOV EBX,DWORD PTR FS:[030H]

			;Check if PEB.NtGlobalFlag != 0
			CMP DWORD PTR [EBX+068H],0
			JNE Debugger_Found
			;query for the PID of CSRSS.EXE
			CALL [CsrGetProcessId]

			;try to open the CSRSS.EXE process
			PUSH EAX
			PUSH FALSE
			PUSH PROCESS_QUERY_INFORMATION
			CALL [OpenProcess]

			;if OpenProcess() was successful
			;process is probably being debugged
			TEST EAX,EAX
			JNZ Debugger_Found

		EXIT:
		POPAD
	}

	(CheckRemoteDebuggerPresent(GetCurrentProcess(),&debuged) == FALSE) ? ShellExit() : 0;	
	(debuged == TRUE) ? ShellExit() : 0;
	NtQueryInformationProcess(GetCurrentProcess(),ProcessDebugPort,&DebugPort,4,&ReturnLen);
	(DebugPort != 0) ? ShellExit() : 0;

#endif
}

inline int GetNetworkAdapterAddress()
{
	NCB ncb;
	uint t, p;
	int i, j;

	typedef struct _ASTAT_
	{
		ADAPTER_STATUS   adapt;
		NAME_BUFFER   NameBuff[30];
	}ASTAT, *PASTAT;

	ASTAT Adapter;

	typedef struct _LANA_ENUM
	{
		UCHAR   length;
		UCHAR   lana[MAX_LANA];
	}LANA_ENUM;

	mac.clear();
	LANA_ENUM lana_enum;
	UCHAR uRetCode;
	memset(&ncb, 0, sizeof(ncb));
	memset(&lana_enum, 0, sizeof(lana_enum));
	ncb.ncb_command = NCBENUM;
	ncb.ncb_buffer = (unsigned char *)&lana_enum;
	ncb.ncb_length = sizeof(LANA_ENUM);
	uRetCode = Netbios(&ncb);

	if (uRetCode != NRC_GOODRET)
		return uRetCode;

	for (int lana = 0; lana < lana_enum.length; lana++)
	{
		ncb.ncb_command = NCBRESET;
		ncb.ncb_lana_num = lana_enum.lana[lana];
		uRetCode = Netbios(&ncb);
		if (uRetCode == NRC_GOODRET)
			break;
	}

	if (uRetCode != NRC_GOODRET)
		return uRetCode;

	for (i = 0; i < lana_enum.length; i++)
	{
		memset(&ncb, 0, sizeof(ncb));
		ncb.ncb_command = NCBASTAT;
		ncb.ncb_lana_num = lana_enum.lana[i];
		strcpy((char*)ncb.ncb_callname, "*");
		ncb.ncb_buffer = (unsigned char *)&Adapter;
		ncb.ncb_length = sizeof(Adapter);
		uRetCode = Netbios(&ncb);

		if (uRetCode != NRC_GOODRET)
			return uRetCode;

		p = 0;

		for (j = 0; j < 6; j++)
		{
			t = Adapter.adapt.adapter_address[j];
			p |= t << ((5 - j) * 8);
		}

		mac.push_back(p);
	}

	return 0;
}

inline uint64 GetMachineCode()
{
	uint64 machinecode;
	int i;

	GetNetworkAdapterAddress();
	machinecode = 0xAD12F5E4D6A2F1D2;

	for (i = 0; i < mac.size(); i++)
	{
		machinecode ^= mac[i] * mac[i];
	}

	return machinecode;
}

inline void MachineVerify()
{
	int i;
	uint64 machinecode;

	if (DataInfoStruct.VerifyMachineCode)
	{
		machinecode = GetMachineCode();
#ifdef IS_DEBUG
		printf("当前机器码：%X%X  程序内部机器码：%X%X\r\n",(DWORD)((machinecode >> 32) & 0xFFFFFFFF),(DWORD)(machinecode & 0xFFFFFFFF),(DWORD)((DataInfoStruct.MachineCode >> 32) & 0xFFFFFFFF),(DWORD)(DataInfoStruct.MachineCode & 0xFFFFFFFF));
#endif
		(machinecode != DataInfoStruct.MachineCode) ? ShellExit() : 0;
		(machinecode != DataInfoStruct.MachineCode) ? ShellExit() : 0;
		(machinecode == DataInfoStruct.MachineCode) ? 0 : ShellExit();
		(machinecode != DataInfoStruct.MachineCode) ? ShellExit() : 0;
	}
}

inline void DataVerify()//数据完整性验证
{
	DWORD i;
	char *p = DataInfo;
	char *q = DataInfo2;
	char xorcode;
	DWORD crccode;

	//双数据块比对

	for (i = 0; i < BLOCK_SIZE; i++)
	{
		(p[i] == q[i]) ? 0 : ShellExit();
		(p[i] != q[i]) ? ShellExit() : 0;
		(p[i] == q[i]) ? 0 : ShellExit();
		(p[i] != q[i]) ? ShellExit() : 0;
	}

#ifdef IS_DEBUG
	printf("数据块对比OK\r\n");
#endif

	//XOR计算 去除XOR和CRC32CODE共5个字节区域

	xorcode = 0x7C;

	for (i = 0; i < BLOCK_SIZE; i++)
	{
		if ((i != DATAINFO_XORDATAVERIFYCODE) && (!ValidNumRange(i, DATAINFO_CRC32DATAVERIFYCODE, DATAINFO_CRC32DATAVERIFYCODE + 3)))
		{
			xorcode ^= DataInfo[i];
		}
	}

#ifdef IS_DEBUG
	printf("XOR计算结果：%u\r\n",(DWORD)xorcode);
#endif

	for (i = 0; i < 5; i++)
	{
		(xorcode == DataInfoStruct.XORDataVerifyCode) ? 0 : ShellExit();
	}

	(xorcode != DataInfoStruct.XORDataVerifyCode) ? ShellExit() : 0;

#ifdef IS_DEBUG
	printf("XOR计算OK\r\n");
#endif

	//CRC32计算 将CRC32CODE 4字节区域设置为0x418A2E3D

	crccode = 0xA582ECB6;
	*((DWORD *)(DataInfo2 + DATAINFO_CRC32DATAVERIFYCODE)) = 0x418A2E3D;
	crccode = CRC32(crccode, (uchar *)DataInfo2, BLOCK_SIZE);
#ifdef IS_DEBUG
	printf("CRC32计算结果：%u\r\n",crccode);
#endif
	(crccode == DataInfoStruct.CRC32DataVerifyCode) ? 0 : ShellExit();
	(crccode != DataInfoStruct.CRC32DataVerifyCode) ? ShellExit() : 0;

#ifdef IS_DEBUG
	printf("CRC32对比OK\r\n");
#endif
}

inline void DataInfoLoad()//加载数据信息
{
	DataInfoStruct.FileSize = *((LPDWORD)(DataInfo + DATAINFO_FILESIZE));
	DataInfoStruct.FileOriginSize = *((LPDWORD)(DataInfo + DATAINFO_FILEORIGINSIZE));
	DataInfoStruct.FileAESPassword = DataInfo + DATAINFO_FILEAESPASSWORD;
	DataInfoStruct.FileXORPassword = DataInfo + DATAINFO_FILEXORPASSWORD;
	DataInfoStruct.DLLVirtualName = DataInfo + DATAINFO_DLLVIRTUALNAME;
	DataInfoStruct.VerifyMachineCode = (*((uchar *)(DataInfo2 + DATAINFO_VERIFYMACHINECODE)) != 0xAF) ? true : false;
	DataInfoStruct.MachineCode = *((uint64 *)(DataInfo2 + DATAINFO_MACHINECODE));
	DataInfoStruct.XORDataVerifyCode = *((char *)(DataInfo2 + DATAINFO_XORDATAVERIFYCODE));
	DataInfoStruct.CRC32DataVerifyCode = *((DWORD *)(DataInfo2 + DATAINFO_CRC32DATAVERIFYCODE));

#ifdef IS_DEBUG
	printf("数据大小:%u\r\n数据原始大小：%u\r\nDLL虚拟名称：%s\r\nXOR数据校验码：%u\r\nCRC32数据校验码：%u\r\n验证机器码正常值：0x%X\r\n机器码项值：0x%X\r\n",DataInfoStruct.FileSize,DataInfoStruct.FileOriginSize,DataInfoStruct.DLLVirtualName,(DWORD)DataInfoStruct.XORDataVerifyCode,DataInfoStruct.CRC32DataVerifyCode,(DWORD)0xAF,(DWORD)(*((uchar *)(DataInfo2 + DATAINFO_VERIFYMACHINECODE))));
#endif
}

inline char * DataDecrypt(char *CurModuleCode, DWORD Length)//数据解密
{
	int xorptr = 0;//xor密钥指针
	DWORD i;
	char iv[16];
	LPVOID Data[4] = { Data1, Data2, Data3, Data4 };
	LPVOID TempDataBuf = VirtualAlloc(NULL, max(DataInfoStruct.FileSize, BLOCK_NUM * BLOCK_SIZE), MEM_COMMIT, PAGE_READWRITE);
	LPVOID ResultDataBuf = VirtualAlloc(NULL, DataInfoStruct.FileOriginSize * 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	char *TempResult = new char[(DataInfoStruct.FileOriginSize + DataInfoStruct.FileOriginSize % 16) * 2];

	//数据块拷贝合并

#ifdef IS_DEBUG
	printf("开始进行数据块拷贝合并\r\n");
#endif

	for (i = 0; i < BLOCK_NUM; i++)
	{
#ifdef IS_DEBUG
		printf("开始拷贝第%u块  源内存：0x%X-%X  目标内存：0x%X\r\n",i,Data[i],Data1,((DWORD)TempDataBuf + i * BLOCK_SIZE));
#endif
		CopyMemory((LPVOID)((DWORD)TempDataBuf + i * BLOCK_SIZE), Data[i], BLOCK_SIZE);
	}

#ifdef IS_DEBUG
	printf("基本块拷贝完毕\r\n");
#endif

	if (((BLOCK_NUM * BLOCK_SIZE) + Length) < DataInfoStruct.FileSize)
	{
		ShellExit();
	}

	if (DataInfoStruct.FileSize > (BLOCK_NUM * BLOCK_SIZE))
	{
		CopyMemory((LPVOID)((DWORD)TempDataBuf + BLOCK_NUM * BLOCK_SIZE), (LPVOID)((DWORD)CurModuleCode + (Length - (DataInfoStruct.FileSize - (BLOCK_NUM * BLOCK_SIZE)))), DataInfoStruct.FileSize - (BLOCK_NUM * BLOCK_SIZE));
	}

#ifdef IS_DEBUG
	printf("扩展块拷贝完毕\r\n");
#endif

	//XOR解密

#ifdef IS_DEBUG
	printf("开始进行XOR解密\r\n");
#endif

	xorptr = 0;

	for (i = 0; i < DataInfoStruct.FileSize; i++)
	{
		((char *)TempDataBuf)[i] ^= DataInfoStruct.FileXORPassword[xorptr++];

		if (xorptr == XORPASSWORDLEN)
		{
			xorptr = 0;
		}
	}

	//AES解密

#ifdef IS_DEBUG
	printf("开始进行AES解密\r\n");
#endif

	memcpy(iv, InputVector, 16);
#ifdef IS_DEBUG
	printf("iv复制完成\r\n");
#endif
	AES_CBC_decrypt_buffer((uint8_t *)TempResult, (uint8_t *)TempDataBuf, DataInfoStruct.FileSize, (uint8_t *)DataInfoStruct.FileAESPassword, (uint8_t *)iv);
#ifdef IS_DEBUG
	printf("AES初步解密执行完成\r\n");
	printf("目标数据地址：0x%X 数据大小：%u\r\n",(DWORD)ResultDataBuf,DataInfoStruct.FileOriginSize);
#endif
	memcpy(ResultDataBuf, TempResult, DataInfoStruct.FileOriginSize);
#ifdef DEBUG
	printf("AES解密完成\r\n");
#endif
	return ((char *)ResultDataBuf);
	//return ((char *)TempDataBuf);
}

inline uint64 MachineCodeEncrypt(uint64 x)
{
	uint64 r;
	char iv[16];
	char key[16] = { 0x52, 0x63, 0x75, 0x82, 0x63, 0x75, 0xA5, 0x9F, 0xCC, 0x7A, 0x82, 0x6B, 0x77, 0xAF, 0xBC, 0x1A };

	memcpy(iv, InputVector, 16);
	AES_CBC_encrypt_buffer((uint8_t *)&r, (uint8_t *)&x, 8, (uint8_t *)key, (uint8_t *)iv);
	return r;
}

int ShellExit()
{
	__asm
	{
		MOV ESP, MainESP
			MOV EBP, MainEBP
			JMP ExitAddress
	}

	return 0;
}

int main()
{
	HMODULE hMod;//DLL内存基址即DLL句柄句柄
	DWORD ReadFileSize;//这个变量只是为了使用ReadFile API而定义的，并没有什么实际意义
	char *DecryptedData;
	char *UnknownData[5] = { UnknownData1, UnknownData2, UnknownData3, UnknownData4, UnknownData5 };//防止Unknown块被优化
	int i;

	__asm
	{
		MOV ExitAddress, OFFSET ExitPrg
			MOV MainESP, ESP
			MOV MainEBP, EBP
	}

	for (i = 0; i < 5; i++)//防止Unknown块被优化
	{
		memset(UnknownData[i], UnknownData[i][0], 1);
	}

	CsrGetProcessId = (Csr)GetProcAddress(GetModuleHandle("ntdll"), "CsrGetProcessId");
	CheckDebug();
#ifdef IS_DEBUG
	printf("第一次Debug检测完成！\r\n");
#endif

	BeginCheckTimingDebug();
	InitCRCTable();//初始化CRC表
	EndCheckTimingDebug(40000000);
	BeginCheckTimingDebug();
	DataInfoLoad();//加载数据信息
	EndCheckTimingDebug(40000000);
	BeginCheckTimingDebug();
	DataVerify();//数据信息验证
	EndCheckTimingDebug(40000000);
#ifdef IS_DEBUG
	printf("数据信息验证通过！\r\n");
#endif
	BeginCheckTimingDebug();
	MachineVerify();//机器验证
#ifdef IS_DEBUG
	printf("机器验证通过！\r\n");
#endif
	EndCheckTimingDebug(40000000);

#ifdef IS_DEBUG
	printf("准备运行\r\n");
#endif

	GetModuleFileName(NULL, (LPSTR)CurPath, sizeof(CurPath));
#ifdef IS_DEBUG
	printf("准备打开自身文件\r\n");
#endif
	HANDLE DLLFile = CreateFile((LPCSTR)CurPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);//绝对路径打开DLL文件

	if ((DLLFile == NULL) || ((DWORD)DLLFile == 0xFFFFFFFF))
	{
		return 0;//自身文件无法打开
	}
	else
	{
		CheckDebug();
		DWORD FileSize = GetFileSize(DLLFile, NULL);//获取DLL文件大小
#ifdef DEBUG
		printf("准备分配存储空间：%u\r\n",FileSize);
#endif
		LPVOID DLLFileBuf = VirtualAlloc(NULL, FileSize, MEM_COMMIT, PAGE_READWRITE);//分配DLL文件存储内存空间

		CheckDebug();

		if (ReadFile(DLLFile, DLLFileBuf, FileSize, &ReadFileSize, NULL) == NULL)//读入DLL文件
		{
			CloseHandle(DLLFile);
			return 0;//文件读取失败
		}
		else
		{
			BeginCheckTimingDebug();
			CheckDebug();
			EndCheckTimingDebug(40000000);
#ifdef IS_DEBUG
			printf("开始解密文件\r\n");
#endif
			DecryptedData = DataDecrypt((char *)DLLFileBuf, FileSize);
#ifdef IS_DEBUG
			printf("解密文件成功\r\n");
#endif
#ifdef IS_DEBUG
			HANDLE OutputFile = CreateFile((LPCSTR)"Out.dll", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			if ((OutputFile == NULL) || ((DWORD)OutputFile == 0xFFFFFFFF))
			{
				printf("Output File \"%s\" can't be created!\r\n", "D:\\Temp\\Out.dll");
				CloseHandle(DLLFile);
				CloseHandle(OutputFile);
				return 0;
			}

			DWORD WrittenDataSize;

			if (WriteFile(OutputFile, DecryptedData, DataInfoStruct.FileOriginSize, &WrittenDataSize, NULL) == FALSE)
			{
				printf("Write Output File \"%s\" Fail!\r\n", "D:\\Temp\\Out.dll");
				CloseHandle(DLLFile);
				CloseHandle(OutputFile);
				return 0;
			}

			CloseHandle(DLLFile);
			CloseHandle(OutputFile);
#endif

			if (DataDecrypt == NULL)
			{
				return 0;//数据解密失败
			}

			CheckDebug();
#ifdef IS_DEBUG
			printf("准备调用自身程序,内存第一个字符%c\r\n", DecryptedData[0]);
#endif
			hMod = (HMODULE)DLLMemLoad(DecryptedData, DataInfoStruct.FileOriginSize, DataInfoStruct.DLLVirtualName, DataInfoStruct.DLLVirtualName);//DLL内存加载函数，注意为了保证一些DLL模块的正常运行，请保证MemDLLBaseName参数和MemDLLFullName参数的结尾是“.dll”（不区分大小写）
			Run = (FUNC_RUN)GetProcAddress(hMod, "Run");//获取“Run”函数地址

			if (DataInfoStruct.VerifyMachineCode)
			{
				Run(GetMachineCode(), MachineCodeEncrypt(GetMachineCode()));
			}
			else
			{
				Run(0xAF857463F6E5F3A4, MachineCodeEncrypt(0xC63F8A6E1A639E5A));
			}

#ifdef IS_DEBUG
			printf("结束运行\r\n");
#endif
		}
#ifdef IS_DEBUG
		printf("句柄关闭完成\r\n");
#endif
	}

	DLLMemFree((char *)hMod);//DLL内存释放函数，请在程序结束之前调用它释放加载的DLL，否则程序可能会异常退出
#ifdef IS_DEBUG
	printf("DLL释放完成\r\n");
#endif
ExitPrg:
	TerminateProcess(GetCurrentProcess(), 0);
	return 0;
}