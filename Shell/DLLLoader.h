#ifndef __DLLLOADER_H__
#define __DLLLOADER_H__

	char* DLLMemLoad(char* DLLFileBuf, DWORD DLLFileSize, char* MemDLLBaseName, char* MemDLLFullName);//DLL内存加载函数，注意为了保证一些DLL模块的正常运行，请保证MemDLLBaseName参数和MemDLLFullName参数的结尾是“.dll”（不区分大小写）
	void DLLMemFree(char* DLLMemBaseAddress);//DLL内存释放函数，请在程序结束之前调用它释放加载的DLL，否则程序可能会异常退出
#endif