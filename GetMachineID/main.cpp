#include <cstdio>
#include <windows.h>
#include <wincon.h>
#include <stdlib.h>
#include <vector>
#include <Nb30.h>
#pragma comment(lib,"netapi32.lib")  

#define uchar unsigned char
#define uint unsigned int
#define uint64 unsigned long long

using namespace std;

vector<uint64> mac;

inline int GetNetworkAdapterAddress()
{
	NCB ncb;
	uint t,p;
	int i,j;

	typedef struct _ASTAT_
	{
		ADAPTER_STATUS   adapt;
		NAME_BUFFER   NameBuff   [30];
	}ASTAT,*PASTAT;

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

	if(uRetCode != NRC_GOODRET)     
		return uRetCode;     

	for(int lana=0; lana<lana_enum.length; lana++)     
	{
		ncb.ncb_command = NCBRESET;
		ncb.ncb_lana_num = lana_enum.lana[lana];
		uRetCode = Netbios(&ncb); 
		if(uRetCode == NRC_GOODRET)
			break; 
	}

	if(uRetCode != NRC_GOODRET)
		return uRetCode;     

	for(i = 0;i < lana_enum.length;i++)
	{
		memset(&ncb, 0, sizeof(ncb));
		ncb.ncb_command = NCBASTAT;
		ncb.ncb_lana_num = lana_enum.lana[i];
		strcpy((char*)ncb.ncb_callname, "*");
		ncb.ncb_buffer = (unsigned char *)&Adapter;
		ncb.ncb_length = sizeof(Adapter);
		uRetCode = Netbios(&ncb);

		if(uRetCode != NRC_GOODRET)
			return uRetCode;

		p = 0;

		for(j = 0;j < 6;j++)
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

	for(i = 0;i < mac.size();i++)
	{
		machinecode ^= mac[i] * mac[i];
	}

	return machinecode;
}

int main()
{
	uint64 machinecode = GetMachineCode();
	printf("»úÆ÷ÂëÎª£º%X%X\r\n",(DWORD)((machinecode >> 32) & 0xFFFFFFFF),(DWORD)(machinecode & 0xFFFFFFFF));
	system("pause");
	return 0;
}