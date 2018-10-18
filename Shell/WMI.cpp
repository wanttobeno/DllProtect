#include "WMI.h"  
#include <comutil.h>  
#include <Wbemidl.h>  
#include <string.h>
#include <strsafe.h>  
#include <algorithm>  
#include <atlconv.h>  
#include <ntddndis.h>  

#pragma comment (lib, "comsuppw.lib")  
#pragma comment (lib, "wbemuuid.lib")  

typedef struct _WQL_QUERY  
{  
	CHAR*   szSelect;       // SELECT语句  
	CHAR*  szProperty;     // 属性字段  
} WQL_QUERY;  

// WQL查询语句  
const WQL_QUERY szWQLQuery[] = {  
	// 网卡原生MAC地址  
	"SELECT * FROM Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",  
	"PNPDeviceID",  

	// 硬盘序列号  
	"SELECT * FROM Win32_DiskDrive WHERE (SerialNumber IS NOT NULL) AND (MediaType LIKE 'Fixed hard disk%')",  
	"SerialNumber",  

	// 主板序列号  
	"SELECT * FROM Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)",  
	"SerialNumber",      

	// 处理器ID  
	"SELECT * FROM Win32_Processor WHERE (ProcessorId IS NOT NULL)",  
	"ProcessorId",  

	// BIOS序列号  
	"SELECT * FROM Win32_BIOS WHERE (SerialNumber IS NOT NULL)",  
	"SerialNumber",  

	// 主板型号  
	"SELECT * FROM Win32_BaseBoard WHERE (Product IS NOT NULL)",  
	"Product",  

	// 网卡当前MAC地址  
	"SELECT * FROM Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",  
	"MACAddress",  
};  

// 通过“PNPDeviceID”获取网卡原生MAC地址  
static BOOL WMI_DoWithPNPDeviceID( const char *PNPDeviceID, char *MacAddress, UINT uSize )  
{  
	char   DevicePath[MAX_PATH];  
	HANDLE  hDeviceFile;      
	BOOL    isOK = FALSE;  

	// 生成设备路径名  
	StringCchCopy( DevicePath, MAX_PATH, ("////.//") );  
	StringCchCat( DevicePath, MAX_PATH, PNPDeviceID );  
	StringCchCat( DevicePath, MAX_PATH, ("#{ad498944-762f-11d0-8dcb-00c04fc3358c}") );  

	// 将“PNPDeviceID”中的“/”替换成“#”，以获得真正的设备路径名  
	std::replace( DevicePath + 4, DevicePath + 4 + strlen(PNPDeviceID), (char)('//'), ('#') );   

	// 获取设备句柄  
	hDeviceFile = CreateFile( DevicePath,  
		0,  
		FILE_SHARE_READ | FILE_SHARE_WRITE,  
		NULL,  
		OPEN_EXISTING,  
		0,  
		NULL);  

	if( hDeviceFile != INVALID_HANDLE_VALUE )  
	{     
		ULONG   dwID;  
		BYTE    ucData[8];  
		DWORD   dwByteRet;        

		// 获取网卡原生MAC地址  
		dwID = OID_802_3_PERMANENT_ADDRESS;  
		isOK = DeviceIoControl( hDeviceFile, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwID, sizeof(dwID), ucData, sizeof(ucData), &dwByteRet, NULL );  
		if( isOK )  
		{   // 将字节数组转换成16进制字符串  
			for( DWORD i = 0; i < dwByteRet; i++ )  
			{  
				StringCchPrintf( MacAddress + (i << 1), uSize - (i << 1), ("%02X"), ucData[i] );  
			}  

			MacAddress[dwByteRet << 1] = ('/0');  // 写入字符串结束标记  
		}  

		CloseHandle( hDeviceFile );  
	}  

	return isOK;  
}  

static BOOL WMI_DoWithHarddiskSerialNumber( char *SerialNumber, UINT uSize )  
{  
	UINT    iLen;  
	UINT    i;  

	iLen = strlen( SerialNumber );  
	if( iLen == 40 )    // InterfaceType = "IDE"  
	{   // 需要将16进制编码串转换为字符串  
		char ch, szBuf[32];  
		BYTE b;       

		for( i = 0; i < 20; i++ )  
		{   // 将16进制字符转换为高4位  
			ch = SerialNumber[i * 2];  
			if( (ch >= '0') && (ch <= '9') )  
			{  
				b = ch - '0';  
			}  
			else if( (ch >= 'A') && (ch <= 'F') )  
			{  
				b = ch - 'A' + 10;  
			}  
			else if( (ch >= 'a') && (ch <= 'f') )  
			{  
				b = ch - 'a' + 10;  
			}  
			else  
			{   // 非法字符  
				break;  
			}  

			b <<= 4;  

			// 将16进制字符转换为低4位  
			ch = SerialNumber[i * 2 + 1];  
			if( (ch >= '0') && (ch <= '9') )  
			{  
				b += ch - '0';  
			}  
			else if( (ch >= 'A') && (ch <= 'F') )  
			{  
				b += ch - 'A' + 10;  
			}  
			else if( (ch >= 'a') && (ch <= 'f') )  
			{  
				b += ch - 'a' + 10;  
			}  
			else  
			{   // 非法字符  
				break;  
			}  

			szBuf[i] = b;  
		}  

		if( i == 20 )  
		{   // 转换成功  
			szBuf[i] = L'/0';  
			StringCchCopy( SerialNumber, uSize, szBuf );  
			iLen = strlen( SerialNumber );  
		}  
	}  

	// 每2个字符互换位置  
	for( i = 0; i < iLen; i += 2 )  
	{  
		std::swap( SerialNumber[i], SerialNumber[i+1] );  
	}  

	// 去掉空格  
	std::remove( SerialNumber, SerialNumber + strlen(SerialNumber) + 1, ' ' );  

	return TRUE;  
}  

static BOOL WMI_DoWithProperty( INT iQueryType, char *szProperty, UINT uSize )  
{  
	BOOL isOK = TRUE;  

	switch( iQueryType )  
	{  
	case 0:     // 网卡原生MAC地址          
		isOK = WMI_DoWithPNPDeviceID( szProperty, szProperty, uSize );  
		break;  

	case 1:     // 硬盘序列号  
		isOK = WMI_DoWithHarddiskSerialNumber( szProperty, uSize );  
		break;  

	case 6:     // 网卡当前MAC地址  
				// 去掉冒号  
		std::remove( szProperty, szProperty + strlen(szProperty) + 1, L':' );  
		break;  

	default:  
		// 去掉空格  
		std::remove( szProperty, szProperty + strlen(szProperty) + 1, L' ' );  
	}  

	return isOK;  
}  

// 基于Windows Management Instrumentation（Windows管理规范）  
INT WMI_DeviceQuery( INT iQueryType, T_DEVICE_PROPERTY *properties, INT iSize )  
{  
	HRESULT hres;  
	INT iTotal = 0;  

	// 判断查询类型是否支持  
	if( (iQueryType < 0) || (iQueryType >= sizeof(szWQLQuery)/sizeof(T_WQL_QUERY)) )  
	{  
		return -1;  // 查询类型不支持  
	}  

	// 初始化COM  
	hres = CoInitializeEx( NULL, COINIT_MULTITHREADED );   
	if( FAILED(hres) )  
	{  
		return -2;  
	}  

	// 设置COM的安全认证级别  
	hres = CoInitializeSecurity(   
		NULL,   
		-1,   
		NULL,   
		NULL,   
		RPC_C_AUTHN_LEVEL_DEFAULT,   
		RPC_C_IMP_LEVEL_IMPERSONATE,  
		NULL,  
		EOAC_NONE,  
		NULL  
	);  
	if( FAILED(hres) )  
	{  
		CoUninitialize();  
		return -2;  
	}  

	// 获得WMI连接COM接口  
	IWbemLocator *pLoc = NULL;  
	hres = CoCreateInstance(   
		CLSID_WbemLocator,               
		NULL,   
		CLSCTX_INPROC_SERVER,   
		IID_IWbemLocator,  
		reinterpret_cast<LPVOID*>(&pLoc)  
	);   
	if( FAILED(hres) )  
	{  
		CoUninitialize();  
		return -2;  
	}  

	// 通过连接接口连接WMI的内核对象名"ROOT//CIMV2"  
	IWbemServices *pSvc = NULL;  
	hres = pLoc->ConnectServer(  
		_bstr_t( L"ROOT//CIMV2" ),  
		NULL,  
		NULL,  
		NULL,  
		0,  
		NULL,  
		NULL,  
		&pSvc  
	);      
	if( FAILED(hres) )  
	{  
		pLoc->Release();   
		CoUninitialize();  
		return -2;  
	}  

	// 设置请求代理的安全级别  
	hres = CoSetProxyBlanket(  
		pSvc,  
		RPC_C_AUTHN_WINNT,  
		RPC_C_AUTHZ_NONE,  
		NULL,  
		RPC_C_AUTHN_LEVEL_CALL,  
		RPC_C_IMP_LEVEL_IMPERSONATE,  
		NULL,  
		EOAC_NONE  
	);  
	if( FAILED(hres) )  
	{  
		pSvc->Release();  
		pLoc->Release();       
		CoUninitialize();  
		return -2;  
	}  

	// 通过请求代理来向WMI发送请求  
	IEnumWbemClassObject *pEnumerator = NULL;  
	hres = pSvc->ExecQuery(  
		bstr_t("WQL"),   
		bstr_t( szWQLQuery[iQueryType].szSelect ),  
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   
		NULL,  
		&pEnumerator  
	);  
	if( FAILED(hres) )  
	{  
		pSvc->Release();  
		pLoc->Release();  
		CoUninitialize();  
		return -3;  
	}  

	// 循环枚举所有的结果对象    
	while( pEnumerator )  
	{  
		IWbemClassObject *pclsObj = NULL;  
		ULONG uReturn = 0;  

		if( (properties != NULL) && (iTotal >= iSize) )  
		{  
			break;  
		}  

		pEnumerator->Next(  
			WBEM_INFINITE,  
			1,   
			&pclsObj,  
			&uReturn  
		);  

		if( uReturn == 0 )  
		{  
			break;  
		}  

		if( properties != NULL )  
		{   // 获取属性值  
			VARIANT vtProperty;  

			VariantInit( &vtProperty );   
			pclsObj->Get( szWQLQuery[iQueryType].szProperty, 0, &vtProperty, NULL, NULL );  
			StringCchCopy( properties[iTotal].szProperty, PROPERTY_MAX_LEN, (LPCSTR)_bstr_t(vtProperty.bstrVal) );  
			VariantClear( &vtProperty );  

			// 对属性值做进一步的处理  
			if( WMI_DoWithProperty( iQueryType, properties[iTotal].szProperty, PROPERTY_MAX_LEN ) )  
			{  
				iTotal++;  
			}  
		}  
		else  
		{  
			iTotal++;  
		}  

		pclsObj->Release();  
	} // End While  

	  // 释放资源  
	pEnumerator->Release();  
	pSvc->Release();  
	pLoc->Release();      
	CoUninitialize();  

	return iTotal;  
}  