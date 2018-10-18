#pragma once

/* ----------------------------------------------------------
文件名称：WMI_DeviceQuery.h

作者：秦建辉

MSN：splashcn@msn.com

版本历史：
V1.4	2010年05月17日
修正了硬盘序列号处理中的错误。现在和EVEREST Ultimate Edition 5.5一致。

V1.3	2010年05月11日
增加了对网卡原生MAC地址的查询。

V1.2	2010年05月05日
增加对硬盘序列号的进一步处理。

V1.1	2010年04月30日
修正微软MSDN例子错误，并增加对虚拟机网卡的判断。

V1.0	2010年04月27日
完成正式版本。

功能描述：
基于WMI获取设备属性：
0：网卡原生MAC地址
1：硬盘序列号
2：主板序列号
3：CPU ID
4：BIOS序列号
5：主板型号
6：网卡当前MAC地址

接口函数：
WMI_DeviceQuery
------------------------------------------------------------ */
#pragma once

#include <windows.h>

#ifndef MACRO_T_DEVICE_PROPERTY
#define MACRO_T_DEVICE_PROPERTY

#define PROPERTY_MAX_LEN	128	// 属性字段最大长度
typedef struct _T_DEVICE_PROPERTY
{
	TCHAR szProperty[PROPERTY_MAX_LEN];
} T_DEVICE_PROPERTY;
#endif

#define WMI_QUERY_TYPENUM	7	// WMI查询支持的类型数

#ifdef __cplusplus
extern "C"
{
#endif

	/*
	功能：通过WMI获取设备属性
	参数说明：
	iQueryType：需要查询的设备属性
	0：网卡原生MAC地址
	1：硬盘序列号
	2：主板序列号
	3：CPU ID
	4：BIOS序列号
	5：主板型号
	6：网卡当前MAC地址
	properties：存储设备属性值
	iSize：可存储的最大设备个数
	返回值：
	-1：不支持的设备属性值
	-2：WMI连接失败
	-3：不正确的WQL查询语句
	>=0：获取的设备个数	
	*/
	INT WMI_DeviceQuery( INT iQueryType, T_DEVICE_PROPERTY *properties, INT iSize );

#ifdef __cplusplus
}
#endif
