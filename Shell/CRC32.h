#pragma once

#ifndef __CRC32_H__
#define __CRC32_H__

void InitCRCTable();  
unsigned int CRC32(unsigned int crc, unsigned char * buffer, unsigned int size); 

#endif