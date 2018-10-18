#include <stdio.h>  
#include <stdlib.h>  
#include <fcntl.h>  
#include <errno.h>  


#define BUFSIZE 1024 * 4  

unsigned int crc_table[256]; 

void InitCRCTable();  
unsigned int CRC32(unsigned int crc,unsigned char * buffer,unsigned int size);  

void InitCRCTable()    
{    
	unsigned int c;    
	unsigned int i, j;    

	for (i = 0; i < 256; i++)   
	{    
		c = (unsigned int)i;    

		for (j = 0; j < 8; j++)   
		{    
			if (c & 1)    
			{
				c = 0xedb88320L ^ (c >> 1);    
			}
			else    
			{
				c = c >> 1;    
			}
		}    

		crc_table[i] = c;    
	}    
}    
  
unsigned int CRC32(unsigned int crc,unsigned char *buffer, unsigned int size)    
{    
	unsigned int i;    

	for (i = 0; i < size; i++)   
	{    
		crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);    
	}    

	return crc ;    
}    