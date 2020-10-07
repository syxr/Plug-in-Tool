//至可乐

#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <math.h>
#include <netdb.h>
#include <cstring>
#include <dirent.h>
#define SERVER_PORT 80

//*****以下为UFT-8转码函数*******//
#ifndef __UTF_H__
#define __UTF_H__
 
#define FALSE  0
#define TRUE   1
 
#define halfShift	10
#define UNI_SUR_HIGH_START  (UTF32)0xD800
#define UNI_SUR_HIGH_END    (UTF32)0xDBFF
#define UNI_SUR_LOW_START   (UTF32)0xDC00
#define UNI_SUR_LOW_END     (UTF32)0xDFFF
/* Some fundamental constants */
#define UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
#define UNI_MAX_BMP (UTF32)0x0000FFFF
#define UNI_MAX_UTF16 (UTF32)0x0010FFFF
#define UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
#define UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF
 
typedef unsigned char   boolean;
typedef unsigned int	CharType ;
typedef  char	UTF8;
typedef unsigned short	UTF16;
typedef unsigned int	UTF32;
 
static const UTF32 halfMask = 0x3FFUL;
static const UTF32 halfBase = 0x0010000UL;
static const UTF8 firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static const UTF32 offsetsFromUTF8[6] = { 0x00000000UL, 0x00003080UL, 0x000E2080UL, 0x03C82080UL, 0xFA082080UL, 0x82082080UL };
static const char trailingBytesForUTF8[256] =
{
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};
typedef enum 
{
	strictConversion = 0,
	lenientConversion
} ConversionFlags;
typedef enum 
{
	conversionOK, 		/* conversion successful */
	sourceExhausted,	/* partial character in source, but hit end */
	targetExhausted,	/* insuff. room in target for conversion */
	sourceIllegal,		/* source sequence is illegal/malformed */
	conversionFailed
} ConversionResult;
#endif

int Utf16_To_Utf8 (const UTF16* sourceStart, UTF8* targetStart, size_t outLen , ConversionFlags flags) {
	int result = 0;
	const UTF16* source = sourceStart;
	UTF8* target = targetStart;
	UTF8* targetEnd	= targetStart + outLen;
	if ((NULL == source) || (NULL == targetStart)){
		// printf("ERR, Utf16_To_Utf8: source=%p, targetStart=%p\n", source, targetStart);
		return conversionFailed;
	}
	
	while (*source) {
		UTF32 ch;
		unsigned short bytesToWrite = 0;
		const UTF32 byteMask = 0xBF;
		const UTF32 byteMark = 0x80; 
		const UTF16* oldSource = source; /* In case we have to back up because of target overflow. */
		ch = *source++;
		/* If we have a surrogate pair, convert to UTF32 first. */
		if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
			/* If the 16 bits following the high surrogate are in the source buffer... */
			if ( *source ){
				UTF32 ch2 = *source;
				/* If it's a low surrogate, convert to UTF32. */
				if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
					ch = ((ch - UNI_SUR_HIGH_START) << halfShift) + (ch2 - UNI_SUR_LOW_START) + halfBase;
					++source;
				}else if (flags == strictConversion) { /* it's an unpaired high surrogate */
					--source; /* return to the illegal value itself */
					result = sourceIllegal;
					break;
				}
			} else { /* We don't have the 16 bits following the high surrogate. */
				--source; /* return to the high surrogate */
				result = sourceExhausted;
				break;
			}
		} else if (flags == strictConversion) {
			/* UTF-16 surrogate values are illegal in UTF-32 */
			if (ch >= UNI_SUR_LOW_START && ch <= UNI_SUR_LOW_END){
				--source; /* return to the illegal value itself */
				result = sourceIllegal;
				break;
			}
		}
		/* Figure out how many bytes the result will require */
		if(ch < (UTF32)0x80){		 
			bytesToWrite = 1;
		} else if (ch < (UTF32)0x800) {	 
			bytesToWrite = 2;
		} else if (ch < (UTF32)0x10000) {  
			bytesToWrite = 3;
		} else if (ch < (UTF32)0x110000){ 
			bytesToWrite = 4;
		} else {	
			bytesToWrite = 3;
			ch = UNI_REPLACEMENT_CHAR;
		}
		
		target += bytesToWrite;
		if (target > targetEnd) {
			source = oldSource; /* Back up source pointer! */
			target -= bytesToWrite; result = targetExhausted; break;
		}
		switch (bytesToWrite) { /* note: everything falls through. */
			case 4: *--target = (UTF8)((ch | byteMark) & byteMask); ch >>= 6;
			case 3: *--target = (UTF8)((ch | byteMark) & byteMask); ch >>= 6;
			case 2: *--target = (UTF8)((ch | byteMark) & byteMask); ch >>= 6;
			case 1: *--target = (UTF8)(ch | firstByteMark[bytesToWrite]);
		}
		target += bytesToWrite;
	}
	return result;
}
//*************截止**************//


//**********以下为md5*********//
#define MAX_BUFFER 10240		// 数据缓冲区最大值

#define READ_DATA_SIZE  1024
#define MD5_SIZE        16
#define MD5_STR_LEN     (MD5_SIZE * 2)

typedef struct
{
  unsigned int count[2];
  unsigned int state[4];
  unsigned char buffer[64];   
} MD5_CTX;

char md5_str[MD5_STR_LEN + 1];

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))

/**判断str1是否以str2开头
 * 如果是返回1
 * 不是返回0
 * 出错返回-1
 * */
int is_begin_with(const char * str1,char *str2)
{
    if(str1 == NULL || str2 == NULL)
        return -1;
    int len1 = strlen(str1);
    int len2 = strlen(str2);
    if((len1 < len2) ||  (len1 == 0 || len2 == 0))
        return -1;
    char *p = str2;
    int i = 0;
    while(*p != '\0')
    {
        if(*p != str1[i])
            return 0;
        p++;
        i++;
    }
    return 1;
}
#define FF(a,b,c,d,x,s,ac) \
{ \
  a += F(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
#define GG(a,b,c,d,x,s,ac) \
{ \
  a += G(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
#define HH(a,b,c,d,x,s,ac) \
{ \
  a += H(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
#define II(a,b,c,d,x,s,ac) \
{ \
  a += I(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}  
unsigned char PADDING[] =
{
  0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

void MD5Init(MD5_CTX *context)
{
  context->count[0] = 0;
  context->count[1] = 0;
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
}
void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len)
{
  unsigned int i = 0;
  unsigned int j = 0;

  while(j < len)
  {
    output[i] = (input[j]) |
      (input[j+1] << 8) |
      (input[j+2] << 16) |
      (input[j+3] << 24);
    i++;
    j += 4; 
  }
}
void MD5Transform(unsigned int state[4], unsigned char block[64])
{
  unsigned int a = state[0];
  unsigned int b = state[1];
  unsigned int c = state[2];
  unsigned int d = state[3];
  unsigned int x[64];

  MD5Decode(x,block,64);

  FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
  FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
  FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
  FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
  FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
  FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
  FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
  FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
  FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
  FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
  FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
  FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
  FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
  FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
  FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
  FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

  /* Round 2 */
  GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
  GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
  GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
  GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
  GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
  GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
  GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
  GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
  GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
  GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
  GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
  GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
  GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
  GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
  GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
  GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
  HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
  HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
  HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
  HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
  HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
  HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
  HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
  HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
  HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
  HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
  HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
  HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
  HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
  HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
  HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
  II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
  II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
  II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
  II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
  II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
  II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
  II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
  II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
  II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
  II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
  II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
  II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
  II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
  II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
  II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)
{
  unsigned int i = 0;
  unsigned int index = 0;
  unsigned int partlen = 0;

  index = (context->count[0] >> 3) & 0x3F;
  partlen = 64 - index;
  context->count[0] += inputlen << 3;

  if(context->count[0] < (inputlen << 3))
    context->count[1]++;
  context->count[1] += inputlen >> 29;

  if(inputlen >= partlen)
  {
    memcpy(&context->buffer[index], input,partlen);
    MD5Transform(context->state, context->buffer);

    for(i = partlen; i+64 <= inputlen; i+=64)
      MD5Transform(context->state, &input[i]);

    index = 0;        
  }  
  else
  {
    i = 0;
  }
  memcpy(&context->buffer[index], &input[i], inputlen-i);
}



void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
  unsigned int i = 0;
  unsigned int j = 0;

  while(j < len)
  {
    output[j] = input[i] & 0xFF;  
    output[j+1] = (input[i] >> 8) & 0xFF;
    output[j+2] = (input[i] >> 16) & 0xFF;
    output[j+3] = (input[i] >> 24) & 0xFF;
    i++;
    j += 4;
  }
}
void MD5Final(MD5_CTX *context, unsigned char digest[16])
{
  unsigned int index = 0,padlen = 0;
  unsigned char bits[8];

  index = (context->count[0] >> 3) & 0x3F;
  padlen = (index < 56)?(56-index):(120-index);
  MD5Encode(bits, context->count, 8);
  MD5Update(context, PADDING, padlen);
  MD5Update(context, bits, 8);
  MD5Encode(digest, context->state, 16);
}

int Compute_file_md5(const char *file_path, char *md5_str)
{
  int i;
  int fd;
  int ret;
  unsigned char data[READ_DATA_SIZE];
  unsigned char md5_value[MD5_SIZE];
  MD5_CTX md5;

  fd = open(file_path, O_RDONLY);
  if (-1 == fd)
  {
    perror("open");
    return -1;
  }

  // init md5
  MD5Init(&md5);

  while (1)
  {
    ret = read(fd, data, READ_DATA_SIZE);
    if (-1 == ret)
    {
      perror("read");
      return -1;
    }

    MD5Update(&md5, data, ret);

    if (0 == ret || ret < READ_DATA_SIZE)
    {
      break;
    }
  }

  close(fd);

  MD5Final(&md5, md5_value);

  for(i = 0; i < MD5_SIZE; i++)
  {
    snprintf(md5_str + i*2, 2+1, "%02x", md5_value[i]);
  }
  md5_str[MD5_STR_LEN] = '\0'; // add end

  return 0;
}

// MD5
//*********截止********//

//**********以下为内存映射***********//
using namespace std;
class MemShare
{
	private:
	char *mapped;// 创建的内存段指针
	int mappedsize;// 创建的内存控件大小
	public:
	int fd;// 文件指针
	struct stat sb;// 文件属性
	/** 初始化内存映射文件
	* @filename 需要映射的文件
	* @size 创建内存映射大小
	* return 1为初始化成功，0为初始化失败*/
	int initMemShare(char *filename, const int size);//初始化
	
	char *readMemContent();//获取内存映射内容
	void writeMemContent(char *content);//写入内存映射
	void relieve();//解除内存映射
};

int MemShare::initMemShare(char *filename, const int size)
{
	mappedsize = size;
	// 创建指定大小的空间
	char *buf = (char *)malloc(size);
	memset(buf, 0, size);
	// 打开需要映射到内存的文件
	if ((fd = open(filename, O_RDWR|O_CREAT,0666)) < 0)
	{
		perror("open file error");
		return 0;
	}
	
	// 设置指定大小映射空间
	write(fd, buf, size);
	
	// 将文件映射到内存
	if ((mapped =
		 (char *)mmap(NULL, size, PROT_READ |PROT_WRITE, MAP_SHARED, fd, 0)) == (void *)-1)
	{
		perror("mmap");
		return 0;
	}
	free(buf);//释放掉无用的指针
	buf = NULL;
	// 文件映射到内存后关闭
	close(fd);
	return 1;
}

char *MemShare::readMemContent()
{
	return mapped;
}

void MemShare::writeMemContent(char *content)
{
	//memset(mapped,0,sizeof(mapped));
	//memset(mapped,0,strlen(content));
	//memset(mapped,'\0',1024);
	strcpy(mapped, content);
}

void MemShare::relieve(){
	munmap(mapped, mappedsize);
}
//*************到此截止**************//


//********以下为功能结构体********//
#define BYTE0 0x00000000
#define BYTE4 0x00000004
#define BYTE8 0x00000008
#define BYTE16 0x00000010
#define BYTE24 0x00000018
#define BYTE32 0x00000020
#define BYTE64 0x00000040
#define BYTE128 0x00000080
#define BYTE256 0x00000100
#define BYTE512 0x00000200
#define BYTE1024 0x00000400
float matrix[50];
int mPid = -1;
int fd;



typedef struct {
    float x;
    float y;
    float z;
} Perspective;


typedef struct {
    float Run; //奔跑
    float Stand; //站立
    float Squat; //下蹲
    float Jump; //跳跃
} Status;


typedef struct {
    long OneWorldAdder=0x25ae00;  //世界一级地址
    long OneMatrixAdder=0x25ae00;  //一级矩阵偏移
    long OneObjectAdder=0x25ae00; //一级对象偏移
    long ZhunxinAdderX=0x25ae00; //准心x
    long ZhunxinAdderY=0x25ae00; //准心y
} Oneaddress;



typedef struct {
    char PlayerName[];  //人物名称
} Function;
//*********到此截止********//





//以下为内存读写函数//
//**************************************//

void getRoot(char **argv)
{
	char shellml[64];
	sprintf(shellml, "su -c %s", *argv);
	if (getuid() != 0)
	{
		system(shellml);
		exit(1);
	}
}

int getPid(const char *packageName)
{
    int id = -1;
	DIR *dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];
	struct dirent *entry;
    dir = opendir("/proc");
		while ((entry = readdir(dir)) != NULL)
		{
			id = atoi(entry->d_name);
			if (id != 0)
			{
				sprintf(filename, "/proc/%d/cmdline", id);
				fp = fopen(filename, "r");
				if (fp)
				{
					fgets(cmdline, sizeof(cmdline), fp);
					fclose(fp);

					if (strcmp(packageName, cmdline) == 0)
					{
						return id;
					}
				}
			}
		}
		closedir(dir);
		return -1;
	}

	// 获取so基址头部
unsigned long getModuleBase(char *moduleName)
{
		char line[1024] = "";
		FILE *p = fopen("/proc/self/maps", "r");
		int retn = -1;
		if (p)
		{
			while (fgets(line, sizeof(line), p))
			{
				if (strstr(line, moduleName) != NULL)
				{
					fclose(p);
					return strtoul(line, NULL, 16);
				}
			}
			fclose(p);
		}
		return retn;
	}

	// 读取核心函数
	int readBuffer(unsigned long off, void *buffer, int size)
	{
		struct iovec iov_ReadBuffer, iov_ReadOffset;
		iov_ReadBuffer.iov_base = buffer;
		iov_ReadBuffer.iov_len = size;
		iov_ReadOffset.iov_base = (void *)off;
		iov_ReadOffset.iov_len = size;
		return syscall(SYS_process_vm_readv, mPid, &iov_ReadBuffer, 1, &iov_ReadOffset, 1, 0);
	}

	// 写入核心函数
	int writeBuffer(unsigned long off, void *buffer, int size)
	{
		struct iovec iov_WriteBuffer, iov_WriteOffset;
		iov_WriteBuffer.iov_base = buffer;
		iov_WriteBuffer.iov_len = size;
		iov_WriteOffset.iov_base = (void *)off;
		iov_WriteOffset.iov_len = size;
		return syscall(SYS_process_vm_writev, mPid, &iov_WriteBuffer, 1, &iov_WriteOffset, 1, 0);
	}

	// 根据地址读一个int D类型
	int readInt(unsigned long address)
	{
		int value = 0;
		int *p = &value;
		readBuffer(address, p, sizeof(int));
		return value;
	}

	// 根据地址读一个float F类型
	float readFloat(unsigned long address)
	{
		float value = 0.0;
		float *p = &value;
		readBuffer(address, p, sizeof(float));
		return value;
	}

	// 根据地址读一个unsigned long int Q类型 地址类型
	unsigned long readUnsignedLong(unsigned long address)
	{
		unsigned long value = 0;
		unsigned long *p = &value;
		readBuffer(address, p, sizeof(unsigned long));
		return value;
	}

	// 写入一个数据 传地址和int D类型值
	void writeInt(unsigned long address, int value)
	{
		int *p = &value;
		writeBuffer(address, p, sizeof(int));
	}

	// 写入一个数据 传地址和float F类型值
	void writeFloat(unsigned long address, float value)
	{
		float *p = &value;
		writeBuffer(address, p, sizeof(float));
	}

	// 写入一个数据 传地址和unsigned long int Q类型值
	// 改变指针 一般用不到
	void writeUnsignedLong(unsigned long address, unsigned long value)
	{
		unsigned long *p = &value;
		writeBuffer(address, p, sizeof(unsigned long));
	}	
//*************************不需要可以将此代码块删除************************//






//********linux本地防火墙*****//
void linuxFirewall(){
    system("su -c 'iptables -F'");
	system("su -c 'iptables -A OUTPUT -p tcp -j REJECT'");
	system("su -c 'iptables -A INPUT -p tcp  -j REJECT'");
	system("su -c 'iptables -I INPUT -p tcp --sport 17500  -j ACCEPT'");
	system("su -c 'iptables -I OUTPUT -p tcp --dport 17500  -j ACCEPT'");
}
//*********截止到此*****//

//********定义address****//
void sockaddress(char *name, long size){
  
}
//*************//

int main(int argc, char *argv[]) {
   linuxFirewall();
}


