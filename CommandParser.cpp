#include "stdafx.h"
#include "CommandParser.h"
#include "Keccak.h"
#include "ParserCommon.h"
#include <cstdlib>

unsigned int hashType = 0;
unsigned int hashWidth = 512;
unsigned int shakeDigestLength = 512;
unsigned int sha3widths[] = {224, 256, 384, 512, 0};
unsigned int keccakwidths[] = {224, 256, 384, 512, 0};
unsigned int shakewidths[] = {128, 256, 0};

unsigned int bufferSize = 1024 * 100 *100;
char *buf = NULL;

int doFile(const char *fileName)
{
	if(hashType==0)
	{
		//  SHA-3
		unsigned int hashSize = hashWidth;
		keccakState *st = keccakCreate(hashSize);

		FILE *fHand = fopen(fileName, "rb");
		if(!fHand)
		{
			printf("Unable to open input file: %s\n", fileName);
			return 0;
		}
		fseek(fHand, 0, SEEK_SET);
		buf = new char[bufferSize];
		while (true)
		{
			unsigned int bytesRead = fread(buf, 1, bufferSize, fHand);

			keccakUpdate((uint8_t*)buf, 0, bytesRead, st);
			if (bytesRead < bufferSize)
			{
				break;
			}
		}
		delete[] buf;
		fclose(fHand);
		unsigned char *op = sha3Digest(st);

		printf("SHA-3-%u %s: ", hashSize, fileName);
		for(unsigned int i = 0 ; i != (hashSize/8) ; i++)
		{
			printf("%.2x", *(op++));
		}
		printf("\n");
		return 1;
	}
	else if (hashType == 1)
	{
		// Keccak
		unsigned int hashSize = hashWidth;
		keccakState *st = keccakCreate(hashSize);

		FILE *fHand = fopen(fileName, "rb");
		if (!fHand)
		{
			printf("Unable to open input file: %s\n", fileName);
			return 0;
		}
		fseek(fHand, 0, SEEK_SET);
		char *buf = new char[bufferSize];
		while (true)
		{
			unsigned int bytesRead = fread(buf, 1, bufferSize, fHand);

			keccakUpdate((uint8_t*)buf, 0, bufferSize, st);

			if (bytesRead < bufferSize)
			{
				break;
			}
		}
		delete[] buf;
		fclose(fHand);
		unsigned char *op = keccakDigest(st);

		printf("Keccak-%u %s: ", hashSize, fileName);
		for(unsigned int i = 0 ; i != (hashSize/8) ; i++)
		{
			printf("%.2x", *(op++));
		}
		printf("\n");
		return 1;
	}
	else if (hashType == 2)
	{
		// SHAKE
		unsigned int hashSize = hashWidth;
		keccakState *st = shakeCreate(hashSize, shakeDigestLength);

		FILE *fHand = fopen(fileName, "rb");
		if (!fHand)
		{
			printf("Unable to open input file: %s\n", fileName);
			return 0;
		}
		fseek(fHand, 0, SEEK_SET);
		char *buf = new char[bufferSize];
		while (true)
		{
			unsigned int bytesRead = fread(buf, 1, bufferSize, fHand);

			keccakUpdate((uint8_t*)buf, 0, bufferSize, st);

			if (bytesRead < bufferSize)
			{
				break;
			}
		}
		delete[] buf;
		fclose(fHand);
		unsigned char *op = shakeDigest(st);

		printf("SHAKE-%u %s: ", hashSize, fileName);
		for (unsigned int i = 0; i != (shakeDigestLength / 8); i++)
		{
			printf("%.2x", *(op++));
		}
		printf("\n");
		return 1;
	}
	return 0;
}


void usage()
{
	puts("\n\nUsage: sha3sum [command]* file*\n"
	"\n"
	" where command is an optional parameter that can set either the algorithm, as\n"
	" there is a slight difference between the bare keccak function and the SHA-3\n"
	" variant.\n"
	"\n" 
	" Algorithm \n"
	"\n" 
	" -a=s   :  Set algorithm to SHA-3 (default).\n"
	" -a=k   :  Set algotithm to Keccak.\n"
	" -a=h   :  Set algotithm to SHAKE.\n"
	"\n" 
	" Size\n"
	" \n"
	" -w=224 :  Set width to 224 bits.\n"
	" -w=256 :  Set width to 256 bits.\n"
	" -w=384 :  Set width to 384 bits.\n"
	" -w=512 :  Set width to 512 bits (default).\n"
	"\n"
	" Digest size (SHAKE)\n"
	"\n"
	" -d=number : Set the SHAKE digest size. Should be less than or equal to the hash size.\n"
	"		should be multiple of 8.\n"
	"       Only relevant for SHAKE - For SHA-3 and keccak, digest size is equal to sponge size.\n"
	"\n"
	"Any number of files can be specified. Files will be processed with the most\n"
	"recently specified options - for example:\n"
	"\n"
	"  sha3sum test.txt -a=k -w=384 test.txt -a=s -w=256 text.txt\n"
	"\n"
	"will hash \"test.txt\" three times - First with 512-bit SHA-3, then with 384-bit\n"
	"keccak, then finally with 256-bit SHA-3.\n");

}

int parseAlg(const char *param, const unsigned int pSize)
{
	unsigned int index = 0;
	if(param[index] == '=')
	{
		index++;
	}

	if(index + 1 == pSize)
	{
		const char algInitial = param[index];
		if(algInitial == 'k')
		{
			hashType = 1;
			return 1;
		}
		else if(algInitial == 's')
		{
			hashType = 0;
			return 1;
		}
		else if (algInitial == 'h')
		{
			hashType = 2;
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
}

int parseWidth(const char *param, const unsigned int pSize)
{
	unsigned int index = 0;
	if(param[index] == '=')
	{
		index++;
	}

	if(index+3 == pSize)
	{
		if(strncmp(&param[index], "224", pSize-index)==0)
		{
			hashWidth = 224;
			return 1;
		}
		else if(strncmp(&param[index], "256", pSize-index)==0)
		{
			hashWidth = 256;
			return 1;	
		}
		else if(strncmp(&param[index], "384", pSize-index)==0)
		{
			hashWidth = 384;
			return 1;
		}
		else if(strncmp(&param[index], "512", pSize-index)==0)
		{
			hashWidth = 512;
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

}

int parseDigestWidth(const char *param, const unsigned int pSize)
{
	unsigned int index = 0;
	if (param[index] == '=')
	{
		index++;
	}

	if (index + 3 == pSize)
	{
		unsigned int sdl = atoun(&param[index], pSize-index);
		if (sdl % 8 != 0)
		{
			fprintf(stderr, "Error - param: %s is not divisible by 8.\n", param);
			return 0;
		}
		if (sdl > hashWidth)
		{
			fprintf(stderr, "Error - param: %s is greater than the hash size.\n", param);
			return 0;
		}
		shakeDigestLength = sdl;
		return 1;
	}
	else
	{
		return 0;
	}

}

int parseOption(const char *param, const unsigned int pSize)
{
	unsigned int index = 1;

	if(index != pSize)
	{
		const char commandInitial = param[index];
		if(commandInitial == 'h')
		{
			if((index + 1) == pSize)
			{
				usage();
				return 0;
			}
			else
			{
				return 0;
			}
		}
		else if(commandInitial == 'a')
		{
			return parseAlg(&param[index+1], pSize-(index+1));	
		}
		else if(commandInitial == 'w')
		{
			return parseWidth(&param[index+1], pSize-(index+1));
		}
		else if (commandInitial == 'd')
		{
			return parseDigestWidth(&param[index + 1], pSize - (index + 1));
		}
		else
		{
			return 0;	
		}
	}
	else 
	{
		return 0;
	}
}

void parseParameter(const char *param)
{
	unsigned int index = 0;
	unsigned int paramSize = 0;

	paramSize = strlen(param);

	// Eat leading whitespace
	for(unsigned int i = index ; i != paramSize ; i++)
	{
		const char posI = param[i];
		if((posI != ' ') && (posI != '\t'))
		{
			index = i;
			break;
		}
	}

	if(index != paramSize)
	{
		if(param[index] != '-')
		{
			doFile(&param[index]);
		}
		else
		{
			parseOption(&param[index], paramSize-index);	
		}
	}
}

void parseCommandLine(const int argc, char* argv[])
{
	if(argc > 1)
	{
		for(unsigned int i = 1 ; i != argc ; i++)
		{
			parseParameter(argv[i]);
		}	
	}
}
