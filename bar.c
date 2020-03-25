#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <errno.h>

#define Archive_PATH ""
#define wb 1
#define rb 2

FILE *fopen_with_path(const char* path, int type)
{
FILE *fp = NULL;

	char buffer[1024];
	sprintf(buffer, "%s%s", Archive_PATH, path);
		if(type == 1)
			fp=fopen(buffer,"wb");
		else if (type == 2)
			fp=fopen(buffer,"rb");

		return fp;
}

typedef struct {
    uint8_t signature[0x20];
} caf_header_signature_t;
//32

typedef struct {
    uint64_t index;
    uint8_t signature[0x20];
    uint64_t padding;
} caf_segment_signature_t;
//48

typedef struct {
    uint64_t index;
    uint64_t data_offset;
    uint64_t data_size_with_padding;
    uint64_t algorithm;
    uint64_t cipher_key_index;
    uint8_t cipher_seed[0x10];
    uint64_t data_size_without_padding;
} caf_segment_table_t;
//64

typedef struct {
    uint8_t magic[8];
    uint64_t version;
    uint64_t hasher_key_index;
    uint64_t num_segments;
    uint64_t file_offset;
    uint64_t file_size;
} caf_header_t;
//48

static const uint8_t sbl_bar_hash_key[32] = {
	0x1f, 0x18, 0xc9, 0x70, 0xd0, 0x00, 0xac, 0x7e, 
	0x6f, 0xcc, 0x1a, 0x8c, 0xdd, 0x89, 0xb4, 0xfe, 
	0xcd, 0xa1, 0x33, 0xa1, 0x0e, 0xc8, 0xf5, 0x25,
	0x98, 0x22, 0x23, 0xf5, 0x86, 0x1f, 0x02, 0x00
};

static const uint8_t sbl_bar_cipher_key[16] = {
    0x79, 0xc8, 0xcc, 0xc8, 0x89, 0xa1, 0x54, 0x0d,
    0x4f, 0x2e, 0x27, 0xbb, 0x61, 0x4f, 0xd6, 0x53
};

#define MAX_SEG_SIZE 4294901760

int last_open = -1;
FILE* f_last_open = NULL;
FILE* getArchive(uint64_t offset)
{
	char* name;
	int number = floor(offset / MAX_SEG_SIZE);

	if(number == last_open)
		return f_last_open;
	else if(last_open  != -1)
                     fclose(f_last_open);

	if(number == 0)
	{
		name = (char*) malloc(13);
		strcpy(name, "archive.dat");
	}
	else
	{
		name = (char*) malloc(17);
		sprintf(name, "archive%04d.dat", number);
	}
	fprintf(stderr, "reading %s\n", name);
	f_last_open = fopen_with_path(name, rb);
        last_open = number;
	free(name);


	return f_last_open;
}

unsigned char* hmac_sha256(const void *key, int keylen,
                           const unsigned char *data, int datalen,
                           unsigned char *result, unsigned int* resultlen)
{
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

void hexDump(const void *data, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    printf("%02hhX%c", ((char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
  }
  printf("\n");
}
char  folder[1024];

int main(int argc, char** argv){
FILE* fp = fopen_with_path("archive.dat", rb);
	printf("trying to open %sarchive.dat\n", Archive_PATH);
sprintf(folder, "%s/blobs", Archive_PATH);
if(fp != NULL)
{
	fseeko(fp,0,SEEK_SET);
	unsigned char buf[48] = {0};
	fread(buf,48,1,fp);
	caf_header_t* hdr = (caf_header_t*)buf;
	printf("Number of Entries:%lx\n",hdr->num_segments);
	uint64_t i=0;
	
	FILE *fl = NULL;
int ret = mkdir(folder, 0777);
	for(i=0;i<hdr->num_segments;i++){
		uint8_t* name = (uint8_t*) malloc(10 + 3);
if(ret == -1)
	sprintf(name, "blob%lx.bin", i);
else if(ret == 0)
printf("folder %s\n", folder);
      sprintf(name, "/blobs/blob%lx.bin", i);

		FILE *blob = fopen_with_path(name, wb);
if (blob != NULL)
{
		uint8_t buf2[64] = {0};
		fseeko(fp,48+(64*i),SEEK_SET);
		fread(buf2,64,1,fp);
		caf_segment_table_t * seg = (caf_segment_table_t *) buf2;
		
		fl = getArchive(seg->data_offset);
if (fl != NULL)
{
		fseeko(fl,seg->data_offset % MAX_SEG_SIZE,SEEK_SET);
		
		uint8_t *buf3 = (uint8_t*) malloc (seg->data_size_without_padding);
		fread(buf3, seg->data_size_without_padding, 1,fl);
		
		//HASHER
		//skipping this
		/*
		uint8_t md[0x20] = {0};
		int resultlen = 0x20;
		uint8_t buf4[48] = {0};
		fseeko(fp,48+(64*hdr->num_segments)+(48*i),SEEK_SET);
		fread(buf4,48,1,fp);
		caf_segment_signature_t * sig = (caf_segment_signature_t *) buf4;
		hmac_sha256(sbl_bar_hash_key,0x20,buf3,seg->data_size_without_padding,md,&resultlen);
		if(memcmp(md,sig->signature,0x20)==0){
			//printf("match \n");
		}else{
			hexDump(sig->signature,0x20);
		}*/
		
		
		//CIPHER
		AES_KEY ctx;
		AES_set_decrypt_key(sbl_bar_cipher_key,0x80,&ctx);
		AES_cbc_encrypt(buf3,buf3,seg->data_size_without_padding,&ctx,seg->cipher_seed,AES_DECRYPT);
		printf("writing data offset %08X, data size without padding %08X\n",seg->data_offset,seg->data_size_without_padding);
		fwrite(buf3, seg->data_size_without_padding, 1,blob);
		printf("write data offset %08X, data size without padding %08X done\n",seg->data_offset,seg->data_size_without_padding);
		free(buf3);
		fclose(blob);
		free(name);
}

else
{
printf("fopen f1 error %s\n", strerror(errno));
exit(0);
}
}
else
{
printf("fopen BLOB error %s\n", strerror(errno));
exit(0);
}

}
fclose(fl);	
}
else
{
printf("fopen Archive error %s\n", strerror(errno));
exit(0);
}
	
	//let's skip this as well
	//HEADER HASHER
	/*
	fseeko(fp,48+(64*hdr->num_segments)+(48*hdr->num_segments),SEEK_SET);
	uint64_t header_size=ftello(fp);
	fseeko(fp,0,SEEK_SET);
	uint8_t *buf5 = (uint8_t *) malloc(header_size);
	fread(buf5,header_size,1,fp);
	uint8_t md2[0x20] = {0};
	int resultlen2 = 0x20;
	hmac_sha256(sbl_bar_hash_key,0x20,buf5,header_size,md2,&resultlen2);
	uint8_t header_hash[0x20]={0};
	fseeko(fp,48+(64*hdr->num_segments)+(48*hdr->num_segments),SEEK_SET);
	fread(header_hash,0x20,1,fp);
	
	if(memcmp(header_hash,md2,0x20)==0){
		//printf("header_hash match\n");
	}
	*/

	
	return 0;
}

