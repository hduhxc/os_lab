#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <corecrt_io.h>
#include <assert.h>

#define BLOCK_SIZE sizeof(FCB) 
#define TOTAL_SIZE 1024000 
#define END 65535
#define FREE 0
#define MAX_OPENFILE 10
#define MAX_TEXT (2 * BLOCK_SIZE)
#define FILENAME_LEN 10
#define FCB_LEN sizeof(FCB)
#define DEBUG

#define TRUNC '1'
#define OVERWRITE '2'
#define APPEND '3'
#define IS_DIR 0
#define IS_FILE 1
#define IS_LINK_FILE 2
#define VHARD_FILENAME "vhard"

#define P_BLOCK(idx) (vhard + (idx) * BLOCK_SIZE)
#define FAT1_I(idx) (((FAT*)P_BLOCK(1) + (idx))->id)
#define FAT2_I(idx) (((FAT*)P_BLOCK(3) + (idx))->id)
#define MAGIC (((Block0*)P_BLOCK(0))->magic)
#define ROOT_BLOCK (((Block0*)P_BLOCK(0))->root_block)
#define ROOT_OFF (((Block0*)P_BLOCK(0))->root_off)
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define DISPLAY_ERROR(str) printf("%s(%s) occurs an error", __FUNCTION__, str) 

typedef unsigned short uint16;
typedef unsigned long uint32;

typedef struct
{
	char filename[FILENAME_LEN];
	char attribute;
	time_t time;
	uint16 block;
	uint16 off;
	uint32 length;
} FCB;

typedef struct {
	uint16 id;
} FAT;

typedef struct
{
	char filename[FILENAME_LEN];
	char attribute;
	time_t time;
	uint16 block;
	uint16 off;
	uint32 length;
	uint16 dir_no;
	uint16 dir_off;
	char is_dirty;
	uint32 p_read;
} UserOpen;

typedef struct 
{
	char magic[8];
	uint16 root_block;
	uint16 root_off;
} Block0;

char* vhard;
UserOpen open_file_list[MAX_OPENFILE];
char path_buf[5 * FILENAME_LEN];
int cur_dir_fd;

inline char* malloc_on_stack(int len);
inline void free_on_stack(void* buf);
void __init_fcb(FCB* fcb, char* name, int block, int off, int len, int attribute);
inline void init_file(FCB* fcb, char* name, int block, int len);
inline void init_dir(FCB* fcb, char* name, int block);
inline void init_link_file(FCB* fcb, char* name, int block, int off);
int init_open_file(FCB* fcb, int dir_no, int dir_off);
void start_sys(void);
int get_fd(int dir_no, int dir_off);
int find_file(char* path, FCB* dir, FCB* file, int* dir_no, int* dir_off);
char* split_dir_file(char* path, char** dirname);
FCB* find_file_in_buf(char* buf, int len, char* filename, int* off);
int do_open(char* path);
int get_free_block(void);
void free_block_list(int block);
int get_next_k_block(int block, int k);
int get_last_block(int block);
void do_close(int fd);
inline uint16 read_from_fat(int idx);
inline void write_to_fat(int idx, uint16 block_id);
inline void read_from_disk(int id, char* buf);
inline void write_to_disk(int id, char* buf);
void do_read(FCB* file, int off, void* text, int len);
void do_write_block(int block, int off, void* text, int len);
int do_write(FCB* file, int dir_no, int dir_off, void* p_text, int len, char wstyle);
void exit_sys(void);

inline char* malloc_on_stack(int len)
{
	char* buf = (char*)_malloca(len);
	memset(buf, 0, len);
	return buf;
}

inline void free_on_stack(void* buf)
{
	_freea(buf);
}

void __init_fcb(FCB* fcb, char* name, int block, int off, int len, int attribute)
{
	strncpy(fcb->filename, name, FILENAME_LEN);
	fcb->filename[FILENAME_LEN - 1] = '\0';
	fcb->attribute = attribute;
	fcb->block = block;
	fcb->off = off;
	fcb->time = time(NULL);
	fcb->length = len;
}

inline void init_file(FCB* fcb, char* name, int block, int len)
{
	__init_fcb(fcb, name, block, 0, len, IS_FILE);
}

inline void init_dir(FCB* fcb, char* name, int block)
{
	__init_fcb(fcb, name, block, 0, 0, IS_DIR);
}

inline void init_link_file(FCB* fcb, char* name, int block, int off)
{
	__init_fcb(fcb, name, block, off, FCB_LEN, IS_LINK_FILE);
}

void my_format(void)
{
	int i;
	int root_block = 5;

	strncpy(MAGIC, "10101010", 8);
	ROOT_BLOCK = root_block;
	ROOT_OFF = 0;

	for (i = 0; i <= 5; i++) {
		FAT1_I(i) = END;
		FAT2_I(i) = END;
	}

	FCB cur, par;
	init_dir(&cur, ".", root_block);
	init_link_file(&par, "..", root_block, 0);
	do_write(&cur, root_block, 0, &cur, FCB_LEN, APPEND);
	do_write(&cur, root_block, 0, &par, FCB_LEN, APPEND);
}

int init_open_file(FCB* fcb, int dir_no, int dir_off)
{
	int fd;
	for (fd = 0; fd < MAX_OPENFILE; fd++) {
		if (!open_file_list[fd].filename[0])
			break;
	}
	if (open_file_list[fd].filename[0])
		return -1;

	UserOpen* open_file = &open_file_list[fd];
	memcpy((char*)open_file, fcb, FCB_LEN);
	open_file->dir_no = dir_no;
	open_file->dir_off = dir_off;

	return fd;
}

void start_sys(void)
{
	int is_file_valid = 1;
	FILE* vhard_file = NULL;
	vhard = (char*)calloc(TOTAL_SIZE, 1);
	
#ifndef DEBUG
	if (_access(VHARD_FILENAME, 0) == 0) {
		vhard_file = fopen(VHARD_FILENAME, "rb+");
		fread(vhard, TOTAL_SIZE, 1, vhard_file);
		if (strncmp(vhard, "10101010", 8)) {
			is_file_valid = 0;
			fclose(vhard_file);
		}
	} else
		is_file_valid = 0;
#else
	is_file_valid = 0;
#endif

	if (!is_file_valid) {
		puts("Now start to create new file system");
		vhard_file = fopen(VHARD_FILENAME, "wb+");
		my_format();
		fwrite(vhard, TOTAL_SIZE, 1, vhard_file);
	}
	fclose(vhard_file);

	FCB* root = (FCB*)P_BLOCK(ROOT_BLOCK);
	cur_dir_fd = init_open_file(root, ROOT_BLOCK, 0);
}

void my_cd(char* path)
{
	path = strcpy(path_buf, path);
	int fd = do_open(path);
	if (fd == -1 || open_file_list[fd].attribute != IS_DIR) {
		DISPLAY_ERROR(path);
		return;
	}
	if (cur_dir_fd != 0)
		do_close(cur_dir_fd);
	cur_dir_fd = fd;
}

void my_mkdir(char* path)
{
	FCB dir;
	int dir_no = 0;
	int dir_off = 0;
	char* dirname = NULL;
	char* filename = split_dir_file(path, &dirname);

	if (!find_file(dirname, NULL, &dir, &dir_no, &dir_off)) {
		puts("Invalid path");
		return;
	}

	if (find_file(filename, &dir, NULL, NULL, NULL)) {
		puts("File already exist");
		return;
	}

	FCB new_dir;
	int new_block = get_free_block();
	init_dir(&new_dir, filename, new_block);
	do_write(&dir, dir_no, dir_off, &new_dir, FCB_LEN, APPEND);
	
	FCB cur, par;
	int new_dir_off = dir.length / FCB_LEN - 1;
	init_link_file(&cur, ".", dir.block, new_dir_off);
	init_link_file(&par, "..", dir_no, dir_off);
	do_write(&new_dir, dir.block, new_dir_off, &cur, FCB_LEN, APPEND);
	do_write(&new_dir, dir.block, new_dir_off, &par, FCB_LEN, APPEND);
}

int get_fd(int dir_no, int dir_off)
{
	int i;
	for (i = 0; i < MAX_OPENFILE; i++)
		if (open_file_list[i].dir_no == dir_no
		 && open_file_list[i].dir_off == dir_off)
			return i;
	return -1;
}

void my_rmdir(char* path)
{
	FCB dir;
	int dir_no;
	int dir_off;
	char* dirname = NULL;
	char* filename = split_dir_file(path, &dirname);

	if (!find_file(dirname, NULL, &dir, &dir_no, &dir_off)) {
		puts("Invalid path");
		return;
	}

	char* buf = malloc_on_stack(dir.length);
	do_read(&dir, 0, buf, dir.length);

	int file_off;
	FCB* file = find_file_in_buf(buf, dir.length, filename, &file_off);
	if (!file || file->attribute != IS_DIR) {
		puts("Directory doesn't exist");
		return;
	}
	if (file->length > 2 * FCB_LEN) {
		puts("Directory is not empty");
		return;
	}

	int fd = get_fd(dir.block, file_off);
	if (fd != -1)
		do_close(fd);

	free_block_list(file->block);
	int dir_num = dir.length / FCB_LEN;
	FCB* last_file = (FCB*)buf + dir_num;
	for (; file < last_file - 1; file++)
		*file = *(file + 1);

	do_write(&dir, dir_no, dir_off, buf, dir.length - FCB_LEN, TRUNC);
}

void my_ls(void)
{
	FCB* file = (FCB*)&open_file_list[cur_dir_fd];
	int len = file->length;
	int file_num = len / FCB_LEN;

	char* buf = malloc_on_stack(len);
	do_read(file, 0, buf, len);
	file = (FCB*)buf;

	while (file_num--) {
		if (file->attribute == IS_DIR)
			printf("D       %s\n", file->filename);
		if (file->attribute == IS_FILE)
			printf("F %4d  %s\n", file->length, file->filename);
		if (file->attribute == IS_LINK_FILE)
			printf("L       %s\n", file->filename);
		file++;
	}
	putchar('\n');
}

/*
 * param: dir in the specific directory
 *        file, dir_no, dir_off return the FCB info
 * return: 1 file exists
 *         0 file does not exist
*/
int find_file(char* path, FCB* dir, FCB* file, int* dir_no, int* dir_off)
{
	FCB tmp_file;
	int tmp_dir_off;
	int tmp_block;
	char* p;

	p = strtok(path, "/");
	/* Path is '/' or start from '/' */
	if (!p || !*p) {
		tmp_file = *(FCB*)&open_file_list[0];
		tmp_block = tmp_file.block;
		tmp_dir_off = 0;
		p = strtok(NULL, "/");
	}  else
		tmp_file = *(FCB*)&open_file_list[cur_dir_fd];  // start from current dir
	
	if (dir)
		tmp_file = *dir;

	while (p) {
		/* If directory has already opened, use the item of open_file_list */
		if (tmp_file.block == open_file_list[0].block)
			tmp_file = *(FCB*)&open_file_list[0];
		if (tmp_file.block == open_file_list[cur_dir_fd].block)
			tmp_file = *(FCB*)&open_file_list[cur_dir_fd];

		char* buf = malloc_on_stack(tmp_file.length);
		tmp_block = tmp_file.block;
		do_read(&tmp_file, 0, buf, tmp_file.length);
		FCB* p_tmp_file = find_file_in_buf(buf, tmp_file.length, p, &tmp_dir_off);

		if (!p_tmp_file)
			return 0;
		tmp_file = *p_tmp_file;

		if (tmp_file.attribute == IS_FILE)
			break;
		/* If the file is link_file, repeat above process */
		if (tmp_file.attribute == IS_LINK_FILE) {
			tmp_block = tmp_file.block;
			tmp_dir_off = tmp_file.off;
			do_read(&tmp_file, tmp_file.off * FCB_LEN, buf, FCB_LEN);
			tmp_file = *(FCB*)buf;
		}

		p = strtok(NULL, "/");
		free_on_stack(buf);
	}

	/* Path has rest item */
	if (strtok(NULL, "/"))
		return 0;

	int fd;
	if ((fd = get_fd(tmp_block, tmp_dir_off)) != -1)
		tmp_file = *(FCB*)&open_file_list[fd];

	if (file)
		*file = tmp_file;
	if (dir_no)
		*dir_no = tmp_block;
	if (dir_off)
		*dir_off = tmp_dir_off;

	return 1;
}

char* split_dir_file(char* path, char** dirname)
{
	path = strcpy(path_buf, path);
	char* p_path = strrchr(path, '/');

	if (!p_path) {
		*dirname = ".";
		return path;
	}
	*p_path = '\0';
	*dirname = path;
	return p_path + 1;
}

/*
 * param: off return the offset of FCB
*/
FCB* find_file_in_buf(char* buf, int len, char* filename, int* off)
{
	FCB* tmp_file = (FCB*)buf;
	int file_num = len / FCB_LEN;

	for (int i = 0; i < file_num; i++, tmp_file++) {
		if (!strcmp(filename, tmp_file->filename)) {
			if (off != NULL)
				*off = i;
			return tmp_file;
		}
	}

	return NULL;
}

int my_create(char* path)
{
	FCB dir;
	int dir_no = 0;
	int dir_off = 0;
	char* dirname = NULL;
	char* filename = split_dir_file(path, &dirname);

	if (!find_file(dirname, NULL, &dir, &dir_no, &dir_off)) {
		puts("Invalid path");
		return -1;
	}

	if (find_file(filename, &dir, NULL, NULL, NULL)) {
		puts("File already exist");
		return -1;
	}

	FCB new_file;
	int new_block = get_free_block();
	init_file(&new_file, filename, new_block, 0);
	do_write(&dir, dir_no, dir_off, &new_file, FCB_LEN, APPEND);

	int fd = init_open_file(&new_file, dir.block, dir.length / FCB_LEN - 1);
	if (fd == -1) {
		puts("Maximum fd exceeded");
		return -1;
	}
	
	return fd;
}

void my_rm(char* path)
{
	FCB dir;
	int dir_no;
	int dir_off;
	char* dirname = NULL;
	char* filename = split_dir_file(path, &dirname);

	if (!find_file(dirname, NULL, &dir, &dir_no, &dir_off)) {
		puts("Invalid path");
		return;
	}

	char* buf = malloc_on_stack(dir.length);
	do_read(&dir, 0, buf, dir.length);

	int file_off;
	FCB* file = find_file_in_buf(buf, dir.length, filename, &file_off);
	if (!file || file->attribute != IS_FILE) {
		puts("File doesn't exist");
		return;
	}

	int fd = get_fd(dir.block, file_off);
	if (fd != -1)
		do_close(fd);

	free_block_list(file->block);
	int dir_num = dir.length / FCB_LEN;
	FCB* last_file = (FCB*)buf + dir_num;
	for (; file < last_file - 1; file++)
		*file = *(file + 1);

	do_write(&dir, dir_no, dir_off, buf, dir.length - FCB_LEN, TRUNC);
}

int do_open(char* path)
{
	FCB file;
	int dir_no;
	int dir_off;
	int fd;

	if (!find_file(path, NULL, &file, &dir_no, &dir_off))
		return -1;
	if ((fd = get_fd(dir_no, dir_off)) != -1)
		return fd;

	fd = init_open_file(&file, dir_no, dir_off);

	return fd;
}

int my_open(char* path)
{
	path = strcpy(path_buf, path);
	int fd = do_open(path);
	if (fd < 0 || open_file_list[fd].attribute != IS_FILE)
		DISPLAY_ERROR(path);

	return fd;
}

int get_free_block(void)
{
	int i;
	for (i = ROOT_BLOCK + 1; i < TOTAL_SIZE / BLOCK_SIZE; i++) {
		if (read_from_fat(i) == FREE) {
			char buf[BLOCK_SIZE];
			memset(buf, 0, BLOCK_SIZE);
			write_to_disk(i, buf);
			write_to_fat(i, END);
			return i;
		}
	}
	return 0;
}

void free_block_list(int block)
{
	while (block != END) {
		int next_block = read_from_fat(block);
		write_to_fat(block, END);
		block = next_block;
	}
}

int get_next_k_block(int block, int k)
{
	while (k--)
		block = read_from_fat(block);
	return block;
}

int get_last_block(int block)
{
	int tmp_block;
	while ((tmp_block = read_from_fat(block)) != END)
		block = tmp_block;
	return block;
}

void do_close(int fd)
{
	assert(fd >= 0 && fd < MAX_OPENFILE);

	if (open_file_list[fd].is_dirty) {
		FCB* file = (FCB*)&open_file_list[fd];
		int dir_no = open_file_list[fd].dir_no;
		int dir_off = open_file_list[fd].dir_off;
		
		int k = dir_off * FCB_LEN / BLOCK_SIZE;
		dir_no = get_next_k_block(dir_no, k);
		dir_off %= BLOCK_SIZE / FCB_LEN;

		do_write_block(dir_no, dir_off * FCB_LEN, (char*)file, FCB_LEN);
	}
	memset(&open_file_list[fd], 0, sizeof(UserOpen));
}

void my_close(int fd)
{
	if (fd >= MAX_OPENFILE || fd <= 0) {
		puts("Invalid file descriptor");
		return;
	}
	do_close(fd);
}

inline uint16 read_from_fat(int idx)
{
	return FAT1_I(idx);
}

inline void write_to_fat(int idx, uint16 block_id)
{
	FAT1_I(idx) = block_id;
	FAT2_I(idx) = block_id;
}

inline void read_from_disk(int id, char* buf)
{
	memcpy(buf, P_BLOCK(id), BLOCK_SIZE);
}

inline void write_to_disk(int id, char* buf)
{
	memcpy(P_BLOCK(id), buf, BLOCK_SIZE);
}
 
void do_read(FCB* file, int off, void* p_text, int len)
{
	char buf[BLOCK_SIZE];
	int block_id = file->block;
	int block_num = off / BLOCK_SIZE;
	char* text = (char*)p_text;
	block_id = get_next_k_block(block_id, block_num);
	off %= BLOCK_SIZE;

	while (block_id != END && len) {
		memset(buf, 0, BLOCK_SIZE);
		read_from_disk(block_id, buf);
		memcpy(text, buf + off, MIN(BLOCK_SIZE - off, len));
		len -= MIN(BLOCK_SIZE - off, len);
		text += MIN(BLOCK_SIZE - off, len);
		off = 0;
		block_id = read_from_fat(block_id);
	}
}

void my_read(int fd, int len)
{
	if (fd >= MAX_OPENFILE || fd <= 0) {
		puts("Invalid file descriptor");
		return;
	}

	UserOpen* file = &open_file_list[fd];
	if (!file->filename[0] || file->attribute != IS_FILE) {
		puts("Invalid file descriptor");
		return;
	}
	int off = file->p_read;
	char* buf = (char*)malloc(len + 1);
		
	do_read((FCB*)file, off, buf, len);
	buf[len] = '\0';
	file->p_read += len;
	printf("Content: %s\n", buf);

	free(buf);
}

void do_write_block(int block, int off, void* text, int len)
{
	char buf[BLOCK_SIZE];
	memset(buf, 0, BLOCK_SIZE);
	read_from_disk(block, buf);
	memcpy(buf + off, text, MIN(BLOCK_SIZE - off, len));
	write_to_disk(block, buf);
}

int do_write(FCB* file, int dir_no, int dir_off, 
			 void* p_text, int len, char wstyle)
{
	char buf[BLOCK_SIZE];
	int block_id;
	int p_read;
	int fd = get_fd(dir_no, dir_off);
	char* text = (char*)p_text;

	switch (wstyle) {
		case TRUNC: {
			block_id = file->block;
			p_read = 0;

			free_block_list(block_id);
			write_to_fat(block_id, END);
			file->length = len;
			memset(buf, 0, BLOCK_SIZE);
			break;
		}
		case OVERWRITE: {
			block_id = file->block;
			if (fd != -1)
				p_read = open_file_list[fd].p_read;
			else
				p_read = 0;

			block_id = get_next_k_block(block_id, p_read / BLOCK_SIZE);
			read_from_disk(block_id, buf);
			file->length = MAX(file->length, len);
			break;
		}
		case APPEND: {
			block_id = file->block;
			p_read = file->length;

			block_id = get_last_block(block_id);
			/* File is not empty and p_read point to the edge of a block */
			if (p_read && !(p_read % BLOCK_SIZE)) {
				int next_id = get_free_block();
				write_to_fat(block_id, next_id);
				block_id = next_id;
			}

			read_from_disk(block_id, buf);
			file->length += len;
		}
	}

	int off = p_read % BLOCK_SIZE;
	while (len) {
		memcpy(buf + off, text, MIN(len, BLOCK_SIZE - off));
		write_to_disk(block_id, buf);
		len -= MIN(len, BLOCK_SIZE - off);
		text += MIN(len, BLOCK_SIZE - off);
		off = 0;

		if (len == 0)
			break;

		if (read_from_fat(block_id) != END) {
			block_id = read_from_fat(block_id);
			read_from_disk(block_id, buf);
		} else {
			int next_id = get_free_block();
			write_to_fat(block_id, next_id);
			block_id = next_id;
		}
	}

	/* If file has been opened, write to open_file_list, otherwise write to fcb in disk */
	if (fd != -1) {
		memcpy(&open_file_list[fd], file, FCB_LEN);
		open_file_list[fd].is_dirty = 1;
		open_file_list[fd].p_read = p_read;
	} else {
		dir_no = get_next_k_block(dir_no, (dir_off * FCB_LEN) / BLOCK_SIZE);
		dir_off %= BLOCK_SIZE / FCB_LEN;
		read_from_disk(dir_no, buf);
		memcpy(buf + dir_off * FCB_LEN, file, FCB_LEN);
		write_to_disk(dir_no, buf);
	}

	return 0;
}

void my_write(int fd)
{
	if (fd >= MAX_OPENFILE || fd <= 0) {
		puts("Invalid file descriptor");
		return;
	}

	UserOpen* file = &open_file_list[fd];
	if (!file->filename[0] || file->attribute != IS_FILE) {
		puts("Invalid file descriptor");
		return;
	}

	puts("Please choose the writing style: (1)Trunc (2)Overwrite (3)Append");
	char wstyle = getchar();
	puts("Now input text, Press Ctrl+Z to end");
	getchar();

	char* str = (char*)malloc(MAX_TEXT);
	char* p_str = str;
	while (fgets(p_str, MAX_TEXT, stdin))
		p_str += strlen(p_str);
	
	do_write((FCB*)file, file->dir_no, file->dir_off, str, strlen(str), wstyle);

	free(str);
}

void exit_sys(void)
{
	do_close(0);
	do_close(cur_dir_fd);

	FILE* file;
	file = fopen(VHARD_FILENAME, "wb+");
	fwrite(vhard, TOTAL_SIZE, 1, file);
	fclose(file);

	memset(open_file_list, 0, MAX_OPENFILE * sizeof(UserOpen));
	free(vhard);
	vhard = NULL;
}
