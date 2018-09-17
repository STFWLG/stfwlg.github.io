#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct chunk_struct
{
	void *chunk;
	unsigned int chunk_size;
	char *bin;
	char *status;
};

struct chunk_struct chunk_list[10];
int chunk_count = 0;

char fastbin[] = "fastbin";
char small_bin[] = "small_bin";
char large_bin[] = "large_bin";

char status_malloc[] = "malloc";
char status_free[] = "free";
char status_double_free[] = "double_free";

void func_menu()
{
	printf(" ======================\n");
	printf("| 1. new_chunk         |\n");
	printf("| 2. edit_chunk        |\n");
	printf("| 3. chunk_list        |\n");
	printf("| 4. print_chunk       |\n");
	printf("| 5. free_chunk        |\n");
	printf("| 6. exit              |\n");
	printf(" ======================\n");
}

void func_malloc()
{
	printf("-------------------------\n");

	if(chunk_count >= 10)
	{
		printf("chunk_list is full! free chunk plz\n");
		return ;
	}

	void *chunk;
	int len;

	printf("len : 0x");
	scanf("%x", &len);

	chunk_list[chunk_count].chunk = (void *) malloc(len);
	chunk_list[chunk_count].chunk_size = ((*(unsigned int *) ((chunk_list[chunk_count].chunk) - 0x8)) & 0xfffffffffffffff0);
	if(chunk_list[chunk_count].chunk_size <= 0x200)
	{
		if(chunk_list[chunk_count].chunk_size <= 0x80)
			chunk_list[chunk_count].bin = fastbin;
		else
			chunk_list[chunk_count].bin = small_bin;
	}
	else
		chunk_list[chunk_count].bin = large_bin;
	chunk_list[chunk_count].status = status_malloc;

	printf("\nnew chunk's index : %d\n", chunk_count++);
	printf("-----------------------\n\n");
	
	return ;
}

void func_read()
{
	printf("-----------------------\n");

	int index, len;

	printf("index : ");
	scanf("%d", &index);

	if(!chunk_list[index].chunk)
	{
		printf("chunk_list[%d] is blank! plz check index\n", index);
		return ;
	}

	printf("len : 0x");
	scanf("%x", &len);

	printf("content : ");
	read(0, chunk_list[index].chunk, len);

	printf("-----------------------\n\n");

	return ;
}

void func_list()
{
	printf("-----------------------\n");
	
	for(int i = 0; i < chunk_count; i++)
	{
		printf("[%d] %p : 0x%016X (%s - %s)\n", i, chunk_list[i].chunk, chunk_list[i].chunk_size, chunk_list[i].bin, chunk_list[i].status);
	}

	printf("-----------------------\n\n");
	return ;
}

void func_print()
{
	int index;

	printf("-----------------------\n");

	printf("index : ");
	scanf("%d", &index);

	if(chunk_list[index].chunk)
	{
		for(int i = 0; i < (chunk_list[index].chunk_size/0x10) + 1; i++)
		{
			printf("%p : 0x%08X%08X 0x%08X%08X\n", (chunk_list[index].chunk - 0x10 + (0x10 * i)), (*(unsigned int *) (chunk_list[index].chunk - 0xc + (0x10 * i))), (*(unsigned int *) (chunk_list[index].chunk - 0x10 + (0x10 * i))), (*(unsigned int *) (chunk_list[index].chunk - 0x4 + (0x10 * i))), (*(unsigned int *) (chunk_list[index].chunk - 0x8 + (0x10 * i))));
		}
	}
	else
		printf("chunk_list[%d] is blank! check index plz\n", index);

	printf("-----------------------\n\n");
	return ;
}

void func_free()
{
	printf("-----------------------\n");

	char check;
	int index;

	printf("index : ");
	scanf("%d", &index);

	if(chunk_list[index].chunk)
	{
		free(chunk_list[index].chunk);
		if(chunk_list[index].status == status_malloc)
			chunk_list[index].status = status_free;
		else if(chunk_list[index].status == status_free)
			chunk_list[index].status = status_double_free;
	}
	else
		printf("chunk_list[%d] is blank! check index plz\n", index);

	printf("-----------------------\n\n");

	return ;
}

void func_exit()
{
	printf("-----------------------\n");
	exit(1);
}

int main()
{
	int menu;

	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);

	while(1)
	{
		func_menu();
		printf("menu : ");
		scanf("%d", &menu);
		printf("\n");

		switch(menu)
		{
			case 1:
				func_malloc();
				break;
		
			case 2:
				func_read();
				break;

			case 3:
				func_list();
				break;

			case 4:
				func_print();
				break;

			case 5:
				func_free();
				break;

			case 6:
				func_exit();
				break;

			default:
				printf("Invalid input :(\n\n");
		}
	}

	return 0;
}
