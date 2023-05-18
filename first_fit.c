#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "此文件不是为了演示某种攻击方式，但他表现了glibc内存分配器的某种性质。\n");
	fprintf(stderr, "glibc 使用第一拟合算法(first-fit算法)来选择一个被释放的块。\n");
	fprintf(stderr, "如果一个chunk是空闲的并且足够大，malloc将选择这个块。\n");
	fprintf(stderr, "这会引起一种叫做use-after-free(uaf，释放后重用)的漏洞\n");

	fprintf(stderr, "分配两个缓冲区，因为他们足够大，所以不会被装入fastbin中\n");
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	fprintf(stderr, "第一次调用malloc(0x512)返回的地址: %p\n", a);
	fprintf(stderr, "第二次调用malloc(0x256)返回的地址: %p\n", b);
	fprintf(stderr, "我们可以在这里继续分配...\n");
	fprintf(stderr, "现在让我们在a写入一个我们以后可以读取的字符串， \"this is A!\"\n");
	strcpy(a, "this is A!");
	fprintf(stderr, "第一次分配的地址是: %p 中的内容是: %s \n", a, a);

	fprintf(stderr, "现在释放掉第一个chunk...\n");
	free(a);

	fprintf(stderr, "我们不需要再释放任何chunk。只要我们的分配小于0x512，它最终将分配到 %p\n", a);

	fprintf(stderr, "所以，让我们分配0x500字节\n");
	c = malloc(0x500);
	fprintf(stderr, "第三次调用malloc(0x500)返回的地址: %p\n", c);
	fprintf(stderr, "然后我们在c写入一个不同的字符串, \"this is C!\"\n");
	strcpy(c, "this is C!");
	fprintf(stderr, "第三次分配的地址是: %p 内容是: %s \n", c, c);
	fprintf(stderr, "第一次分配的地址是: %p 内容是: %s \n", a, a);
	fprintf(stderr, "如果我们重用第一次malloc返回的地址，会发现他和第三次malloc返回的地址相同。\n");
}
