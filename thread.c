#include <dos.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GET_INDOS 0x34
#define GET_CRIT_ERR 0x5d06

#define FINISHED 0
#define RUNNING 1
#define READY 2
#define BLOCKED 3

#define NTCB 6
#define NBUF 3
#define TL 5
#define STACK_LEN 1024
#define NTEXT 10

#define SEND_NUM 2

#define MALLOC_STACK(len) (char*)calloc(len, 1)

typedef struct {
    int value;
    struct TCB *head;
} semaphore;

struct TCB {
    char *stack;
    unsigned ss;
    unsigned sp;
    char state;
    char name[10];
    struct TCB *next;
    struct msg_buf *msg_head;
    semaphore msg_mutex;
    semaphore msg_count;
    struct TCB* msg_ready;
} tcb[NTCB];

struct msg_buf {
    int sender;
    int size;
    char text[NTEXT];
    struct msg_buf *next;
} buf[NBUF];

struct int_regs {
    unsigned bp, di, si, ds, es, dx, cx, bx, ax, ip, cs, flags, off, seg;
};

semaphore msg_buf_mutex = { 1, NULL };
semaphore msg_buf_count = { NBUF, NULL };

typedef int (far *codeptr)(void);
void interrupt (*old_int8)(void);
/* void interrupt (*old_int23)(void); */

char far *indos_ptr = 0;
char far *crit_err_ptr = 0;

int current;
unsigned timecount;
struct msg_buf *free_buf;

void InitDos(void)
{
    union REGS regs;
    struct SREGS segregs;

    regs.h.ah = GET_INDOS;
    intdosx(&regs, &regs, &segregs);
    indos_ptr = MK_FP(segregs.es, regs.x.bx);

    if (_osmajor < 3)
        crit_err_ptr = indos_ptr + 1;
    else if (_osmajor == 3 && _osminor == 0)
        crit_err_ptr = indos_ptr - 1;
    else {
        regs.x.ax = GET_CRIT_ERR;
        intdosx(&regs, &regs, &segregs);
        crit_err_ptr = MK_FP(segregs.ds, regs.x.si);
    }
}

int DosBusy(void)
{
    if (indos_ptr && crit_err_ptr)
        return(*indos_ptr || *crit_err_ptr);
    else
        return(-1);
}

void display_thread_state(void)
{
    int i;

    puts("******************** Thread State ********************");
    for (i = 0; i < NTCB; i++) {
        printf("%s:", tcb[i].name);
        switch (tcb[i].state) {
            case READY: printf("%-13s", "Ready"); break;
            case RUNNING: printf("%-13s", "Running"); break;
            case FINISHED: printf("%-13s", "Finished"); break;
            case BLOCKED: printf("%-13s", "Blocked"); break;
        }
    }
    puts("\n******************************************************");
}

void interrupt schedule_thread(void)
{
    int i;

    while (DosBusy());

    disable();

    if (tcb[current].state != FINISHED) {
        tcb[current].ss = _SS;
        tcb[current].sp = _SP;

        if (tcb[current].state == RUNNING) {
            tcb[current].state = READY;
        }
    }

    for (i = current + 1; ; i = (i + 1) % NTCB) {
        if (tcb[i].state == READY)
            break;
    }

    _SS = tcb[i].ss;
    _SP = tcb[i].sp;
    tcb[i].state = RUNNING;

    current = i;
    timecount = 0;

#ifdef DEBUG
    puts("**Message: Thread has been scheduled");
    display_thread_state();
#endif

    enable();
}

void interrupt new_int8(void)
{
    int i;

    (*old_int8)();

    if (++timecount < TL)
        return;
    if (DosBusy())
        return;

    disable();

#ifdef DEBUG
    puts("**Message: Time out");
#endif
    if (tcb[current].state != FINISHED) {
        tcb[current].ss = _SS;
        tcb[current].sp = _SP;

        if (tcb[current].state == RUNNING) {
            tcb[current].state = READY;
        }
    }

    for (i = current + 1; ; i = (i + 1) % NTCB) {
        if (tcb[i].state == READY)
            break;
    }

    _SS = tcb[i].ss;
    _SP = tcb[i].sp;
    tcb[i].state = RUNNING;

    current = i;
    timecount = 0;

#ifdef DEBUG
    puts("**Message: Thread has been scheduled");
    display_thread_state();
#endif

    enable();
}

/*
void interrupt new_int23(void)
{
    setvect(23, old_int23);
    setvect(8, old_int8);
    (*old_int8)();
}
*/

void destroy_thread(void)
{
    disable();

    free(tcb[current].stack);
	tcb[current].stack = NULL;
	tcb[current].state = FINISHED;
	schedule_thread();

    enable();
}

int get_free_TCB(void)
{
    int i;
    for (i = 0; i < NTCB; i++) {
        if (tcb[i].state == FINISHED)
            return i;
    }
    return -1;
}

void init_TCB(int num,
              char* stack, int stack_len,
              char* name)
{
    struct int_regs far *r;

    r = (struct int_regs *)(stack + stack_len);
    r--;
    tcb[num].stack = stack;
    strcpy(tcb[num].name, name);
    tcb[num].state = READY;
    tcb[num].ss = FP_SEG(r);
    tcb[num].sp = FP_OFF(r);
    tcb[num].msg_mutex.value = 1;
    tcb[num].msg_mutex.head = NULL;
    tcb[num].msg_count.value = 0;
    tcb[num].msg_count.head = NULL;
}

void init_regs(char* stack,
               codeptr code,
               unsigned stack_len)
{
    struct int_regs far *r;

    r = (struct int_regs*)(stack + stack_len);
    r--;
    r->cs = FP_SEG(code);
    r->ip = FP_OFF(code);
    r->ds = _DS;
    r->es = _DS;
    r->flags = 0x200;
    r->seg = FP_SEG(destroy_thread);
    r->off = FP_OFF(destroy_thread);
}

int create_thread(char* name,
                  codeptr code,
                  unsigned stack_len)
{
    char *stack;
    int tcb_num;

    tcb_num = get_free_TCB();
    if (tcb_num == -1) {
        puts("**Error: There is not enough free TCB");
        return -1;
    }

    disable();

    memset(&tcb[tcb_num], 0, sizeof(struct TCB));
    stack = MALLOC_STACK(stack_len);
    init_TCB(tcb_num, stack, stack_len, name);
    init_regs(stack, code, stack_len);

    enable();

    return 0;
}

void block_thread(struct TCB **p_head)
{
    struct TCB *head;
    tcb[current].state = BLOCKED;

    if (!p_head)
        return;

    if (!*p_head) {
        *p_head = &tcb[current];
    } else {
        head = *p_head;
        while (head->next)
            head = head->next;
        head->next = &tcb[current];
    }
    schedule_thread();
}

void raise_thread(struct TCB **p_head)
{
    struct TCB *head;

    if (!p_head || !*p_head || (*p_head)->state != BLOCKED)
        return;
    head = *p_head;
    head->state = READY;
    *p_head = head->next;
    head->next = NULL;
}

void p(semaphore *sem)
{
    disable();
    sem->value = sem->value - 1;
    if (sem->value < 0) {
        block_thread(&(sem->head));
    }
    enable();
}

void v(semaphore *sem)
{
    disable();
    sem->value = sem->value + 1;
    if (sem->value <= 0) {
        raise_thread(&(sem->head));
    }
    enable();
}

void wait(struct TCB **p_head,
          semaphore *sem)
{
    disable();
    sem->value = sem->value + 1;
    if (sem->value <= 0) {
        raise_thread(&(sem->head));
    }

    block_thread(p_head);

    sem->value = sem->value - 1;
    if (sem->value < 0) {
        block_thread(&(sem->head));
    }
    enable();
}

void signal(struct TCB **p_head)
{
    raise_thread(p_head);
}

int is_thread_die(char* sender)
{
    int i;

    for (i = 0; i >= NTCB || !strcmp(tcb[i].name, sender); i++);

    if (!strcmp(tcb[i].name, sender) ||
        tcb[i].state == FINISHED) return 1;

    return 0;
}

int is_all_thread_die(void)
{
    int i;

    for (i = 1; i < NTCB; i++) {
        if (tcb[i].state != FINISHED)
            return 0;
    }
    return 1;
}

struct msg_buf *get_msg_buf(void)
{
    struct msg_buf *buf;
    buf = free_buf;
    free_buf = free_buf->next;

    return buf;
}

void ins_msg_buf(struct msg_buf **head,
                 struct msg_buf *buf)
{
    struct msg_buf *tmp;
    if (!buf)
        return;

    buf->next = NULL;
    if (!(*head)) {
        *head = buf;
    } else {
        tmp = *head;
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = buf;
    }
}

struct msg_buf *del_msg_buf(struct msg_buf **p_head,
                            int sender)
{
    struct msg_buf *node = *p_head;
    struct msg_buf *pre = node;

    while (node->next != NULL &&
           node->sender != sender) {

        pre = node;
        node = node->next;
    }
    if (node->sender != sender)
        return NULL;

    if (pre == node) {
        *p_head = node->next;
        return node;
    }

    pre->next = node->next;
    return node;
}

void send_msg(char* rev,
              char* str)
{
    struct msg_buf *buf;
    int i;

    for (i = 0; i < NTCB; i++)
        if (!strcmp(rev, tcb[i].name))
            break;

    if (strcmp(rev, tcb[i].name)) {
        puts("**Error: Receiver do not exist");
        return;
    }

    p(&msg_buf_count);
    p(&msg_buf_mutex);

    buf = get_msg_buf();
    v(&msg_buf_mutex);

    buf->sender = current;
    buf->size = strlen(str);
    buf->next = NULL;

    strcpy(buf->text, str);

    p(&tcb[i].msg_mutex);
    ins_msg_buf(&(tcb[i].msg_head), buf);
    v(&tcb[i].msg_mutex);
    v(&tcb[i].msg_count);

    signal(&tcb[i].msg_ready);
}

int receive_msg(char* sender,
                char* str)
{
    struct msg_buf *buf;

    p(&(tcb[current].msg_count));
    p(&(tcb[current].msg_mutex));
    buf = tcb[current].msg_head;

    if (sender) {
        /* 获取指定 sender 的信息 */
        while (1) {
            while (buf->next && strcmp(sender, tcb[buf->sender].name))
                buf = buf->next;
            if (!strcmp(sender, tcb[buf->sender].name))
                break;
            if (is_thread_die(sender)) {
                v(&tcb[current].msg_mutex);
                v(&tcb[current].msg_count);
                puts("**Error: Sender has finished");
                return 0;
            }
            wait(&(tcb[current].msg_ready), &(tcb[current].msg_mutex));
        }
    }
    del_msg_buf(&(tcb[current].msg_head), buf->sender);
    v(&(tcb[current].msg_mutex));

    strcpy(str, buf->text);
    memset(buf, sizeof(struct msg_buf), 0);

    p(&msg_buf_mutex);
    ins_msg_buf(&free_buf, buf);
    v(&msg_buf_mutex);
    v(&msg_buf_count);
}

void init_buf(void)
{
    int i;
    struct msg_buf *tmp;

    free_buf = buf;
    tmp = free_buf;

    for (i = 0; i < NBUF - 1; i++) {
        tmp->next = tmp + 1;
        tmp++;
    }
}

void init(void)
{
#ifdef DEBUG
    freopen("C:\\debug.txt", "w", stdout);
#endif
    init_buf();

    InitDos();
    old_int8 = getvect(8);
    /* old_int23 = getvect(23); */

    strcpy(tcb[0].name, "main");
    tcb[0].state = RUNNING;
    current = 0;
}

void delay_time(int loop)
{
    int i, j, k;

    for (i = 0; i < loop; i++)
        for (j = 0; j < loop; j++)
            for (k = 0; k < loop; k++);
}

void sender1(void)
{
    int i;
    puts("Sender1 start to run");
    delay_time(150);

    for (i = 0; i < SEND_NUM; i++) {
        send_msg("receiver1", "sender1");
        puts("Sender1 send a message to receiver1");
        send_msg("receiver2", "sender1");
        puts("Sender1 send a message to receiver2");
    }
}

void sender2(void)
{
    int i;
    puts("Sender2 start to run");
    delay_time(150);

    for (i = 0; i < SEND_NUM; i++) {
        send_msg("receiver1", "sender2");
        puts("Sender2 sent a message to receiver1");
        delay_time(150);
    }
}

void sender3(void)
{
    int i;
    puts("Sender3 start to run");
    delay_time(150);

    for (i = 0; i < SEND_NUM; i++) {
        send_msg("receiver2", "sender3");
        puts("Sender3 sent a message to receiver2");
        delay_time(150);
    }
}

void receiver1(void)
{
    int i;
    char str[NTEXT];

    puts("Receiver1 start to run");

    for (i = 0; i < 2 * SEND_NUM; i++) {
        receive_msg(NULL, str);
        printf("Receiver1 received a message: %s\n", str);
    }
}

void receiver2(void)
{
    int i;
    char str[NTEXT];

    puts("Receiver2 start to run");

    for (i = 0; i < SEND_NUM; i++) {
        receive_msg("sender1", str);
        printf("Receiver2 received a message: %s\n", str);
        receive_msg("sender3", str);
        printf("Receiver2 received a message: %s\n", str);
    }
}

int main(void)
{
    init();

    create_thread("sender1", (codeptr)sender1, STACK_LEN);
    create_thread("sender2", (codeptr)sender2, STACK_LEN);
    create_thread("sender3", (codeptr)sender3, STACK_LEN);
    create_thread("receiver1", (codeptr)receiver1, STACK_LEN);
    create_thread("receiver2", (codeptr)receiver2, STACK_LEN);

    setvect(8, new_int8);
    /* setvect(23, new_int23); */
    schedule_thread();

    while (!is_all_thread_die());
    setvect(8, old_int8);
    /* setvect(23, old_int23); */

    puts("All thread has been terminated\n");

    return 0;
}

