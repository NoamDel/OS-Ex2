
#include "uthreads.h"

#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>
#include <unordered_map>
#include <deque>
#include <queue>
#include <set>
#include <cmath>
#include <iostream>

#define SECOND_TO_MICRO 1000000
#define MIN_ARR_SIZE 0
#define MIN_QUANTUM_VAL 0
#define MIN_PRIORITY 0
#define EXIT_FAIL -1
#define EXIT_SUCCESS 0
#define MAIN_THREAD_INDEX 0


#define BLOCKED_STATE "BLOCKED"
#define READY_STATE "READY"
#define RUNNING_STATE "RUNNING"


using namespace std;
void switch_context();
int terminate_flag = -1;
bool block_flag = false;




#ifdef __x86_64__
/* code for 64 bit Intel arch */

typedef unsigned long address_t;
#define JB_SP 6
#define JB_PC 7


/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%fs:0x30,%0\n"
                 "rol    $0x11,%0\n"
    : "=g" (ret)
    : "0" (addr));
    return ret;
}


#else
/* code for 32 bit Intel arch */

typedef unsigned int address_t;
#define JB_SP 4
#define JB_PC 5

/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%gs:0x18,%0\n"
		"rol    $0x9,%0\n"
                 : "=g" (ret)
                 : "0" (addr));
    return ret;
}

#endif

/* ######################################## EXCEPTIONS: ######################################### */
#define BAD_QUANTUM_VAL "Quantum num should be non-negative integer"
#define BAD_PRIORITY_VAL "Priority should be within range of given number of threads"
#define MAX_THREADS_ERR "Cannot add new thread, max number of threads achieved"
#define ILLEGAL_POINTER "Bad pointer argument"
#define BAD_PRIORITY_ARR_SIZE "Array size must be positive"
#define ILLEGAL_BLOCK "Cannot block the main thread!"
#define UN_EXISTED_THREAD "No such thread exists"

#define SYSTEM_ERR_PREFIX "system error: "
#define INPUT_ERR_PREFIX "thread library error: "


class Thread
{
public:
    Thread(unsigned int id, unsigned int priority, void (*f)(void))
            : id(id), state(READY_STATE), priority(priority), quants_num(0),
              stack(new char[STACK_SIZE])
    {
        if (id != 0)
        {
            address_t sp, pc;
            sp = (address_t) stack + STACK_SIZE - sizeof(address_t);
            pc = (address_t) f;
            sigsetjmp(env, 1);
            (env->__jmpbuf)[JB_SP] = translate_address(sp);
            (env->__jmpbuf)[JB_PC] = translate_address(pc);
        }
        else // Main thread is already running so we just need to increase his quantoms
        {
            quants_num++;
        }
        if(sigemptyset(&env->__saved_mask))
        {
            cerr << "error!!!" << endl;
        }

    }

    ~Thread()
    {
        delete[] stack;
        stack = nullptr;
    }

    sigjmp_buf env{};
    unsigned int id;
    string state;
    unsigned int priority;
    unsigned int quants_num;
    char *stack;
};

//Globals:
unordered_map<int, Thread*> uthreads;
set<int> blocked;
deque<int> readyQueue;
vector<int> priority_to_quantum;
int running_thread_id = 0;
int totalQuants = 0;
int num_priority;
struct itimerval timer;
struct sigaction sa = {};
sigset_t signal_mask_set = {0};


int get_new_id()
{
    for (int id = 0 ; id < MAX_THREAD_NUM ; id++)
    {
        if (uthreads[id] == nullptr)
        {
            return id;
        }
    }
    return EXIT_FAIL;
}

/**
 * Runs when timer ends
 * @param sig
 */
void timer_handler(int sig)
{
    if (sig == SIGVTALRM)
    {
        switch_context();
    }
}

/**
 * Applying RR algorithm and switching between threads
 */
void switch_context()
{
    int ret_val = 0;
    if (terminate_flag == -1)
    {
        if (!block_flag)
        {
            uthreads[running_thread_id]->state = READY_STATE;
            readyQueue.push_back(running_thread_id);
        }
        block_flag = false;
        ret_val = sigsetjmp(uthreads[running_thread_id]->env, 1);
    }

    if (ret_val != 0)
    {
        if (terminate_flag != -1)
        {
            delete uthreads[terminate_flag];
            uthreads[terminate_flag] = nullptr;
            uthreads.erase(terminate_flag);
            terminate_flag = -1;
        }
        return;
    }

    if (!readyQueue.empty())
    {
        running_thread_id = readyQueue.front();
        readyQueue.pop_front();
        uthreads[running_thread_id]->state = RUNNING_STATE;
    }
    uthreads[running_thread_id]->quants_num++;
    totalQuants++;

    // Calc quantum to time in seconds and milliseconds
    int mcSeconds = priority_to_quantum[uthreads[running_thread_id]->priority];
    timer.it_value.tv_sec = mcSeconds / SECOND_TO_MICRO;
    timer.it_value.tv_usec = (mcSeconds % SECOND_TO_MICRO);
    if (setitimer(ITIMER_VIRTUAL, &timer, nullptr))
    {
        cerr << SYSTEM_ERR_PREFIX << "INVALID FUNCTION" << endl;
        exit(EXIT_FAIL);
    }

    // switch to new thread ('running_thread_id' is now the new thread):
    siglongjmp(uthreads[running_thread_id]->env, running_thread_id);
}

/**
 * Sets the timer for the first time after initializing the main thread.
 */
void set_timer(int &quantum)
{
    sa.sa_handler = &timer_handler;
    if (sigaction(SIGVTALRM, &sa, nullptr) < 0 )
    {
        cerr << SYSTEM_ERR_PREFIX << "INVALID FUNCTION CALL" << endl;
        throw;
    }

    // Calc quantum to time in seconds and milliseconds
    int mcSeconds = quantum;
    timer.it_value.tv_sec = mcSeconds / SECOND_TO_MICRO;
    timer.it_value.tv_usec = (mcSeconds % SECOND_TO_MICRO);

    if (setitimer(ITIMER_VIRTUAL, &timer, nullptr) )
    {
        cerr << SYSTEM_ERR_PREFIX << "INVALID FUNCTION CALL" << endl;
        throw;
    }
}

/**
 * This program initiate a representation of the main thread just for having him  in ready queue
 * in order to start context switching. Main thread will be missing some fields because its just a
 * representation.
 * @param priority
 */
void initiate_main_thread(int priority)
{
    totalQuants ++;
    int id = get_new_id();
    try
    {
        auto *newThread = new Thread(id, priority, nullptr);

        uthreads[priority] = newThread;
    }
    catch(bad_alloc &e)
    {
        throw(e);
    }
}

int uthread_init(int *quantum_usecs, int size)
{
    num_priority = size;
    sigaddset(&signal_mask_set, SIGVTALRM);  // Adding signal to mask whenever we need to.

    if (size <= MIN_ARR_SIZE)
    {
        cerr << INPUT_ERR_PREFIX << BAD_PRIORITY_ARR_SIZE << endl;
        return EXIT_FAIL;
    }
    else if (quantum_usecs == nullptr)
    {
        cerr << INPUT_ERR_PREFIX << ILLEGAL_POINTER << endl;
        return EXIT_FAIL;
    }

    for (int i = 0; i < MAX_THREAD_NUM; i++) // Adding priorities and id
    {
        if (i < size)
        {
            if (quantum_usecs[i] <= MIN_QUANTUM_VAL)
            {
                cerr << INPUT_ERR_PREFIX << BAD_QUANTUM_VAL << endl;
                return EXIT_FAIL;

            }
            priority_to_quantum.push_back(quantum_usecs[i]);
        }
    }

    try
    {
        initiate_main_thread(MAIN_THREAD_INDEX);
        set_timer(quantum_usecs[MAIN_THREAD_INDEX]);
    }
    catch (bad_alloc &e)
    {
        cerr << SYSTEM_ERR_PREFIX << e.what() << endl;
        exit(EXIT_FAIL);
    }
    catch (...) //That's just for an exception of set timer func, can create customized exception
    {
        exit(EXIT_FAIL);
    }
    return EXIT_SUCCESS;
}

int uthread_spawn(void (*f)(void), int priority)
{
    sigprocmask(SIG_SETMASK, &signal_mask_set, nullptr);
    if (get_new_id() == EXIT_FAIL)
    {
        cerr << INPUT_ERR_PREFIX << MAX_THREADS_ERR << endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);

        return EXIT_FAIL;
    }
    else if (priority >= num_priority || priority < MIN_PRIORITY)
    {
        cerr << INPUT_ERR_PREFIX << BAD_PRIORITY_VAL << endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);

        return EXIT_FAIL;
    }
    else if (f == nullptr)
    {
        cerr << INPUT_ERR_PREFIX << ILLEGAL_POINTER << endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);

        return EXIT_FAIL;
    }

    try
    {
        int id = get_new_id();
        auto *uthread = new Thread(id, priority, f);
        uthreads[id] = uthread;
        readyQueue.push_back(id);
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        return id;
    }
    catch (bad_alloc& e)
    {
        cerr << INPUT_ERR_PREFIX << e.what() << endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        return EXIT_FAIL;
    }

}

int uthread_change_priority(int tid, int priority)
{
    if (priority >= num_priority || priority < MIN_PRIORITY)
    {
        cerr << INPUT_ERR_PREFIX << BAD_PRIORITY_VAL <<endl;
        return EXIT_FAIL;
    }
    else if(uthreads[tid] == nullptr || uthreads.find(tid) == uthreads.end())
    {
        cerr << INPUT_ERR_PREFIX << UN_EXISTED_THREAD <<endl;
        return EXIT_FAIL;
    }
    else
    {
        uthreads[tid]->priority = priority;
    }
    return 0;
}

void delete_thread_from_queue(int tid)
{
    for (auto it = readyQueue.begin(); it != readyQueue.end(); ++it)
    {
        if (*it == tid)
        {
            readyQueue.erase(it);
            break;
        }
    }
}

/**
 * Delete all threads except the running one, delete running thread and then env.
 */
void terminate_main_thread()
{
    timer.it_value.tv_usec = 0;
    timer.it_value.tv_sec = 0;
    sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);

    for (auto & uthread : uthreads)
    {
        if (uthread.first != running_thread_id)
        {
            delete uthread.second;
            uthread.second = nullptr;
        }
    }
    delete uthreads[running_thread_id];
    uthreads[running_thread_id] = nullptr;
}

int uthread_terminate(int tid)
{
    sigprocmask(SIG_BLOCK, &signal_mask_set, nullptr);
    if (uthreads[tid] == nullptr || uthreads.find(tid) == uthreads.end())
    {
        cerr << INPUT_ERR_PREFIX << UN_EXISTED_THREAD <<endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        return EXIT_FAIL;
    }
    if (tid == MAIN_THREAD_INDEX)
    {
        terminate_main_thread();
        exit(EXIT_SUCCESS);
    }
    else if (running_thread_id == tid)
    {
        terminate_flag = tid;
        // Reset the timer because we're done with this thread, so it should not signal.
        timer.it_value.tv_usec = 0;
        timer.it_value.tv_sec = 0;
        // Un mask the set and proceed to context switch:
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        switch_context(); // Terminate shouldn't return cause the thread is gone.
    }
    else if (uthreads[tid]->state == READY_STATE)
    {
        delete_thread_from_queue(tid);
    }
    else // Thread is in BLOCK state
    {
        blocked.erase(tid);
    }
    delete uthreads[tid];
    uthreads[tid] = nullptr;
    uthreads.erase(tid);
    sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
    return EXIT_SUCCESS;
}

void block_running_thread(int tid)
{
    uthreads[tid]->state = BLOCKED_STATE;
    blocked.insert(running_thread_id);
    block_flag = true;
    // Stop the timer since this thread stops immediately and wouldn't signal.
    timer.it_value.tv_usec = 0;
    timer.it_value.tv_sec = 0;
}

int uthread_block(int tid)
{
    sigprocmask(SIG_BLOCK, &signal_mask_set, nullptr);
    if (uthreads[tid] == nullptr || uthreads.find(tid) == uthreads.end())
    {
        cerr << INPUT_ERR_PREFIX << UN_EXISTED_THREAD <<endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        return EXIT_FAIL;
    }
    else if(tid == MAIN_THREAD_INDEX)
    {
        cerr << INPUT_ERR_PREFIX << ILLEGAL_BLOCK <<endl;
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        return EXIT_FAIL;
    }
    else if (uthreads[tid]->state == BLOCKED_STATE)
    {
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        return EXIT_SUCCESS;
    }
    else if (uthreads[tid]->state == READY_STATE)
    {
        delete_thread_from_queue(tid);
    }
    else if (running_thread_id == tid )
    {
        block_running_thread(tid);
        // Unmask the set so it will not mask it in the next thread.
        sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
        switch_context();
        return EXIT_SUCCESS;
    }
    blocked.insert(tid);
    uthreads[tid]->state = BLOCKED_STATE;
    sigprocmask(SIG_UNBLOCK, &signal_mask_set, nullptr);
    return EXIT_SUCCESS;
}

int uthread_resume(int tid)
{
    if (uthreads[tid] == nullptr || uthreads.find(tid) == uthreads.end())
    {
        cerr << INPUT_ERR_PREFIX << UN_EXISTED_THREAD <<endl;
        return EXIT_FAIL;
    }
    else if (tid == running_thread_id || uthreads[tid]->state == READY_STATE)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        blocked.erase(tid);
        uthreads[tid]->state = READY_STATE;
        readyQueue.push_back(tid);
    }
    return EXIT_SUCCESS;
}

int uthread_get_tid()
{
    return running_thread_id;
}

int uthread_get_total_quantums()
{
    return totalQuants;
}

int uthread_get_quantums(int tid)

{
    if (uthreads[tid] == nullptr)
    {
        cerr << INPUT_ERR_PREFIX << UN_EXISTED_THREAD << endl;
        return EXIT_FAIL;
    }
    else if (uthreads.find(tid) == uthreads.end())
    {
        cerr << INPUT_ERR_PREFIX << UN_EXISTED_THREAD << endl;
        return EXIT_FAIL;
    }
    return (int)uthreads[tid]->quants_num;
}
