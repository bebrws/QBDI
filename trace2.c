#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h> 
#include <errno.h>

#include "QBDI.h"
#include "QBDIPreload.h"
#include "QBDI/Callback.h"

#include "gummodulemap.h"

#include "list.h"

#include "map.h"

#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach/task_info.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>
#include <mach/task_info.h>
// borrowed from Breakpad
// Fallback declarations for TASK_DYLD_INFO and friends, introduced in
// <mach/task_info.h> in the Mac OS X 10.6 SDK.
#define TASK_DYLD_INFO 17
// in  #include <mach/task_info.h>
// struct task_dyld_info {
//     mach_vm_address_t all_image_info_addr;
//     mach_vm_size_t all_image_info_size;
//   };
typedef struct task_dyld_info task_dyld_info_data_t;
typedef struct task_dyld_info *task_dyld_info_t;
#define TASK_DYLD_INFO_COUNT (sizeof(task_dyld_info_data_t) / sizeof(natural_t))

typedef struct mach_header_64 platform_mach_header;
typedef struct segment_command_64 mach_segment_command_type;
#define MACHO_MAGIC_NUMBER MH_MAGIC_64
#define CMD_SEGMENT LC_SEGMENT_64
#define seg_size uint64_t

struct __attribute__((packed)) drcov_bb {
    uint32_t start;
    uint16_t size;
    uint16_t id;
};

typedef struct {
  struct drcov_bb bb;
  struct list bblist;
} bb_wrapper;

typedef struct {
  const char * path;
  unsigned long long start;
  unsigned long long end;
  struct list mlist;
} dyld_module;

map_int_t m;

// Linux Kernel List
// https://medium.com/@414apache/kernel-data-structures-linkedlist-b13e4f8de4bf
struct list modules;
struct list bbs;

size_t infoCount = 0;
unsigned long bb_count = 0;

// using namespace QBDI;

QBDIPRELOAD_INIT;

#define MAX_HEADER_SIZE 1024*1024 

char drcov_header[MAX_HEADER_SIZE];


void write_trace_file() {
  FILE *fp;
  fp = fopen("trace.cov", "w");
  // NOTE: I Could write out markers or something on each control C
  // I can run:
  // install_default();
  // To reinstore the original signal handler and exit the running process on control c
  fprintf(fp, "DRCOV VERSION: 2\n");
  fprintf(fp, "DRCOV FLAVOR: drcov\n");
  fprintf(fp, "Module Table: version 2, count %d\n", infoCount);
  fprintf(fp,"Columns: id, base, end, entry, checksum, timestamp, path\n"); 

  int i = 0;
  int column_wdith = (infoCount == 0) ? 1  : (log10(infoCount) + 1);
  dyld_module *cur_module;
  list_for_each_entry(&modules, cur_module, mlist) {
    // printf("%*d, 0x%llx, 0x%llx, 0x0000000000000000, 0x00000000, 0x00000000, %s\n", column_wdith, i, cur_module->start, cur_module->end, cur_module->path);
    fprintf(fp, "%2d, 0x%llx, 0x%llx, 0x0000000000000000, 0x00000000, 0x00000000, %s\n", i, cur_module->start, cur_module->end, cur_module->path);
    // context.m_trace->write_string("%2u, %p, %p, 0x0000000000000000, 0x00000000, 0x00000000, %s\n",
    i += 1;
  }

  fprintf(fp, "BB Table: %lu bbs\n", bb_count);
  // context.m_trace->write_string("BB Table: %u bbs\n", number_of_bbs);
  bb_wrapper *cur_bb;
  list_for_each_entry(&bbs, cur_bb, bblist) {
    // the module id (i from above) that the IP lands in
    // the address of the IP - the image address - So offset into this module/image
    // The size of the image
    fwrite(&cur_bb->bb, sizeof(struct drcov_bb), 1, fp);
    // printf("%d 0x%llx 0x%llx", cur_bb->bb.id, cur_bb->bb.start, cur_bb->bb.size);
    printf("id:%d start:%x size:%d \n", cur_bb->bb.id, cur_bb->bb.start, cur_bb->bb.size);
  }

  printf("Successfully wrote trace.cov");
}


static void catch_sigint(int signum)
{
    write_trace_file();
    exit(0);
    install_default();
}

int install_sigint(void)
{
    struct sigaction  act;

    memset(&act, 0, sizeof act);
    sigemptyset(&act.sa_mask);

    act.sa_handler = catch_sigint;
    act.sa_flags = 0;

    if (sigaction(SIGINT, &act, NULL) == -1)
        return errno;

    return 0;
}

int install_default()
{
    struct sigaction  act;

    memset(&act, 0, sizeof act);
    sigemptyset(&act.sa_mask);

    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;

    if (sigaction(SIGINT, &act, NULL) == -1)
        return errno;

    return 0;
}


static VMAction onInstructionCB(VMInstanceRef vm, GPRState *gprState, FPRState *fprState, void *data) {
    const InstAnalysis* instAnalysis = qbdi_getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY | QBDI_ANALYSIS_SYMBOL);
    // if (instAnalysis->symbol != NULL) {
    //     printf("%20s+%05u\t", instAnalysis->symbol, instAnalysis->symbolOffset);
    // } else {
    //     printf("%26s\t", "");
    // }
    // printf("0x%" PRIRWORD " %s size: %d\n", instAnalysis->address, instAnalysis->disassembly, instAnalysis->instSize);

    uint64_t addr = instAnalysis->address;

    char addr_key[32];
    snprintf(addr_key, 32,"%llx",addr);

    // printf("using key %s\n", addr_key);
    int *val = map_get(&m, addr_key);

    if (!val) {
      int module_found = -1;
      int which_module = 0;
      dyld_module *cur_module;
      list_for_each_entry(&modules, cur_module, mlist) {
        if (addr >= cur_module->start && addr <= cur_module->end) {
          module_found = which_module;
          break;
        }
        which_module += 1;
      }

      if (module_found != -1) {
        bb_wrapper *bbw = malloc(sizeof(bb_wrapper));
        bbw->bb.id = (uint16_t)module_found;
        bbw->bb.start = (uint32_t)(addr - cur_module->start);
        bbw->bb.size = instAnalysis->instSize;
        
        list_add(&bbs, &bbw->bblist);
        map_set(&m, addr_key, 1);
        bb_count += 1;      
      }
    }

    return QBDI_CONTINUE;
}


int qbdipreload_on_start(void *main) {
    return QBDIPRELOAD_NOT_HANDLED;
}


int qbdipreload_on_premain(void *gprCtx, void *fpuCtx) {
    return QBDIPRELOAD_NOT_HANDLED;
}

size_t size_of_image(struct mach_header_64 *header) {
    size_t sz = 0;
    // size_t sz = sizeof(*header); // Size of the header
    // sz += header->sizeofcmds;    // Size of the load commands

    struct load_command *lc = (struct load_command *) (header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 s;
            mach_segment_command_type *seg = (mach_segment_command_type *)lc;
            if (!strcmp(seg->segname, "__TEXT")) {
              sz = seg->vmsize;
            }
            
        }
        lc = (struct load_command *) ((char *) lc + lc->cmdsize);
    }
    return sz;
}

int qbdipreload_on_main(int argc, char** argv) {

  map_init(&m);

  list_init(&modules);
  list_init(&bbs);
  install_sigint();
  
  task_dyld_info_data_t task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  if (task_info(mach_task_self (), TASK_DYLD_INFO, (task_info_t)&task_dyld_info,
                &count) != KERN_SUCCESS) {
    printf("Unable to get task info\n");
    return QBDIPRELOAD_NOT_HANDLED;
  }

  struct dyld_all_image_infos* aii = (struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
  infoCount = aii->infoArrayCount;

  // Iterate through all dyld images (loaded libraries) to get their names
  // and offests.
  for (size_t i = 0; i < infoCount; ++i) {
    const struct dyld_image_info *info = &aii->infoArray[i];

    // If the magic number doesn't match then go no further
    // since we're not pointing to where we think we are.
    if (info->imageLoadAddress->magic != MACHO_MAGIC_NUMBER) {
      continue;
    }

    platform_mach_header* header = (platform_mach_header *)info->imageLoadAddress;
    
    size_t image_size = size_of_image(header);
    unsigned long long header_end = (unsigned long long)header + image_size;

    dyld_module *mod;
    mod = malloc(sizeof(dyld_module));
    mod->path = info->imageFilePath;
    mod->start = header;
    mod->end = header_end - 1; // TODO: Is this necessary?

    printf("%*d, 0x%llx, 0x%llx, 0x0000000000000000, 0x00000000, 0x00000000, %s\n", 2, i, header, header_end, info->imageFilePath);

    list_add(&modules, &mod->mlist);
  }    
    
    return QBDIPRELOAD_NOT_HANDLED;
}

// VMState :
// typedef struct {
//     VMEvent event;           /*!< The event(s) which triggered the callback (must be checked using a mask: event & BASIC_BLOCK_ENTRY).*/
//     rword basicBlockStart;   /*!< The current basic block start address which can also be the execution transfer destination.*/
//     rword basicBlockEnd;     /*!< The current basic block end address which can also be the execution transfer destination.*/
//     rword sequenceStart;     /*!< The current sequence start address which can also be the execution transfer destination.*/
//     rword sequenceEnd;       /*!< The current sequence end address which can also be the execution transfer destination.*/
//     rword lastSignal;        /*!< Not implemented.*/
// } VMState;
//
VMAction onEventCB(VMInstanceRef vm, const VMState *state, GPRState *gprState, FPRState *fprState, void *data) {
    uint64_t addr = state->basicBlockStart;

    char addr_key[32];
    snprintf(addr_key, 32,"%llx",addr);

    // printf("using key %s\n", addr_key);
    int *val = map_get(&m, addr_key);

    if (!val) {
      int module_found = -1;
      int which_module = 0;
      dyld_module *cur_module;
      list_for_each_entry(&modules, cur_module, mlist) {
        if (addr >= cur_module->start && addr <= cur_module->end) {
          module_found = which_module;
          break;
        }
        which_module += 1;
      }

      if (module_found != -1) {
        bb_wrapper *bbw = malloc(sizeof(bb_wrapper));
        bbw->bb.id = (uint16_t)module_found;
        bbw->bb.start = (uint32_t)(addr - cur_module->start);
        bbw->bb.size = state->basicBlockEnd - state->basicBlockStart;
        
        list_add(&bbs, &bbw->bblist);
        map_set(&m, addr_key, 1);
        bb_count += 1;      
      }
    }

    return QBDI_CONTINUE;  
}

int qbdipreload_on_run(VMInstanceRef vm, rword start, rword stop) {
    // qbdi_addCodeCB(vm, QBDI_PREINST, onInstructionCB, NULL);
    qbdi_addVMEventCB(vm, _QBDI_EI(BASIC_BLOCK_ENTRY), onEventCB, NULL);
    qbdi_run(vm, start, stop);
    return QBDIPRELOAD_NO_ERROR;
}


int qbdipreload_on_exit(int status) {
    printf("On exit of coverage tracer\n");
    write_trace_file();
    return QBDIPRELOAD_NO_ERROR;
}
