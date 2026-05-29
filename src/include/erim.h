/*
 * erim.h
 *
 * Defines interface to isolate secrets using ERIM. Applications are
 * split into a trusted component (tc) and an untrusted application
 * (app). To transfer between the two compartments, one has to
 * explicitly call a switch. The interface offers two ways to insert
 * these switches, inlined or overlayed. Inlined provides the
 * interface to inline the switches using erim_switch_to_isolated and
 * erim_switch_to_application. Whereas overlayed, provides the
 * interface to wrap entire functions with switch code and provide a
 * defines to make functions calls including the switch code.
 *
 * Lifecycle of ERIMized Application:
 *   During compilation:
 *     - Insert where necessary switches between application and
 *       tc
 *     - Insert initliazation code somewhere before application start
 *       -> e.g. via DL_PRELOAD
 *
 * Arguments to this header file:
 * ERIM_DBG -> 0, 1 (default 0)
 *  Adds print statements to switch calls and initilization code
 *
 * ERIM_STATS -> 0, 1 (default 0)
 *  Adds code to count the number of switches in a global variable
 *  Print counter by calling print_****
 *
 * ERIM_INTEGRITY_ONLY -> defined, undefined (default undefined)
 *  If defined, assures that untrusted application may read the memory
 *  of the tc.
 *  If undefined, assures that the untrusted application may never
 *  read or write the tc.
 *  (providing confidentiality and integrity)
 *
 * ERIM_ISOLATE_UNTRUSTED -> defined, undefined (default undefined) 
 *  If defined, trusted runs in domain 0. (application runs in domain 1)
 *  If undefined, trusted runs in domain 1. (application runs in
 *  domain 0) Without changes everything runs in domain 0 including
 *  libc. When the tc needs to take control over libc, it also needs
 *  to run in domain 0. When the tc only protects a small and
 *  limited set of functions which do not require libc access
 *  (e.g. the cryptographic functions of OpenSSL), then the tc can
 *  run in domain 1 without chainging the app.
 *
 * SIMULATE_PKRU -> defined, undefined (default undefined
 *  If defined, emulates the cost of WRPKRU instruction
 *  If undefined, uses RD/WRPKRU
 */

 #ifndef ERIM_H_
 #define ERIM_H_

 #include <vector>
 
 //#define ERIM_DBG
   
 /*
  * ERIM stats
  */

 /*
  * Initilization and Finalization functions of ERIM
  */
 

 #define ERIM_FLAG_ISOLATE_TRUSTED    (1<<0)
 #define ERIM_FLAG_ISOLATE_UNTRUSTED  (1<<1)
 #define ERIM_FLAG_INTEGRITY_ONLY     (1<<2)
 #define ERIM_FLAG_SWAP_STACK      (1<<3)
 
 #define ERIM_TRUSTED_DOMAIN_ID(flag) ((flag & ERIM_FLAG_ISOLATE_TRUSTED) ? 1 : 0)
 #define ERIM_UNTRUSTED_DOMAIN_ID(flag) ((flag & ERIM_FLAG_ISOLATE_TRUSTED) ? 0 : 1)

 #define uint8ptr(ptr) ((uint8_t *)ptr)
  
#define erim_isWRPKRU(ptr)				\
  ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0x01	\
   && uint8ptr(ptr)[2] == 0xef)?			\
  1 : 0)

#define erim_isXRSTOR(ptr) \
   ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0xae \
    && (uint8ptr(ptr)[2] & 0xC0) != 0xC0 \
    && (uint8ptr(ptr)[2] & 0x38) == 0x28) ? 1 : 0)
  
#define erim_isWRGSBASE32(ptr) \
   ((uint8ptr(ptr)[0] == 0xf3 && uint8ptr(ptr)[1] == 0x0f \
    && uint8ptr(ptr)[2] == 0xae \
    && (uint8ptr(ptr)[3]&0xf8) == 0xd8) \
    ? 1 : 0)

#define erim_isWRGSBASE64(ptr) \
   ((uint8ptr(ptr)[0] == 0xf3 && (uint8ptr(ptr)[1]&0xf0) == 0x40 \
    && uint8ptr(ptr)[2] == 0x0f \
    && uint8ptr(ptr)[3] == 0xae \
    && (uint8ptr(ptr)[4]&0xf8) == 0xd8) \
    ? 1 : 0)
  
#define ERIM_TRUSTED_PKRU (0x55555550)
   
int erim_init(unsigned long long shmemSize, int flags);
struct unsafe_page* erim_memScanRegion(char * start,
                unsigned long long length, unsigned long long * whitelist,
                unsigned int wlEntries,
                int perm, int unsafe_perm, bool trusted_page, char** prev_page_ptr);
int erim_fini(void);
struct unsafe_page* add_unsafe_page(void* address, int current_perm, int desired_perm, bool trusted_page, std::vector<char*>* unsafe_instructions);
struct unsafe_page* add_unsafe_page_locked(void* address, int current_perm, int desired_perm, bool trusted_page, std::vector<char*>* unsafe_instructions);
struct unsafe_page* update_unsafe_page(void* address, int current_perm, int desired_perm, bool trusted_page, std::vector<char*>* unsafe_instructions);
struct unsafe_page* find_unsafe_page(void* address);
void set_page_non_executable(void* address);
 
struct unsafe_page{
   void* address;
   
   bool trusted_page;

   //keep track of the page permissions in case it should be write&exec
   int current_perm;
   int desired_perm;
   
   std::vector<char*>* unsafe_instructions;
   int unsafe_instructions_size;
};

struct unsafe_page_list{
   std::vector<struct unsafe_page*> list = {};
   int size = 0;
};

enum scan_state {
   FIRST,
   MID,
   LAST,
   ONLY
};

 
 #endif /* ERIM_H_ */