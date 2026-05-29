/*
 * erim.c
 *
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include "erim.h"
#include "mpk_isolation.h"
#include "virt_page_manager.h"
#include <assert.h>
#include "nolibc_util.h"
#include <mutex>
#include <algorithm>


#define TYPE_WRPKRU 1
#define TYPE_XRSTOR 2
#define TYPE_WRGSBASE 3

//TODO currently pages are never removed, only updated. remove them when they are unmapped to prevent memory leaks?
//TODO erim mutex?
unsafe_page_list unsafe_pages;
extern virt_page_manager page_manager;

struct unsafe_page* add_unsafe_page(void* address, int current_perm, int desired_perm, bool trusted_page, std::vector<char*>* unsafe_instructions){
  struct unsafe_page* updated_page = update_unsafe_page(address, current_perm, desired_perm, trusted_page, unsafe_instructions);
  if(updated_page != NULL) return updated_page;
  struct unsafe_page* new_page = (unsafe_page*)calloc(1, sizeof(unsafe_page));
  assert(new_page != NULL);
  new_page->address = address;
  new_page->current_perm = current_perm;
  new_page->desired_perm = desired_perm;
  new_page->trusted_page = trusted_page;
  new_page->unsafe_instructions = unsafe_instructions;
  if(unsafe_instructions != NULL){
    new_page->unsafe_instructions_size = unsafe_instructions->size();
  }else{
    new_page->unsafe_instructions_size = 0;
  }
  //printf("new page: %p\n", new_page->address);
  unsafe_pages.list.push_back(new_page);
  unsafe_pages.size++;
  return new_page;
}

//returns the index in the vector if the unsafe_page existed and -1 otherwise
struct unsafe_page* update_unsafe_page(void* address, int current_perm, int desired_perm, bool trusted_page, std::vector<char*>* unsafe_instructions){
  if(unsafe_pages.size==0) return NULL;
  size_t i = 0;
  while(unsafe_pages.list[i]->address != address){
    i++;
    if(i>=unsafe_pages.size)return NULL;
  }
  unsafe_pages.list[i]->address = address;
  unsafe_pages.list[i]->current_perm = current_perm;
  unsafe_pages.list[i]->desired_perm = desired_perm;
  unsafe_pages.list[i]->trusted_page = trusted_page;

  free(unsafe_pages.list[i]->unsafe_instructions);
  
  unsafe_pages.list[i]->unsafe_instructions = unsafe_instructions;
  unsafe_pages.list[i]->unsafe_instructions_size = unsafe_instructions->size();
  return unsafe_pages.list[i];
}

static int update_unsafe_instruction(char* address, char* instruction, int current_perm, int desired_perm, bool trusted_page){
  struct unsafe_page* page = NULL;
  assert((instruction >= address) && (instruction < address+PAGE_SIZE));

  //first find the page
  void* address_page = __builtin_align_down(address, PAGE_SIZE);
  for(int i = 0; i < unsafe_pages.size; i++) {
      if(unsafe_pages.list[i]->address==address_page){
          page = unsafe_pages.list[i];
      }
  }
  if(page == NULL){
    std::vector<char*>* unsafe_instructions = new std::vector<char*>();
    unsafe_instructions->push_back(instruction);
    assert(add_unsafe_page(address, current_perm, desired_perm, trusted_page, unsafe_instructions) != NULL);
    return 0;
  }

  //now check if the instruction already exists, otherwise add it
    auto& vec = page->unsafe_instructions;

    if (std::find(vec->begin(), vec->end(), instruction) == vec->end()) {
        vec->push_back(instruction);
    }

    return 0;
}

/*
 * Scan for WRPKRU sequence in memory segment
 */

//TODO rewrite in assembly to get rid of full permissions
int erim_scanMemForWRPKRUXRSTOR(char * mem_start, unsigned long length, unsigned int* ret)
{
  uint8_t* ptr = (uint8_t*)mem_start;
  int type = 0;
  unsigned int it = 0;
  if (length < 3)
    return 0;
  int pkru = rdpkru();
  internal_wrpkru(GRANT_FULL_PERMISSIONS);
  for(it=0; it < length - 3; it++) {
    if(erim_isWRPKRU(&ptr[it])) {
      type = TYPE_WRPKRU;
      *ret = it;
      break;
    }
    if(erim_isXRSTOR(&ptr[it])) {
      type = TYPE_XRSTOR;
      *ret = it;
      break;
    }
    if(erim_isWRGSBASE32(&ptr[it])||erim_isWRGSBASE64(&ptr[it])){
      type = TYPE_WRGSBASE;
      *ret = it;
      break;
    }
  }
  internal_wrpkru(pkru);
  return type;
}

//return 0 == not in whitelist, 1 == in whitelist
static int checkWhitelistedWRPKRU(unsigned long long addr, unsigned long long* whitelist, int whitelist_size) {
    for(int i=0;i<whitelist_size;i++){
      //printf(" addr %p whitelist: %p\n", addr, whitelist[i]);
      if(addr==whitelist[i]){
        return 1;
      }
    }
    return 0;
}

/*
 * Check if XRSTOR starting at addr is benign
 * Return: 0 -> not benign
 *         1 -> benign
 */
static int isBenignXRSTOR(char* loc) {
  int pkru = rdpkru();
  internal_wrpkru(GRANT_FULL_PERMISSIONS);
  uint8_t * addr = uint8ptr(loc);
  //printf("addr %p\n", addr);
  if(erim_isXRSTOR(&addr[0]) &&
    addr[3] == 0x89 && addr[4] == 0xc2 && //mov eax, edx
    addr[5] == 0x0f && addr[6] == 0xba && addr[7] == 0xe2 && addr[8] == 0x09 && //bt 0x9, edx 
    addr[9] == 0x73 && addr[10] == 0x03 && //jnc
    addr[11] == 0x0f && addr[12] == 0x0b &&//ud2 instruction
    addr[13] == 0xcc //int3 instruction
    ){
    internal_wrpkru(pkru);
    return 1;
  }
  internal_wrpkru(pkru);
  return 0;
}

/*
 * Check if WRPKRU starting at addr is benign
 * Return: 0 -> not benign
 *         1 -> benign
 */
int isBenignWRPKRU(char* loc) {
  int pkru = rdpkru();
  internal_wrpkru(GRANT_FULL_PERMISSIONS);
  uint8_t * addr = uint8ptr(loc);
  //printf("addr:%p 0:%d 1:%d 2:%d 3:%d 4:%d 5:%d 13:%x 14:%x 15;%x 16:%x 12:%x\n", addr, addr[0] == 0x31, addr[1] == 0xc9, addr[2] == 0x31, addr[3] == 0xd2, addr[4] == 0xb8, *((uint32_t*) &addr[5]) == REVOKE_PERMISSIONS, addr[13], addr[14], addr[15], addr[16], addr[12]);
  //printf("addr %p: %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", addr, erim_isWRPKRU(&addr[0]), addr[3] == 0x65, addr[4] == 0x8a, addr[5] == 0x14, addr[6] == 0x25, *((uint32_t*) &addr[7])==0x10, addr[11] == 0x80, addr[12] == 0xfa, addr[13] == 0x0, addr[14] == 0x74, addr[15] == 0x03, addr[16] == 0x0f, addr[17] == 0x0b, addr[18] == 0xcc);
  // switch to untrusted domain
  if(*((uint32_t*) &addr[4]) == REVOKE_PERMISSIONS && // new PKRU value is application
     erim_isWRPKRU(&addr[0]) &&
     addr[3] == 0x3d && //cmp opcode
     (
      (addr[8] == 0x74 &&//jmp opcode gcc (short opcode)
       addr[9] == 0x03 && // addr for short jmp code
       addr[10] == 0x0f && addr[11] == 0x0b &&//ud2 instruction
       addr[12] == 0xcc //int3 instruction
      )
       /*
      || 
      (addr[17] == 0x0f && addr[18] == 0x84 &&  // jmp opcode clang (long opcode)
       (0xffffffff - *((uint32_t*)&addr[19])) == ???) // addr clalc
       */
     ))
    {  
      //printf("found revoke wrpkru at %p\n", addr); 
      internal_wrpkru(pkru);
      return 1;
    } 
    //internal wrpkru (use %dl for the check)
    else if(erim_isWRPKRU(&addr[0]) && //wpkru sequence
            addr[3] == 0x65 &&//segment override 
            addr[4] == 0x8a && //mov opcode 
            addr[5] == 0x14 && addr[6] == 0x25 &&
              *((uint32_t*) &addr[7])==0x10 &&
            addr[11] == 0x80 && addr[12] == 0xfa && addr[13] == TS_MONITOR &&//cmp 0x0, %dl
            (addr[14] == 0x74 &&//jmp opcode gcc (short opcode)
            addr[15] == 0x03 && // addr for short jmp code
            addr[16] == 0x0f && addr[17] == 0x0b &&//ud2 instruction
            addr[18] == 0xcc //int3 instruction
            ))
    { 
      //printf("found internal wrpkru at %p\n", addr);   
      internal_wrpkru(pkru);
      return 1;
    }
  internal_wrpkru(pkru);
  return 0;
}

std::mutex erim_scan_mutex;


//TODO, only scan accross boundaries if both pages are executable
struct unsafe_page* erim_memScanRegion(char * origstart,
		       unsigned long long origlength,
		       unsigned long long * whitelist,
		       unsigned int wlEntries, 
           int perm, int unsafe_perm,bool trusted_page, char** prev_page_ptr) {

#if !SCAN_UNSAFE_INSTRUCTIONS
  return NULL;
#endif
  erim_scan_mutex.lock();
  assert(origlength==PAGE_SIZE);
  unsigned int wlIt = 0;
  char * start = origstart;
  unsigned long long length = origlength;
  bool found_non_benign = false;


  char* next_page = NULL; 
  char* prev_page = NULL; 
  struct virt_page* temp;
  int temp_prot = 0;
  int temp_cid = -1;

  //if prev_page_ptr == NULL, then we are the first page in the scann, so lets check if a page exists before this one
  //otherwise, we know that a page exists before this one
  if(prev_page_ptr == NULL || *prev_page_ptr == NULL) {
    if(start >= (char*)PAGE_SIZE){
      temp = page_manager.lookup_addr(start - PAGE_SIZE, -1);
      if(temp != NULL && temp != ((struct virt_page*)-1) && (temp->prot != PROT_NONE)){ //temp->prot&PROT_EXEC
        prev_page = start - PAGE_SIZE;
        temp_prot = temp->prot;
        temp_cid = temp->Cid;
      }
    }
  }else{
    prev_page = *prev_page_ptr;
    temp_prot = perm;
    temp_cid= (trusted_page ? TS_MONITOR : TS_APPLICATION);
  }



  temp = page_manager.lookup_addr(start + PAGE_SIZE, -1);
  if(temp != NULL && temp != ((struct virt_page*)-1) && (temp->prot != PROT_NONE)){//temp->prot&PROT_EXEC
    next_page = start + PAGE_SIZE;
    temp_prot = temp->prot;
    temp_cid = temp->Cid;
  }

  //we know that there is an executable page before this one, so lets start at the final 3 bytes of the previous page to check for cross page unsafe instructions
  if(prev_page){
    int pkru = rdpkru();
    for(int offset = -3; offset < 0; offset++){
      char* ptr = start + offset;
      internal_wrpkru(GRANT_FULL_PERMISSIONS);
      if(erim_isWRPKRU(ptr) || erim_isXRSTOR(ptr) || erim_isWRGSBASE32(ptr) || erim_isWRGSBASE64(ptr)){
        if(!((whitelist && checkWhitelistedWRPKRU((unsigned long long)(ptr), whitelist, wlEntries)) || isBenignWRPKRU(ptr))){ 
          assert(update_unsafe_instruction(prev_page, ptr, unsafe_perm, perm, trusted_page)==0);
          //if this is the first page in the scan, we can just update the actual page
          if(prev_page_ptr == NULL || *prev_page_ptr == NULL){
            assert(syscall_wrapper(__NR_mprotect, (size_t)prev_page, PAGE_SIZE, temp_prot&~PROT_EXEC, 0, 0, 0, temp_cid)==0);
          }else{
          //otherwise set prev_page_ptr == -1 so the higher level function knows that is should be made non executable
            *prev_page_ptr = (char*)-1;
          }
        }
      }
      internal_wrpkru(pkru);
    }
  }

  //we know that there is an executable page after this one, so lets start at the final 3 bytes of the next page to check for cross page unsafe instructions
  if(next_page){
    int pkru = rdpkru();
    for(int offset = 0; offset < 4; offset++){
      internal_wrpkru(GRANT_FULL_PERMISSIONS);
      char* ptr = next_page + offset;
      if(erim_isWRPKRU(ptr) || erim_isXRSTOR(ptr) || erim_isWRGSBASE32(ptr) || erim_isWRGSBASE64(ptr)){
        if(!((whitelist && checkWhitelistedWRPKRU((unsigned long long)(ptr), whitelist, wlEntries)) || isBenignWRPKRU(ptr))){ 
          assert(update_unsafe_instruction(next_page, ptr, unsafe_perm, perm, trusted_page)==0);
          assert(syscall_wrapper(__NR_mprotect, (size_t)next_page, PAGE_SIZE, temp_prot&~PROT_EXEC, 0, 0, 0, temp_cid)==0);
        }
      }
      internal_wrpkru(pkru);
    }
  }

  std::vector<char*>* unsafe_instructions = new std::vector<char*>();
  // iterate over every byte and check for WRPKRU sequence
  while (length > 0) {

    // scan for wprkru
    unsigned int found = 0;
    int type = erim_scanMemForWRPKRUXRSTOR(start, length, &found);
    if (found) {// found a sequence at found
      switch(type){
          case TYPE_WRPKRU:
            // check whitelist
            if(!((whitelist && checkWhitelistedWRPKRU((unsigned long long)(start + found), whitelist, wlEntries)) || isBenignWRPKRU(start + found))){ 
              //nolibc_print_size_t_hex("found non-benign WRPKRU at", (size_t)start + found);
              found_non_benign = true;
              unsafe_instructions->push_back(start + found);
            }
            break;
          case TYPE_XRSTOR:
            if(!isBenignXRSTOR(start + found)){
              //nolibc_print_size_t_hex("found non-benign XRSTOR at", (size_t)start + found);
              found_non_benign = true;
              unsafe_instructions->push_back(start + found);
            }
            break;
          case TYPE_WRGSBASE:
            //nolibc_print_size_t_hex("found non-benign WRGSBASE at", (size_t)start + found);
            found_non_benign = true;
            unsafe_instructions->push_back(start + found);
            break;
      }


      
      length -= (found + 3);
      start += found + 3;
      // continue if length > 0
      
    } else { // (!found)
      length = 0; // break loop
    } 
  } // while (length > 0)
  if(found_non_benign){
    erim_scan_mutex.unlock();
    return add_unsafe_page(origstart, unsafe_perm, perm, trusted_page, unsafe_instructions);
  }
  
  erim_scan_mutex.unlock();
  update_unsafe_page(origstart, perm , perm, trusted_page, unsafe_instructions);
  return NULL;
}


