//#ifdef MM_PAGING
/*
 * PAGING based Memory Management
 * Virtual memory module mm/mm-vm.c
 */

#include "string.h"
#include "mm.h"
#include <stdlib.h>
#include <stdio.h>

/*enlist_vm_freerg_list - add new rg to freerg_list
 *@mm: memory region
 *@rg_elmt: new region
 *
 */



int enlist_vm_freerg_list(struct mm_struct *mm, struct vm_rg_struct rg_elmt)
{
  struct vm_rg_struct *rg_node = mm->mmap->vm_freerg_list;
  struct vm_rg_struct *newRg = malloc(sizeof(struct vm_rg_struct));
  newRg->rg_start = rg_elmt.rg_start;
  newRg->rg_end = rg_elmt.rg_end; 
  if (rg_elmt.rg_start >= rg_elmt.rg_end)
    return -1;

  if (rg_node != NULL)
    newRg->rg_next = rg_node;

  /* Enlist the new region */
  mm->mmap->vm_freerg_list = newRg;

  return 0;
}

/*get_vma_by_num - get vm area by numID
 *@mm: memory region
 *@vmaid: ID vm area to alloc memory region
 *
 */
struct vm_area_struct *get_vma_by_num(struct mm_struct *mm, int vmaid)
{
  struct vm_area_struct *pvma= mm->mmap;

  if(mm->mmap == NULL)
    return NULL;

  int vmait = 0;
  
  while (vmait < vmaid)
  {
    if(pvma == NULL)
	  return NULL;

    pvma = pvma->vm_next;
  }

  return pvma;
}

/*get_symrg_byid - get mem region by region ID
 *@mm: memory region
 *@rgid: region ID act as symbol index of variable
 *
 */
struct vm_rg_struct *get_symrg_byid(struct mm_struct *mm, int rgid)
{
  if(rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
    return NULL;

  return &mm->symrgtbl[rgid];
}

// Helping function for ALLOC 

// Function get_free_frame() will return pointer which point to a free frame, and this function will put this frame from free_frame_list into used_frame_list
struct framephy_struct *get_free_frame(struct memphy_struct *memphy) {
	if(memphy->free_fp_list == NULL) return NULL;	// No more free frame
	else {
		// take out a first free frame from free list. Assign this frame to <rt_frame> 
		struct framephy_struct *rt_frame = memphy->free_fp_list;
		memphy->free_fp_list = memphy->free_fp_list->fp_next;
		rt_frame->fp_next = NULL;
		// Put this frame into used_fp_list
		if(memphy->used_fp_list == NULL) {	// No more frame in used
			memphy->used_fp_list = rt_frame;	
		}
		else {
			struct framephy_struct *scan = memphy->used_fp_list;
			while(scan->fp_next != NULL) scan = scan->fp_next;
			scan->fp_next = rt_frame; 
		}
		return rt_frame;
	}
}

/*Debug function: Print fifo_list of page*/
void printFifo(struct pgn_t *fifo_list) {
	printf("\n------------------\n");
	if(fifo_list == NULL) {
		printf("No one in this list\n");
		return;
	}
	else {
		printf("Fifo_list: ");
		struct pgn_t *scan = fifo_list;
		while(scan != NULL) {
			printf("%d ", scan->pgn);
			scan = scan->pg_next;
		}
	}
	printf("\n\n");
	return;
}

/*__alloc - allocate a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *@alloc_addr: address of allocated memory region
 *
 */
int __alloc(struct pcb_t *caller, int vmaid, int rgid, int size, int *alloc_addr)
{
  /*Allocate at the toproof */
  struct vm_rg_struct rgnode;
  // To avoid external fragment, i will convert size to alligned size in get_free_vmrg_area 
  // Becasue in get_free_vmrg_area() just take out enough space (== size) => external fragment 
  
  // Sync
  pthread_mutex_lock(&manip_mem);

  if (get_free_vmrg_area(caller, vmaid, PAGING_PAGE_ALIGNSZ(size), &rgnode) == 0)
  {
    caller->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
    caller->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;
    int pgnum = PAGING_PAGE_ALIGNSZ(size) / PAGING_PAGESZ;
    int pgn = PAGING_PGN(rgnode.rg_start);
    int pgit = 0;
    for(pgit = 0; pgit < pgnum; pgit++) {
      enlist_pgn_node(&caller->mm->fifo_pgn, pgn + pgit);
    }
    *alloc_addr = rgnode.rg_start;
#ifdef MYDEBUG
    	printf("\n\t\tHave free list\n\t\tthis->proc: %d\n\t\talloc size: %d\n", caller->prio, PAGING_PAGE_ALIGNSZ(size));
	printf("\t\trg_start-%d rg_end-%d\n", rgnode.rg_start, rgnode.rg_end);
	printf("\t\tPage number: %d\n", PAGING_PGN(rgnode.rg_start));	
	printf("\t\tPage table entry: %d\n", caller->mm->pgd[PAGING_PGN(rgnode.rg_start)]);
	printFifo(caller->mm->fifo_pgn);
#endif
	// End Sync
	  pthread_mutex_unlock(&manip_mem);
    return 0;
  }

  /* TODO get_free_vmrg_area FAILED handle the region management (Fig.6)*/

  /*Attempt to increate limit to get space */
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  int inc_sz = PAGING_PAGE_ALIGNSZ(size); // size = 300 -> 555
  //int inc_limit_ret
  int old_sbrk ;

  old_sbrk = cur_vma->sbrk;

  /* TODO INCREASE THE LIMIT
   * inc_vma_limit(caller, vmaid, inc_sz)
   */
  inc_vma_limit(caller, vmaid, inc_sz);

  /*Successful increase limit */
  caller->mm->symrgtbl[rgid].rg_start = old_sbrk;
  caller->mm->symrgtbl[rgid].rg_end = old_sbrk + inc_sz;


	cur_vma->sbrk += inc_sz; 

  *alloc_addr = old_sbrk;
	//old_sbrk += size;

#ifdef MYDEBUG
	printf("\n\t\tDont have free list\n\t\tthis->proc: %d\n\t\tSize:\t\t%d\n", caller->prio, size);
	printf("\t\tAligned size:\t%d\n", inc_sz);
	printf("\t\tNumber of pages: %d\n", PAGING_PAGE_ALIGNSZ(inc_sz) / PAGING_PAGESZ);
	printf("\t\told_sbrk: %d\n", old_sbrk);
	// Check macro PAGING_PGN()
	//int fake_sbrk = old_sbrk + 256;
	//printf("\t\tInc by offset:\t%d\n", PAGING_PGN(fake_sbrk));
	printf("\t\tPage number is: %d\n\n", PAGING_PGN(old_sbrk));
#endif

  // vmap_page_range
  // Step 1: Calc num of mapping page 
  // @incnumpage is number of mapping page, enough for allocated size   
  int incnumpage = PAGING_PAGE_ALIGNSZ(inc_sz) / PAGING_PAGESZ;
  struct vm_rg_struct ret_rg;
// In vmap_page_range, i will assign f<incnumpage> frame numbers into <incnumpage> pages
  vmap_page_range(caller, old_sbrk, incnumpage, caller->mram->used_fp_list, &ret_rg);

#ifdef MYDEBUG
	printFifo(caller->mm->fifo_pgn);
#endif
  // End Sync
  pthread_mutex_unlock(&manip_mem);

	// // Step 1: get caller -> vma have id == 0 (vm area for this page table)
	// struct vm_area_struct *get_vma_0 = get_vma_by_num(caller->mm, vmaid);

	// // Step 2: get vm_end (have expanded already - above code)
	// uint32_t end_pageTable = get_vma_0->vm_end;
	// int end_indexPageTable = PAGING_PGN(end_pageTable);
	// printf("\n\t\tThis index is: %d\n\t\tAddress of vmaid = 0 is: %p", end_indexPageTable, (void *)get_vma_0);
	// printf("\n\t\tAddress of pdg is: %p\n\n", (void *)caller->mm->pgd);

	// // Now, we have caller->mm->pgd[end_indexPageTable - 1] is a new page, which we have created
	// // Next, we will find out free frame and get its ID to assign to this the new page
	// // And it frame must be in RAM (because this process is running)	
	// // I have write a helping function to get out a free_frame and put it in used_fp_list
	// struct framephy_struct *new_frame = get_free_frame(caller->mram);

	// // Step 3: Assign this frame_ID to page table entry
	// // 32-bit: present = 1 & fpn = frame_number & ... (any more ??)
	
	// // Clear all bit (set all = 0)
	// CLRBIT(caller->mm->pgd[end_indexPageTable - 1], ~0);
	// // Set bit 0-12: frame number (= frame number)
	// SETVAL(caller->mm->pgd[end_indexPageTable - 1], new_frame->fpn, 0x00001FFF, 0);	
	// // Set bit 31:   present (= 1)
	// SETVAL(caller->mm->pgd[end_indexPageTable - 1], 1, 0x80000000, 31);

  return 0;
}

// Helping function for __free() 
// Remove rg, which has just been freed 
int remove_node_fifoList(struct mm_struct *mm, int pgn) {
  if(mm->fifo_pgn == NULL) return -1;
  else if(mm->fifo_pgn->pg_next == NULL) {
    if(mm->fifo_pgn->pgn == pgn) {
      struct pgn_t *temp = mm->fifo_pgn;
      mm->fifo_pgn = NULL;
      free(temp);
      return 0;
    }
    return -1;
  } 
  else if(mm->fifo_pgn->pgn == pgn) {
    struct pgn_t *temp = mm->fifo_pgn;
    mm->fifo_pgn = mm->fifo_pgn->pg_next;
    free(temp);
    return 0;
  }
  else {
    struct pgn_t *temp = mm->fifo_pgn;
    struct pgn_t *prev_node = temp;
    while(temp != NULL) {
      if(temp->pgn == pgn) {
        prev_node->pg_next = temp->pg_next;
        temp->pg_next = NULL;
        free(temp);
        return 0;
      }
      prev_node = temp;
      temp = temp->pg_next;
    }
    return -1;
  }
}

// Helping function for mergeRg(): remove 1 node in vm_freerg_list
int remove_node_freerg(struct mm_struct *mm, struct vm_rg_struct rgnode) {
  if(mm->mmap->vm_freerg_list == NULL) return -1;
  else if(mm->mmap->vm_freerg_list->rg_next == NULL) {
    if(mm->mmap->vm_freerg_list->rg_start == rgnode.rg_start) {
      struct vm_rg_struct *temp = mm->mmap->vm_freerg_list;
      mm->mmap->vm_freerg_list = NULL;
      free(temp);
      return 0;
    }
    return -1;
  } 
  else if(mm->mmap->vm_freerg_list->rg_start == rgnode.rg_start) {
    struct vm_rg_struct *temp = mm->mmap->vm_freerg_list;
    mm->mmap->vm_freerg_list = mm->mmap->vm_freerg_list->rg_next;
    free(temp);
    return 0;
  }
  else {
    struct vm_rg_struct *temp = mm->mmap->vm_freerg_list;
    struct vm_rg_struct *prev_node = temp;
    while(temp != NULL) {
      if(temp->rg_start == rgnode.rg_start) {
        prev_node->rg_next = temp->rg_next;
        temp->rg_next = NULL;
        free(temp);
        return 0;
      }
      prev_node = temp;
      temp = temp->rg_next;
    }
    return -1;
  }
}
// Helping function for __free() 
// int mergeRg(): return 0 (successful) return -1 (merge fail)
int mergeRg(struct mm_struct *mm, struct vm_rg_struct rgnode) {
	// Run check free_rg_list: if(rgnode is continious node of some node)
	struct vm_rg_struct *rgit = mm->mmap->vm_freerg_list;
	if(rgit == NULL) return -1;
	while(rgit != NULL) {
		if(rgnode.rg_start == rgit->rg_end) {	// Continous case rgnode->rgit
			rgit->rg_end = rgnode.rg_end;
			return 0;
		}
		else if(rgnode.rg_end == rgit->rg_start) {
			rgit->rg_start = rgnode.rg_start;
			return 0;
		}
		rgit = rgit->rg_next;
	}
	return -1;
}
/*__free - remove a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *
 */
int __free(struct pcb_t *caller, int vmaid, int rgid)
{

  if(rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
    return -1;

  // Sync 
  pthread_mutex_lock(&manip_mem);
  
  struct vm_rg_struct rgnode;
  rgnode.rg_start = get_symrg_byid(caller->mm, rgid)->rg_start;
	get_symrg_byid(caller->mm, rgid)->rg_start = 0;
  rgnode.rg_end = get_symrg_byid(caller->mm, rgid)->rg_end;
	get_symrg_byid(caller->mm, rgid)->rg_end = -1;
  if(rgnode.rg_start >= rgnode.rg_end) {	
	pthread_mutex_unlock(&manip_mem);
	return -1;
  }
  /* TODO: Manage the collect freed region to freerg_list */
  // Remove pages from fifo_list
#ifdef FREEDEBUG
	printf("\n-----------Free %d---------\n", rgid);
	printf("rg_start-%d rg_end-%d", get_symrg_byid(caller->mm, rgid)->rg_start, get_symrg_byid(caller->mm, rgid)->rg_end);
	printf("\n-----------End ---------\n\n");
#endif
  for(int i = rgnode.rg_start; i < rgnode.rg_end; i += PAGING_PAGESZ) {
    int cur_pgn = PAGING_PGN(i);
    remove_node_fifoList(caller->mm, cur_pgn);
  }
//ifdef MYDEBUG 
//	printf("\n\tDebug __free(rgid = %d)\n", rgid);
//	printf("\trg_start: %d & rg_end: %d\n\n", rgnode.rg_start, rgnode.rg_end);
//#endif

  // Add mechanism: Merge continious region in freeList 
  // Check continious Rg -> Then merge 2 region   
  if(mergeRg(caller->mm, rgnode) == 0) {
	//struct vm_rg_struct *rgit = caller->mm->mmap->vm_freerg_list;
	//while(rgit != NULL) {
	//	printf("%d - %d || ", rgit->rg_start, rgit->rg_end); 
	//	rgit = rgit->rg_next;
	//}
	//printf("\n\n");
	pthread_mutex_unlock(&manip_mem);
	return 0;
  }

  /*enlist the obsoleted memory region */
  enlist_vm_freerg_list(caller->mm, rgnode);
  
  // End sync
  pthread_mutex_unlock(&manip_mem);
  
  return 0;
}

/*pgalloc - PAGING-based allocate a region memory
 *@proc:  Process executing the instruction
 *@size: allocated size 
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */
int pgalloc(struct pcb_t *proc, uint32_t size, uint32_t reg_index)
{
  int addr;

  /* By default using vmaid = 0 */
  return __alloc(proc, 0, reg_index, size, &addr);
}

/*pgfree - PAGING-based free a region memory
 *@proc: Process executing the instruction
 *@size: allocated size 
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */

int pgfree_data(struct pcb_t *proc, uint32_t reg_index)
{
   return __free(proc, 0, reg_index);
}

// Helping function for <pg_getpage>
// get_fpn(<process>, <pgnum>): will return frame number from page number
int get_fpn_from_pgn(struct pcb_t *caller, int pgnum) {
  uint32_t pte = caller->mm->pgd[pgnum];
  return PAGING_FPN(pte);
}
//
/*pg_getpage - get the page in ram
 *@mm: memory region
 *@pagenum: PGN
 *@framenum: return FPN
 *@caller: caller
 *
 */
int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller)
{
  uint32_t pte = mm->pgd[pgn];
#ifdef GETPAGEDEBUG
	printf("\n-----------Get page---------\n");
	printf("Get page: pgn-%d pte-%08ld fpn-%d", pgn, pte, mm->pgd[pgn] + (2147483648));
	printf("\n-----------End ---------\n\n");
#endif
  if (!PAGING_PAGE_PRESENT(pte))
  { /* Page is not online, make it actively living */
	printf("\n-------Page is not online---------\n");
    int vicpgn, swpfpn; 
    //int vicfpn;
    //uint32_t vicpte;

    int tgtfpn = PAGING_SWP(pte);//the target frame storing our variable

    /* TODO: Play with your paging theory here */
    /* Find victim page */
    // if case == -1  => No one in fifo list & no one in free_rg_list (No "alloc" inst is called)
    // if case == 0   => find out victim page, which is using page
    // if case == 1   => find out victim page, which is freed page
    int victim_case = find_victim_page(caller, &vicpgn);
    // Take out frame num
    int vicfpn = get_fpn_from_pgn(caller, vicpgn);

    if(victim_case == -1) return -1;
    /* Get free frame in MEMSWP */
    // Case 0: using page
    else if(victim_case == 0) {
	 
      // Step 1: u must find out 1 free frame
      // Because in OS, if u want to swap A & B, u need 1 more free space (called C) to contain A or B
      // And if all mem (main mem or backing store) is full, u cant swap any thing 
      MEMPHY_get_freefp(caller->active_mswp, &swpfpn);

      // Step 2: u need to swap data victim page to free frame 
      __swap_cp_page(caller->mram, vicfpn, caller->active_mswp, swpfpn);

      // Step 3: i will push data from swap into victim in 
      __swap_cp_page(caller->active_mswp, tgtfpn, caller->mram, vicfpn);
      // Step 3.5: push data from <swpfpn> to <tgtfpn>
      __swap_cp_page(caller->active_mswp, swpfpn, caller->active_mswp, tgtfpn);

      // Step 4: Assign  victim_frame num to pgd[pgn]
      pte_set_fpn(&caller->mm->pgd[pgn], vicfpn);
      
      // Step 5: Assign pte to pgd[vicpgn]
      caller->mm->pgd[vicpgn] = pte;

      // Step 6: Push <swpfpn> back to free_fp_list 
      enlist_fp_node(&caller->active_mswp->free_fp_list, swpfpn); 

    }
    else if(victim_case == 1) {
      // This case: U find out a free_rg (have free_rg => have free_page)
      // Then i take out enough space (just = 1 page) to push <tgtfpn> into this pgd
      // Step 1: i push data from <backing store> - SWAP to <vicfpn>
      __swap_cp_page(caller->active_mswp, tgtfpn, caller->mram, vicfpn);

      // Step 2: Assign <vicfpn> to pgd[pgn] page table entry of read variable
      pte_set_fpn(&caller->mm->pgd[pgn], vicfpn);

      // Step 3: i push frame of tgtfpn to free_fp_list 
      enlist_fp_node(&caller->active_mswp->free_fp_list, tgtfpn); 
    }

    /* Do swap frame from MEMRAM to MEMSWP and vice versa*/
    /* Copy victim frame to swap */
    // __swap_cp_page();
    /* Copy target frame from swap to mem */
    //__swap_cp_page();

    /* Update page table */
    //pte_set_swap() &mm->pgd;

    /* Update its online status of the target page */
    //pte_set_fpn() & mm->pgd[pgn];
    // pte_set_fpn(&pte, tgtfpn);

    enlist_pgn_node(&caller->mm->fifo_pgn,pgn);
  }

  *fpn = PAGING_FPN(mm->pgd[pgn]);

  return 0;
}

/*pg_getval - read value at given offset
 *@mm: memory region
 *@addr: virtual address to acess 
 *@value: value
 *
 */
int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;

  /* Get the page to MEMRAM, swap from MEMSWAP if needed */
  
  // Sync
  pthread_mutex_lock(&manip_mem);
  if(pg_getpage(mm, pgn, &fpn, caller) != 0) {
    // End sync
    pthread_mutex_unlock(&manip_mem);
    return -1; /* invalid page access */
  }

  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;

  MEMPHY_read(caller->mram,phyaddr, data);
  // End sync
  pthread_mutex_unlock(&manip_mem);

  return 0;
}

/*pg_setval - write value to given offset
 *@mm: memory region
 *@addr: virtual address to acess 
 *@value: value
 *
 */
int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;

  /* Get the page to MEMRAM, swap from MEMSWAP if needed */
  // Sync
  pthread_mutex_lock(&manip_mem);
  if(pg_getpage(mm, pgn, &fpn, caller) != 0) {
    // End Sync
    pthread_mutex_unlock(&manip_mem);
    return -1; /* invalid page access */
  }
  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;

#ifdef WRITEDEBUG
	printf("------------- WRITE DEBUG ------------\n");
	printf("\t Physical address: %d\n", phyaddr);
	printf("\t Frame number: %d\n", fpn);
	printf("------------- END DEBUG ------------\n\n");
#endif
  MEMPHY_write(caller->mram,phyaddr, value);
  // End Sync
  pthread_mutex_unlock(&manip_mem);
  return 0;
}

/*__read - read value in region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region 
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *
 */
int __read(struct pcb_t *caller, int vmaid, int rgid, int offset, BYTE *data)
{
  
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  if(currg == NULL || cur_vma == NULL) /* Invalid memory identify */
	  return -1;
  
  pg_getval(caller->mm, currg->rg_start + offset, data, caller);

  return 0;
}


/*pgwrite - PAGING-based read a region memory */
int pgread(
		struct pcb_t * proc, // Process executing the instruction
		uint32_t source, // Index of source register
		uint32_t offset, // Source address = [source] + [offset]
		uint32_t destination) 
{
  BYTE data;
  int val = __read(proc, 0, source, offset, &data);

  destination = (uint32_t) data;
#ifdef IODUMP
  printf("read region=%d offset=%d value=%d\n", source, offset, data);
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); //print max TBL
#endif
  MEMPHY_dump(proc->mram);
#endif

  return val;
}

/*__write - write a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region 
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *
 */
int __write(struct pcb_t *caller, int vmaid, int rgid, int offset, BYTE value)
{
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  // Check: rgid is exist
  if(currg->rg_start >= currg->rg_end || currg->rg_end == -1) {
#ifdef WRITEDEBUG
	printf("\n------------Region ID is invalid (WRITE CASE)-----------\n");
	printf("\t\tRegion ID: %d\n", rgid);
	printf("\t\tRegion start: %d\n", currg->rg_start);
	printf("\t\tRegion end: %d\n", currg->rg_end);
	printf("---------------------------End------------------------\n\n");
#endif
	return -1;
  }
  if(currg->rg_start + offset >= currg->rg_end) {
#ifdef WRITEDEBUG
	printf("\n------------Offset is invalid (WRITE CASE)-----------\n");
	printf("\t\tRegion ID: %d\n", rgid);
	printf("\t\tRegion start: %d\n", currg->rg_start);
	printf("\t\tRegion end: %d\n", currg->rg_end);
	printf("\t\tOffset: %d\n", offset);
	printf("---------------------------End------------------------\n\n");
#endif
	return -1;
  }
  if(currg == NULL || cur_vma == NULL) /* Invalid memory identify */
	  return -1;

  pg_setval(caller->mm, currg->rg_start + offset, value, caller);

  return 0;
}

/*pgwrite - PAGING-based write a region memory */
int pgwrite(
		struct pcb_t * proc, // Process executing the instruction
		BYTE data, // Data to be wrttien into memory
		uint32_t destination, // Index of destination register
		uint32_t offset)
{
#ifdef IODUMP
  printf("write region=%d offset=%d value=%d\n", destination, offset, data);
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); //print max TBL
#endif
  MEMPHY_dump(proc->mram);
#endif

  return __write(proc, 0, destination, offset, data);
}


/*free_pcb_memphy - collect all memphy of pcb
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@incpgnum: number of page
 */
int free_pcb_memph(struct pcb_t *caller)
{
  int pagenum, fpn;
  uint32_t pte;


  for(pagenum = 0; pagenum < PAGING_MAX_PGN; pagenum++)
  {
    pte= caller->mm->pgd[pagenum];

    if (!PAGING_PAGE_PRESENT(pte))
    {
      fpn = PAGING_FPN(pte);
      MEMPHY_put_freefp(caller->mram, fpn);
    } else {
      fpn = PAGING_SWP(pte);
      MEMPHY_put_freefp(caller->active_mswp, fpn);    
    }
  }

  return 0;
}

/*get_vm_area_node - get vm area for a number of pages
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@incpgnum: number of page
 *@vmastart: vma end
 *@vmaend: vma end
 *
 */
struct vm_rg_struct* get_vm_area_node_at_brk(struct pcb_t *caller, int vmaid, int size, int alignedsz)
{
  struct vm_rg_struct * newrg;
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  newrg = malloc(sizeof(struct vm_rg_struct));

  newrg->rg_start = cur_vma->sbrk;
  newrg->rg_end = newrg->rg_start + size;

  return newrg;
}

/*validate_overlap_vm_area
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@vmastart: vma end
 *@vmaend: vma end
 *
 */
int validate_overlap_vm_area(struct pcb_t *caller, int vmaid, int vmastart, int vmaend)
{
  //struct vm_area_struct *vma = caller->mm->mmap;

  /* TODO validate the planned memory area is not overlapped */

  return 0;
}

/*inc_vma_limit - increase vm area limits to reserve space for new variable
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@inc_sz: increment size 
 *
 */
int inc_vma_limit(struct pcb_t *caller, int vmaid, int inc_sz)
{
  //struct vm_rg_struct * newrg = malloc(sizeof(struct vm_rg_struct));
  int inc_amt = PAGING_PAGE_ALIGNSZ(inc_sz); // NOT USE size = 300 -> 555 -> 810 
  int incnumpage =  inc_amt / PAGING_PAGESZ; // size = 300 -> 555 -> 810 -> 3.164 
  struct vm_rg_struct *area = get_vm_area_node_at_brk(caller, vmaid, inc_sz, inc_amt);
  // After above instruction: area->start = sbrk (of vmaid == 0) area->end = sbrk + 555(inc_sz - after aligned size)
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  //int old_end = cur_vma->vm_end;

  // This case needn't do, beacause this assignment has only 1 mem_seg (vmaid == 0)
  /*Validate overlap of obtained region */
  if (validate_overlap_vm_area(caller, vmaid, area->rg_start, area->rg_end) < 0)
    return -1; /*Overlap and failed allocation */
	
  free(area);
#ifdef MYDEBUG
	printf("\n\t\tThis is debugged text in inc_vma_limit\n");
	printf("\t\tinc_amt: %d\n", inc_amt);
	printf("\t\tNumber of pages: %d\n\n", incnumpage);
#endif
  /* The obtained vm area (only) 
   * now will be alloc real ram region */
  // Lift up sbrk (+= inc_sz), then we lift up vm_end (+= inc_sz)
  cur_vma->vm_end += inc_sz;
  // Then, we map pages to expanded size (number of page is incnumpage)  
  //if (vm_map_ram(caller, area->rg_start, area->rg_end, 
  //                  old_end, incnumpage , newrg) < 0)
  //  return -1; /* Map the memory to MEMRAM */

  return 0;

}

/*find_victim_page - find victim page
 *@caller: caller
 *@pgn: return page number
 *
 */
int find_victim_page(struct pcb_t *caller, int *retpgn) 
{
  /* TODO: Implement the theorical mechanism to find the victim page */
  struct vm_rg_struct rgnode;
  // Case 1: Have free regions (READ_SIZE in this assignment is 8-bit (= 1 BYTE = 1 page)
	//	printf("\n\n\t\t\tDEBUG CASE\n\n");
  if(get_free_vmrg_area(caller, 0, 256, &rgnode) == 0) {
    *retpgn = PAGING_PGN(rgnode.rg_start);
   return 1;
  }

  // Case 2: No more space => select latest page and swap it out
  if(caller->mm->fifo_pgn == NULL) return -1;

  struct pgn_t *pg = caller->mm->fifo_pgn;
  struct pgn_t *prev_pg = caller->mm->fifo_pgn;
  if(pg->pg_next == NULL) {	// Just 1 page in fifo_list
    *retpgn = pg->pgn;
    caller->mm->fifo_pgn = NULL;
  }
  else {			
    while(pg->pg_next != NULL) {
      prev_pg = pg;
      pg = pg->pg_next;
    }
    prev_pg->pg_next = NULL;
    *retpgn = pg->pgn;

  } 
  free(pg);

  return 0;
}

/*get_free_vmrg_area - get a free vm region
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@size: allocated size 
 *
 */
// Take out fitest size
int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg)
{
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  struct vm_rg_struct *rgit = cur_vma->vm_freerg_list;

  if (rgit == NULL)
    return -1;

  /* Probe unintialized newrg */
  newrg->rg_start = newrg->rg_end = -1;

  /* Traverse on list of free vm region to find a fit space */
  while (rgit != NULL)
  {
	//printf("\n\n\t\tDEBUGGGG inside %d %d\n\n", rgit->rg_start, rgit->rg_end); 

    if (rgit->rg_start + size <= rgit->rg_end)
    { /* Current region has enough space */
      newrg->rg_start = rgit->rg_start;
      newrg->rg_end = rgit->rg_start + size;

      /* Update left space in chosen region */
      if (rgit->rg_start + size < rgit->rg_end)
      {
        rgit->rg_start = rgit->rg_start + size;
      }
      else
      { /*Use up all space, remove current node */
        /*Clone next rg node */
        struct vm_rg_struct *nextrg = rgit->rg_next;

        /*Cloning */
        if (nextrg != NULL)
        {
          rgit->rg_start = nextrg->rg_start;
          rgit->rg_end = nextrg->rg_end;

          rgit->rg_next = nextrg->rg_next;

          free(nextrg);
        }
        else
        { /*End of free list */
          rgit->rg_start = rgit->rg_end;	//dummy, size 0 region
          rgit->rg_next = NULL;
        }
      }
      return 0;
    }
    else
    {
      rgit = rgit->rg_next;	// Traverse next rg
    }
  }

	//printf("\n\n\t\tDEBUGGGG outside %d %d\n\n", newrg->rg_start, newrg->rg_end); 

 if(newrg->rg_start == -1) // new region not found
   return -1;

 return 0;
}

//#endif

