#include <inc/lib.h>

//==================================================================================//
//============================ REQUIRED FUNCTIONS ==================================//
//==================================================================================//

struct MemAlloc
{
	uint32 start_virt_add;
	uint32 end_virt_add;
	uint32 size;
} free_blocks[((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE) - 1] = {0};	//used to treat the user heap as an array of blocks each having a start and end virtual address and holding a size


void *malloc(uint32 size)	//takes a size as parameter and allocates it in the user heap according to the best fit allocation strategy
{
	int bestfit_index = -1;	//used to hold the index of the first free block if an appropriate allocation was found
	uint32 bestfit = USER_HEAP_MAX + 1;	//used to hold the best difference
	uint32 virt_add = 0;	//used to hold the address of the first free block in the allocation
	uint32 ref = 0;	//used to hold the ending address of the allocation (ending address of the last block)
	uint32 blocks_needed;

	if (size > (USER_HEAP_MAX - USER_HEAP_START))	//exit function if the requested size is greater than the kernel heap
	{
		return NULL;
	}
	//translate the passed size into an int number of blocks
	if (size % PAGE_SIZE == 0)
	{
		blocks_needed = (size / PAGE_SIZE);
	}
	else	//add 1 to the result in case the actual result/fraction came out as decimal
	{
		blocks_needed = (size / PAGE_SIZE) + 1;
	}

	for (int i = 0; i < (((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE) - 1); i++)		//for loop on all of the user heap
	{
		if (free_blocks[i].size == 0)	//check if the block is empty == size = 0
		{
			int j = i;
			uint32 bestfit_counter = 0;	//initialize the counter to 0

			while (j < (((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE) - 1))	//while loop on the rest of the user heap counting contiguous free blocks
			{
				if (free_blocks[j].size == 0)	//check if the block is empty == size = 0
				{
					bestfit_counter++;	//used as a counter for the number of contiguous free blocks
				}else{break;}
				j++;
			}
			if (bestfit_counter >= blocks_needed)	//checks whether the counter is greater than or equal to number of blocks needed or not
			{
				uint32 diff = bestfit_counter - (float)(size / PAGE_SIZE);	//calculate the difference between the counter and the requested size translated into number of blocks but cated to float for more precise result

				if (diff < bestfit)	//check whether the calculated difference is less than the best difference found until now or not 
				{
					bestfit = diff;	//to hold the best diff found so far
					bestfit_index = i;	//to hold the index of the first free block in the current allocation
				}
			}
			i = j;
		}
	}

	if (bestfit == USER_HEAP_MAX + 1)	//exit function if no appropriate allocation was found (bestfit value unchanged)
	{
		return NULL;
	}

	virt_add = USER_HEAP_START + (bestfit_index * PAGE_SIZE);	//virt_add is given the virtual address of the first free block in the appropriate allocation
	ref = virt_add + (PAGE_SIZE * blocks_needed);	//ref is given the ending virtual address of the last block in the allocation
	sys_allocateMem(virt_add, size);	//sys_allocateMem function call who then call the function allocateMem located in memorymanager.c -> allocates the passed virtual address to the passed size

	for (int i = 0; i < blocks_needed; i++)	//for loop giving values to size, start_virt_add and end_virt_add so that the corresponding blocks will be treated as full
	{	
		free_blocks[bestfit_index + i].size = size;
		free_blocks[bestfit_index + i].start_virt_add = virt_add;
		free_blocks[bestfit_index + i].end_virt_add = ref;
	}
	return (void*)virt_add;	//return the virtual address of the first free block
}

void* smalloc(char *sharedVarName, uint32 size, uint8 isWritable)
{
	// Write your code here, remove the panic and write your code
	panic("smalloc() is not required...!!");

	// Steps:
	//	1) Implement BEST FIT strategy to search the heap for suitable space
	//		to the required allocation size (space should be on 4 KB BOUNDARY)
	//	2) if no suitable space found, return NULL
	//	 Else,
	//	3) Call sys_createSharedObject(...) to invoke the Kernel for allocation of shared variable
	//		sys_createSharedObject(): if succeed, it returns the ID of the created variable. Else, it returns -ve
	//	4) If the Kernel successfully creates the shared variable, return its virtual address
	//	   Else, return NULL

	//This function should find the space of the required range
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	return 0;
}

void* sget(int32 ownerEnvID, char *sharedVarName)
{
	// Write your code here, remove the panic and write your code
	panic("sget() is not required ...!!");

	// Steps:
	//	1) Get the size of the shared variable (use sys_getSizeOfSharedObject())
	//	2) If not exists, return NULL
	//	3) Implement BEST FIT strategy to search the heap for suitable space
	//		to share the variable (should be on 4 KB BOUNDARY)
	//	4) if no suitable space found, return NULL
	//	 Else,
	//	5) Call sys_getSharedObject(...) to invoke the Kernel for sharing this variable
	//		sys_getSharedObject(): if succeed, it returns the ID of the shared variable. Else, it returns -ve
	//	6) If the Kernel successfully share the variable, return its virtual address
	//	   Else, return NULL
	//

	//This function should find the space for sharing the variable
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	return 0;
}

void free(void* virtual_address)	//gets passed a virtual address
{
	if(virtual_address < (void*) USER_HEAP_START || virtual_address > (void*) USER_HEAP_MAX)	//panic function if the passed virtual address is outside of the user heap
	{
		panic("Virtual Address out of Bound!");
	}
	else
	{
		bool found = 0;
		for (int i = 0; i < (((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE) - 1); i++)	//for loop on all of the user heap
		{
			if (virtual_address >= (void *) free_blocks[i].start_virt_add && virtual_address < (void*) free_blocks[i].end_virt_add)	//check if the passed virtual address is within each allocation/group of blocks' range
			{
				uint32 VA = free_blocks[i].start_virt_add;	//used to hold the allocation's start virtual address to be passed later to sys_freeMem()
				uint32 BlockSize = free_blocks[i].size;	//used to hold the allocation's size to be passed later to sys_freeMem()
				found = 1;
				int blocks_needed = (((free_blocks[i].end_virt_add) - (free_blocks[i].start_virt_add))/PAGE_SIZE);
				for (int k = 0; k < blocks_needed; k++)	//for loop for block_needed iterations to set blocks' size, start_virt_add and end_virt_add to zero in order to signal these blocks as empty
				{
					free_blocks[i + k].size = 0;
					free_blocks[i + k].start_virt_add = 0;
					free_blocks[i + k].end_virt_add = 0;
				}
				sys_freeMem(VA, BlockSize);	//sys_freeMem function call
				break;
			}
		}
		if (found == 0)	//the passed virtual address was not found
		{
			panic("Requested virtual address was not found!");
		}
	}
}

//==================================================================================//
//============================== BONUS FUNCTIONS ===================================//
//==================================================================================//

//=============
// [1] sfree():
//=============
//	This function frees the shared variable at the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from main memory then switch back to the user again.
//
//	use sys_freeSharedObject(...); which switches to the kernel mode,
//	calls freeSharedObject(...) in "shared_memory_manager.c", then switch back to the user mode here
//	the freeSharedObject() function is empty, make sure to implement it.

void sfree(void* virtual_address)
{
	// Write your code here, remove the panic and write your code
	panic("sfree() is not required ...!!");

	//	1) you should find the ID of the shared variable at the given address
	//	2) you need to call sys_freeSharedObject()

}


//===============
// [2] realloc():
//===============

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to malloc().
//	A call with new_size = zero is equivalent to free().

//  Hint: you may need to use the sys_moveMem(uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		which switches to the kernel mode, calls moveMem(struct Env* e, uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		in "memory_manager.c", then switch back to the user mode here
//	the moveMem function is empty, make sure to implement it.

void *realloc(void *virtual_address, uint32 new_size)
{
	if(virtual_address == NULL && new_size != 0)
	{
		return malloc(new_size);
	}
	else if (new_size == 0 && virtual_address != NULL)
	{
		free(virtual_address);
	}
	else
	{
		// for (int i = 0; i < (((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE) - 1); i++)
		// {
		// 	if (virtual_address >= (void *) free_blocks[i].start_virt_add && virtual_address < (void*) free_blocks[i].end_virt_add)
		// 	{
		// 		if(new_size <= free_blocks[i].size)
		// 		{
		// 			free(virtual_address);
		// 			return 	malloc(new_size);
		// 		}
		// 		else{return NULL;}
		// 	}
		// }
	}
	return NULL;
}
