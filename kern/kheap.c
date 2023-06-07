#include <inc/memlayout.h>
#include <kern/kheap.h>
#include <kern/memory_manager.h>

struct MemAlloc
{
	uint32 start_virt_add;
	uint32 end_virt_add;
	uint32 size;
} MemBlock[((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE) - 1] = {0};	//used to treat the kernel heap as an array of blocks each having a start and end virtual address and holding a size
uint32 frames_needed;

void *kmalloc(unsigned int size)	//takes a size as parameter and allocates it in the kernel heap according to the first fit allocation strategy
{
	int index;	//used to hold the index of the first free block if an appropriate allocation was found
	if (size > (KERNEL_HEAP_MAX - KERNEL_HEAP_START))	//exit function if the requested size is greater than the kernel heap
	{
		return NULL;
	}
	//translate the passed size into an int number of blocks
	if (size % PAGE_SIZE == 0)
	{
		frames_needed = (size / PAGE_SIZE);
	}
	else	//add 1 to the result in case the actual result/fraction came out as decimal
	{
		frames_needed = (size / PAGE_SIZE) + 1;
	}
	uint32 virt_add = 0;	//used to hold the address of the first free block in the allocation
	uint32 ref = 0;	//used to hold the ending address of the allocation (ending address of the last block)
	int check;	//used as a counter for the number of contiguous free blocks
	for (int i = 0; i < (((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE) - 1); i++)		//for loop on the kernel heap
	{
		check = 0;	//initialize the counter to 0
		if (MemBlock[i].size == 0)	//check if the block is empty == size = 0
		{
			for (int k = 0; k < frames_needed; k++)	//for loop for frames_needed iterations searching for contiguous appropriate blocks 
			{
				if (MemBlock[i + k].size == 0)	//check if the block is empty == size = 0
				{
					check++; //increment counter
				}
				else
				{
					break;
				}
			}
			if (check != frames_needed)	//checks whether the counter is equal to the number of needed blocks or not
			{
				continue;
			}
			else
			{
				virt_add = KERNEL_HEAP_START + (PAGE_SIZE * i);	//virt_add is given the virtual address of the first free block in the appropriate allocation
				for (int k = 0; k < frames_needed; k++)	//for loop giving values to size and start_virt_add so that the corresponding blocks will be treated as full
				{
					MemBlock[i + k].size = size;
					MemBlock[i + k].start_virt_add = virt_add;
				}
				ref = virt_add;	//ref is given the value in virt_add (the virtual address of the first free block in the appropriate allocation)
				index = i;	//hold the index of the first free block in the allocation
				break;
			}
		}
		else
		{
			continue;
		}
	}
	if (virt_add == 0)	//exit function if no appropriate allocation was found
	{
		return NULL;
	}
	for (int i = 0; i < frames_needed; i++)	//for loop for frames_needed iterations
	{
		struct Frame_Info *ptr_frame_info;
		int ret = allocate_frame(&ptr_frame_info);	//Used to allocate a free frame from the free frame list
		if (ret != E_NO_MEM)	//if there is enough available space in memory
		{
			int ret2 = map_frame(ptr_page_directory, ptr_frame_info, (void *)ref, PERM_PRESENT | PERM_WRITEABLE | PERM_USED);	//Used to map a single page with ref into a given allocated frame, simply by setting the directory and page table entries
			ref += PAGE_SIZE;	//increment ref by PAGE_SIZE so at the end of the loop it holds the ending address of the last block in the allocation
			if (ret2 == E_NO_MEM)	//if no available space in memory for the page table
			{
				free_frame(ptr_frame_info);	//free the frame allocated to the process itself
			}
		}
		else
		{
			cprintf("Error: No Physical Memory available!\n");
		}
	}
	for (int i = 0; i < frames_needed; i++)	//for loop giving values to end_virt_add so that the corresponding blocks will be treated as full
	{
		MemBlock[index + i].end_virt_add = ref;
	}
	return (void *)virt_add;	//return the virtual address of the first free block
}


void kfree(void* virtual_address)
{
	if(virtual_address < (void*) KERNEL_HEAP_START || virtual_address > (void*) KERNEL_HEAP_MAX)	//panic function if the passed virtual address is outside of the kernel heap
	{
		panic("Virtual Address out of Bound!");
	}
	else
	{
		for (int i = 0; i < (((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE) - 1); i++)	//for loop on all of the kernel heap
		{
			if (virtual_address >= (void *) MemBlock[i].start_virt_add && virtual_address < (void*) MemBlock[i].end_virt_add)	//check if the passed virtual address is within each allocation/group of blocks' range 
			{
				
				struct Frame_Info* frame_info = NULL;
				uint32* ptr_page_table;
				for(uint32 Var_Va = MemBlock[i].start_virt_add; Var_Va < MemBlock[i].end_virt_add; Var_Va += PAGE_SIZE)		//for loop on the allocation's blocks
				{
					frame_info = get_frame_info(ptr_page_directory, (void*)Var_Va, &ptr_page_table);	//used to get both the page table and the frame of the given virtual address, returns a pointer to it
					if(frame_info != NULL)	//check if the returned pointer points to an actual frame
					{					
						unmap_frame(ptr_page_directory, (void*)Var_Va);	//used to un-map a frame at the given virtual address, simply by clearing the page table entry (-The references count on the physical frame should decrement.- The physical frame should be freed if the 'references' reaches 0.- The page table entry corresponding to 'virtual_address' should be set to 0.(if such a page table exists)- The TLB must be invalidated if you remove an entry fromthe page directory/page table.)
					}
				}
				int NumOfPages = (((MemBlock[i].end_virt_add) - (MemBlock[i].start_virt_add))/PAGE_SIZE);
				for (int k = 0; k < NumOfPages; k++)	//for loop for block_needed iterations to set blocks' size, start_virt_add and end_virt_add to zero in order to signal these blocks as empty
				{
					MemBlock[i + k].size = 0;
					MemBlock[i + k].start_virt_add = 0;
					MemBlock[i + k].end_virt_add = 0;
				}
				
				break;
			}
		}
	}
}


unsigned int kheap_virtual_address(unsigned int physical_address)	//returns the virtual address corresponding to the passed physical address
{
	uint32 PA;
	for(uint32 VA = KERNEL_HEAP_START ; VA < KERNEL_HEAP_MAX ; VA += PAGE_SIZE)	//for loop on all of the kernel heap
	{
		PA = kheap_physical_address(VA);	//kheap_physical_address function call used to get the physical address corresponding to the passed virtual address
		if(PA == physical_address)	//compare the returned physical address with the passed physical address
		{
			return VA;	//return the corresponding virtual address 
		}
	}
	return 0;	//return 0 if the passed physical address has no corresponding virtual address 
}


unsigned int kheap_physical_address(unsigned int virtual_address)	//returns the physical address corresponding to the passed virtual address
{
	uint32* ptr_page_table;
	get_page_table(ptr_page_directory, (void*)virtual_address, &ptr_page_table);	//returns a pointer to the page table if it exists 
	if(ptr_page_table != NULL)	//if thye pointer is actually pointing to a page table
	{
		return (ptr_page_table[PTX(virtual_address)] >> 12) * PAGE_SIZE;	//return the corresponding physical address (ptr_page_table[PTX(virtual_address)] gets the entry in the page table then >> 12 shift by 12 bits inside the entry then * PAGE_SIZE to translate it into a hexadecimal physical address)
	}

	return 0;	//return 0 if the passed virtual address has no corresponding physical address
}

//=================================================================================//
//============================== BONUS FUNCTION ===================================//
//=================================================================================//
// krealloc():

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to kmalloc().
//	A call with new_size = zero is equivalent to kfree().

// krealloc is NOT COMPLETELY WORKING YET! Current Evaluation = 20%

void *krealloc(void *virtual_address, uint32 new_size)
{
	
	if(virtual_address == NULL && new_size != 0)
	{
		return kmalloc(new_size);
	}
	else if (new_size == 0 && virtual_address != NULL)
	{
		kfree(virtual_address);
	}
	else
	{
		for (int i = 0; i < (((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE) - 1); i++)
		{
			if (virtual_address >= (void *) MemBlock[i].start_virt_add && virtual_address < (void*) MemBlock[i].end_virt_add)
			{
				if(new_size <= MemBlock[i].size)
				{
					kfree(virtual_address);
					return 	kmalloc(new_size);
				}
				else{return NULL;}
			}
		}
	}
	return NULL;
}
