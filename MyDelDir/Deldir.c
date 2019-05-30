/*
设计思想，使用list_entry保存遍历的文件，然后构造成栈，遍历时候
遇到文件夹放入栈，遇到文件删除
注意句柄要关闭不然会删除失败
为了方便测试，写死文件夹
*/

#include <ntddk.h>


//定义LIST_ENTRY
typedef struct _FILE_LIST_ENTRY {
	LIST_ENTRY ENTRY;
	PWSTR NameBuffer;
}FILE_LIST_ENTRY, *PFILE_LIST_ENTRY;



//保存文件信息的结构体
typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;



NTSTATUS
ZwQueryDirectoryFile(
	__in HANDLE  FileHandle,
	__in_opt HANDLE  Event,
	__in_opt PIO_APC_ROUTINE  ApcRoutine,
	__in_opt PVOID  ApcContext,
	__out PIO_STATUS_BLOCK  IoStatusBlock,
	__out PVOID  FileInformation,
	__in ULONG  Length,
	__in FILE_INFORMATION_CLASS  FileInformationClass,
	__in BOOLEAN  ReturnSingleEntry,
	__in_opt PUNICODE_STRING  FileName,
	__in BOOLEAN  RestartScan
);


NTSTATUS myDelFile(const WCHAR* fileName)
{
	NTSTATUS						status = STATUS_SUCCESS;
	UNICODE_STRING					uFileName = { 0 };
	OBJECT_ATTRIBUTES				objAttributes = { 0 };
	HANDLE							handle = NULL;
	IO_STATUS_BLOCK					iosb = { 0 };//io完成情况，成功true，失败false
	FILE_DISPOSITION_INFORMATION	disInfo = { 0 };
	RtlInitUnicodeString(&uFileName, fileName);
	//初始化属性
	InitializeObjectAttributes(
		&objAttributes,
		&uFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);
	status = ZwCreateFile(
		&handle,
		SYNCHRONIZE | FILE_WRITE_ACCESS | DELETE,
		&objAttributes,
		&iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,//普通文件，非文件夹
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_ACCESS_DENIED) {
			//如果访问拒绝，可能是只读的，就以没delete去打开，然后进去把属性设置成narmal在删除打开
			status = ZwCreateFile(
				&handle,
				SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
				&objAttributes,
				&iosb,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_OPEN,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0
			);
			if (NT_SUCCESS(status)) {
				FILE_BASIC_INFORMATION		basicInfo = { 0 };//因为要修改文件属性所以床FileBasicInformation
				status = ZwQueryInformationFile(
					handle, &iosb, &basicInfo,
					sizeof(basicInfo),//要查什么这里就是跟其相关的结构体
					FileBasicInformation
				);
				if (!NT_SUCCESS(status)) {
					DbgPrint("ZwQueryInformationFile %wZ is failed %x\n", &uFileName, status);
				}
				//然后修改文件属性
				basicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
				status = ZwSetInformationFile(handle, &iosb, &basicInfo, sizeof(basicInfo), FileBasicInformation);
				if (!NT_SUCCESS(status)) {
					DbgPrint("ZwSetInformationFile (%wZ) failed (%x)\n", &uFileName, status);
				}
				ZwClose(handle);
				status = ZwCreateFile(
					&handle,
					SYNCHRONIZE | FILE_WRITE_DATA | FILE_SHARE_DELETE,
					&objAttributes,
					&iosb,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_ALERT | FILE_DELETE_ON_CLOSE,
					NULL,
					0
				);
			}
		}
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ZwCreateFile(%wZ) failed(%x)\n", &uFileName, status));
			return status;
		}

	}
	disInfo.DeleteFile = TRUE;
	status = ZwSetInformationFile(handle, &iosb, &disInfo, sizeof(disInfo), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status));
	}

	ZwClose(handle);
	return status;
}

NTSTATUS myDelFileDir(const WCHAR * directory)
{
	UNICODE_STRING						uDirName = { 0 };
	PWSTR                            	nameBuffer = NULL;	//记录文件夹
	PFILE_LIST_ENTRY                	tmpEntry = NULL;	//链表结点
	LIST_ENTRY                        	listHead = { 0 };	//链表，用来存放删除过程中的目录
	NTSTATUS                        	status = 0;
	PFILE_LIST_ENTRY                	preEntry = NULL;
	OBJECT_ATTRIBUTES                	objAttributes = { 0 };
	HANDLE                            	handle = NULL;
	IO_STATUS_BLOCK                    	iosb = { 0 };
	BOOLEAN                            	restartScan = FALSE;
	PVOID                            	buffer = NULL;
	ULONG                            	bufferLength = 0;
	PFILE_DIRECTORY_INFORMATION        	dirInfo = NULL;
	UNICODE_STRING                    	nameString = { 0 };
	FILE_DISPOSITION_INFORMATION    	disInfo = { 0 };

	RtlInitUnicodeString(&uDirName, directory);
	nameBuffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, uDirName.Length + sizeof(WCHAR), 'DRID');//为了防'\0'加sizeofwchar
	if (!nameBuffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	tmpEntry = (PFILE_LIST_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_LIST_ENTRY), 'DRID');
	if (!tmpEntry) {
		ExFreePool(nameBuffer);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(nameBuffer, uDirName.Buffer, uDirName.Length);
	nameBuffer[uDirName.Length / sizeof(WCHAR)] = L'\0';
	InitializeListHead(&listHead);//初始化链表
	tmpEntry->NameBuffer = nameBuffer;
	InsertHeadList(&listHead, &tmpEntry->ENTRY);//将要删除的文件夹首先插入链表   
	// listHead里初始化为要删除的文件夹。
	//之后遍历文件夹下的文件和目录，判断是文件，则立即删除；判断是目录，则放进listHead里面
	//每次都从listHead里拿出一个目录来处理
	while (!IsListEmpty(&listHead)) {
		//先将要删除的文件夹和之前打算删除的文件夹比较一下，如果从链表里取下来的还是之前的Entry，表明没有删除成功，说明里面非空
		//否则，已经成功删除，不可能是它自身；或者还有子文件夹，在前面，也不可能是它自身。
		tmpEntry = (PFILE_LIST_ENTRY)RemoveHeadList(&listHead);
		if (preEntry == tmpEntry)
		{
			status = STATUS_DIRECTORY_NOT_EMPTY;
			break;
		}

		preEntry = tmpEntry;
		InsertHeadList(&listHead, &tmpEntry->ENTRY); //放进去，等删除了里面的内容，再移除。如果移除失败，则说明还有子文件夹或者目录非空

		RtlInitUnicodeString(&nameString, tmpEntry->NameBuffer);
		//初始化内核对象
		InitializeObjectAttributes(&objAttributes, &nameString, OBJ_CASE_INSENSITIVE, NULL, NULL);
		//打开文件，查询
		status = ZwCreateFile(
			&handle,
			FILE_ALL_ACCESS,
			&objAttributes,
			&iosb,
			NULL,
			0,
			0, FILE_OPEN,
			FILE_SYNCHRONOUS_IO_ALERT,
			NULL,
			0
		);
		if (!NT_SUCCESS(status))
		{

			DbgPrint("ZwCreateFile(%ws) failed(%x)\n", tmpEntry->NameBuffer, status);
			break;
		}
		//从第一个扫描
		restartScan = TRUE;//这是里面一个属性里面要改false不然ZwQueryDirectoryFile每次从第一个开始
		while (TRUE) //遍历从栈上摘除的文件夹
		{
			buffer = NULL;
			bufferLength = 64;//后面指数扩大
			status = STATUS_BUFFER_OVERFLOW;
			while ((status == STATUS_BUFFER_OVERFLOW) || (status == STATUS_INFO_LENGTH_MISMATCH))//不断分配内存，直到够大
			{
				if (buffer)
				{
					ExFreePool(buffer);
				}

				bufferLength *= 2;
				buffer = ExAllocatePoolWithTag(PagedPool, bufferLength, 'DRID');
				if (!buffer)
				{
					KdPrint(("ExAllocatePool failed\n"));
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				status = ZwQueryDirectoryFile(handle, NULL, NULL,
					NULL, &iosb, buffer, bufferLength, FileDirectoryInformation,
					FALSE, NULL, restartScan);//False代表一次只遍历每次只返回一个文件夹，restartScan设置为true代表顺序查，如果不改成false每次都是第一个文件夹
			}
			//上面查询完了，下面进行判断。查询结果在buffer里
			//如果是空说明遍历完了
			if (status == STATUS_NO_MORE_FILES)
			{
				ExFreePool(buffer);
				status = STATUS_SUCCESS;
				break;
			}
			restartScan = FALSE;

			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwQueryDirectoryFile(%ws) failed(%x)\n", tmpEntry->NameBuffer, status));
				if (buffer)
				{
					ExFreePool(buffer);
				}
				break;
			}

			dirInfo = (PFILE_DIRECTORY_INFORMATION)buffer;
			//申请一块内存保存当前文件夹路径和查询到子目录拼接在一起的完整目录
			nameBuffer = (PWSTR)ExAllocatePoolWithTag(PagedPool,
				wcslen(tmpEntry->NameBuffer) * sizeof(WCHAR) + dirInfo->FileNameLength + 4, 'DRID');
			if (!nameBuffer)
			{
				KdPrint(("ExAllocatePool failed\n"));
				ExFreePool(buffer);
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			//tmpEntry->NameBuffer是当前文件夹路径
			//下面的操作在拼接文件夹下面的文件路径
			RtlZeroMemory(nameBuffer, wcslen(tmpEntry->NameBuffer) * sizeof(WCHAR) + dirInfo->FileNameLength + 4);
			wcscpy(nameBuffer, tmpEntry->NameBuffer);
			wcscat(nameBuffer, L"\\");
			RtlCopyMemory(&nameBuffer[wcslen(nameBuffer)], dirInfo->FileName, dirInfo->FileNameLength);
			RtlInitUnicodeString(&nameString, nameBuffer);
			if (dirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				//如果是非'.'和'..'两个特殊的目录，则将目录放入listHead
				if ((dirInfo->FileNameLength == sizeof(WCHAR)) && (dirInfo->FileName[0] == L'.'))
				{

				}
				else if ((dirInfo->FileNameLength == sizeof(WCHAR) * 2) &&
					(dirInfo->FileName[0] == L'.') &&
					(dirInfo->FileName[1] == L'.'))
				{
				}
				else
				{
					//将文件夹插入listHead中
					PFILE_LIST_ENTRY localEntry;
					localEntry = (PFILE_LIST_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_LIST_ENTRY), 'DRID');
					if (!localEntry)
					{
						KdPrint(("ExAllocatePool failed\n"));
						ExFreePool(buffer);
						ExFreePool(nameBuffer);
						status = STATUS_INSUFFICIENT_RESOURCES;
						break;
					}
					localEntry->NameBuffer = nameBuffer;
					nameBuffer = NULL;
					InsertHeadList(&listHead, &localEntry->ENTRY); //插入头部，先把子文件夹里的删除
				}
			}
			else//如果是文件，直接删除
			{
				status = myDelFile(nameBuffer);
				if (!NT_SUCCESS(status))
				{
					KdPrint(("dfDeleteFile(%wZ) failed(%x)\n", &nameString, status));
					ExFreePool(buffer);
					ExFreePool(nameBuffer);
					break;
				}
			}
			ExFreePool(buffer);
			if (nameBuffer)
			{
				ExFreePool(nameBuffer);
			}//继续在循环里处理下一个子文件或者子文件夹

		}//  while (TRUE) ，一直弄目录里的文件和文件夹

		if (NT_SUCCESS(status))
		{
			//处理完目录里的文件文件夹，再处理目录文件夹
			disInfo.DeleteFile = TRUE;
			status = ZwSetInformationFile(handle, &iosb,
				&disInfo, sizeof(disInfo), FileDispositionInformation);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwSetInformationFile(%ws) failed(%x)\n", tmpEntry->NameBuffer, status));
			}
		}
		ZwClose(handle);
		if (NT_SUCCESS(status))
		{
			//删除成功，从链表里移出该目录
			RemoveEntryList(&tmpEntry->ENTRY);
			ExFreePool(tmpEntry->NameBuffer);
			ExFreePool(tmpEntry);
		}
		//如果失败，则表明在文件夹还有子文件夹，继续先删除子文件夹
	}// while (!IsListEmpty(&listHead)) 
	while (!IsListEmpty(&listHead))
	{
		tmpEntry = (PFILE_LIST_ENTRY)RemoveHeadList(&listHead);
		ExFreePool(tmpEntry->NameBuffer);
		ExFreePool(tmpEntry);
	}
	return status;
}


NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);
	DbgPrint("DriverUnload\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjcect, UNICODE_STRING pRegPath) {
	UNREFERENCED_PARAMETER(pRegPath);
	pDriverObjcect->DriverUnload = DriverUnload;
	myDelFileDir(L"\\??\\c:\\testDelfile");
	return STATUS_SUCCESS;
}