/*
���˼�룬ʹ��list_entry����������ļ���Ȼ�����ջ������ʱ��
�����ļ��з���ջ�������ļ�ɾ��
ע����Ҫ�رղ�Ȼ��ɾ��ʧ��
Ϊ�˷�����ԣ�д���ļ���
*/

#include <ntddk.h>


//����LIST_ENTRY
typedef struct _FILE_LIST_ENTRY {
	LIST_ENTRY ENTRY;
	PWSTR NameBuffer;
}FILE_LIST_ENTRY, *PFILE_LIST_ENTRY;



//�����ļ���Ϣ�Ľṹ��
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
	IO_STATUS_BLOCK					iosb = { 0 };//io���������ɹ�true��ʧ��false
	FILE_DISPOSITION_INFORMATION	disInfo = { 0 };
	RtlInitUnicodeString(&uFileName, fileName);
	//��ʼ������
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
		FILE_ATTRIBUTE_NORMAL,//��ͨ�ļ������ļ���
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_ACCESS_DENIED) {
			//������ʾܾ���������ֻ���ģ�����ûdeleteȥ�򿪣�Ȼ���ȥ���������ó�narmal��ɾ����
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
				FILE_BASIC_INFORMATION		basicInfo = { 0 };//��ΪҪ�޸��ļ��������Դ�FileBasicInformation
				status = ZwQueryInformationFile(
					handle, &iosb, &basicInfo,
					sizeof(basicInfo),//Ҫ��ʲô������Ǹ�����صĽṹ��
					FileBasicInformation
				);
				if (!NT_SUCCESS(status)) {
					DbgPrint("ZwQueryInformationFile %wZ is failed %x\n", &uFileName, status);
				}
				//Ȼ���޸��ļ�����
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
	PWSTR                            	nameBuffer = NULL;	//��¼�ļ���
	PFILE_LIST_ENTRY                	tmpEntry = NULL;	//������
	LIST_ENTRY                        	listHead = { 0 };	//�����������ɾ�������е�Ŀ¼
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
	nameBuffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, uDirName.Length + sizeof(WCHAR), 'DRID');//Ϊ�˷�'\0'��sizeofwchar
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
	InitializeListHead(&listHead);//��ʼ������
	tmpEntry->NameBuffer = nameBuffer;
	InsertHeadList(&listHead, &tmpEntry->ENTRY);//��Ҫɾ�����ļ������Ȳ�������   
	// listHead���ʼ��ΪҪɾ�����ļ��С�
	//֮������ļ����µ��ļ���Ŀ¼���ж����ļ���������ɾ�����ж���Ŀ¼����Ž�listHead����
	//ÿ�ζ���listHead���ó�һ��Ŀ¼������
	while (!IsListEmpty(&listHead)) {
		//�Ƚ�Ҫɾ�����ļ��к�֮ǰ����ɾ�����ļ��бȽ�һ�£������������ȡ�����Ļ���֮ǰ��Entry������û��ɾ���ɹ���˵������ǿ�
		//�����Ѿ��ɹ�ɾ���������������������߻������ļ��У���ǰ�棬Ҳ��������������
		tmpEntry = (PFILE_LIST_ENTRY)RemoveHeadList(&listHead);
		if (preEntry == tmpEntry)
		{
			status = STATUS_DIRECTORY_NOT_EMPTY;
			break;
		}

		preEntry = tmpEntry;
		InsertHeadList(&listHead, &tmpEntry->ENTRY); //�Ž�ȥ����ɾ������������ݣ����Ƴ�������Ƴ�ʧ�ܣ���˵���������ļ��л���Ŀ¼�ǿ�

		RtlInitUnicodeString(&nameString, tmpEntry->NameBuffer);
		//��ʼ���ں˶���
		InitializeObjectAttributes(&objAttributes, &nameString, OBJ_CASE_INSENSITIVE, NULL, NULL);
		//���ļ�����ѯ
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
		//�ӵ�һ��ɨ��
		restartScan = TRUE;//��������һ����������Ҫ��false��ȻZwQueryDirectoryFileÿ�δӵ�һ����ʼ
		while (TRUE) //������ջ��ժ�����ļ���
		{
			buffer = NULL;
			bufferLength = 64;//����ָ������
			status = STATUS_BUFFER_OVERFLOW;
			while ((status == STATUS_BUFFER_OVERFLOW) || (status == STATUS_INFO_LENGTH_MISMATCH))//���Ϸ����ڴ棬ֱ������
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
					FALSE, NULL, restartScan);//False����һ��ֻ����ÿ��ֻ����һ���ļ��У�restartScan����Ϊtrue����˳��飬������ĳ�falseÿ�ζ��ǵ�һ���ļ���
			}
			//�����ѯ���ˣ���������жϡ���ѯ�����buffer��
			//����ǿ�˵����������
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
			//����һ���ڴ汣�浱ǰ�ļ���·���Ͳ�ѯ����Ŀ¼ƴ����һ�������Ŀ¼
			nameBuffer = (PWSTR)ExAllocatePoolWithTag(PagedPool,
				wcslen(tmpEntry->NameBuffer) * sizeof(WCHAR) + dirInfo->FileNameLength + 4, 'DRID');
			if (!nameBuffer)
			{
				KdPrint(("ExAllocatePool failed\n"));
				ExFreePool(buffer);
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			//tmpEntry->NameBuffer�ǵ�ǰ�ļ���·��
			//����Ĳ�����ƴ���ļ���������ļ�·��
			RtlZeroMemory(nameBuffer, wcslen(tmpEntry->NameBuffer) * sizeof(WCHAR) + dirInfo->FileNameLength + 4);
			wcscpy(nameBuffer, tmpEntry->NameBuffer);
			wcscat(nameBuffer, L"\\");
			RtlCopyMemory(&nameBuffer[wcslen(nameBuffer)], dirInfo->FileName, dirInfo->FileNameLength);
			RtlInitUnicodeString(&nameString, nameBuffer);
			if (dirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				//����Ƿ�'.'��'..'���������Ŀ¼����Ŀ¼����listHead
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
					//���ļ��в���listHead��
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
					InsertHeadList(&listHead, &localEntry->ENTRY); //����ͷ�����Ȱ����ļ������ɾ��
				}
			}
			else//������ļ���ֱ��ɾ��
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
			}//������ѭ���ﴦ����һ�����ļ��������ļ���

		}//  while (TRUE) ��һֱŪĿ¼����ļ����ļ���

		if (NT_SUCCESS(status))
		{
			//������Ŀ¼����ļ��ļ��У��ٴ���Ŀ¼�ļ���
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
			//ɾ���ɹ������������Ƴ���Ŀ¼
			RemoveEntryList(&tmpEntry->ENTRY);
			ExFreePool(tmpEntry->NameBuffer);
			ExFreePool(tmpEntry);
		}
		//���ʧ�ܣ���������ļ��л������ļ��У�������ɾ�����ļ���
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