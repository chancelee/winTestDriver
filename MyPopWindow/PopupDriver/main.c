//author tomzhou
//email:soundfuture@sohu.com
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include "Ioctlcmd.h"
#include "main.h"


#define		DEVICE_NAME		L"\\device\\PopupDrv"
#define		LINK_NAME		L"\\dosDevices\\PopupDrv"


/*

NTKERNELAPI NTSTATUS

PsLookupProcessByProcessId(

	IN HANDLE ProcessId,

	OUT PEPROCESS *Process

);





NTSTATUS

IoQueryFileDosDeviceName(

	IN PFILE_OBJECT FileObject,

	OUT POBJECT_NAME_INFORMATION *ObjectNameInformation

); 



*/


NTSTATUS
NTAPI
ZwQueryInformationProcess(

	__in HANDLE ProcessHandle,

	__in PROCESSINFOCLASS ProcessInformationClass,

	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,

	__in ULONG ProcessInformationLength,

	__out_opt PULONG ReturnLength

);

LIST_ENTRY g_OperList;
ERESOURCE  g_OperListLock;

LIST_ENTRY g_WaitList;
ERESOURCE  g_WaitListLock;

LIST_ENTRY g_PendingIrpList;
ERESOURCE  g_PendingIrpListLock;

ULONG g_ulCurrentWaitID = 0;//�¼�ID

VOID __stdcall LockWrite(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lpLock, TRUE);
}


VOID __stdcall UnLockWrite(ERESOURCE *lpLock)
{
    ExReleaseResourceLite(lpLock);
    KeLeaveCriticalRegion();
}


VOID __stdcall LockRead(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(lpLock, TRUE);
}


VOID __stdcall LockReadStarveWriter(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireSharedStarveExclusive(lpLock, TRUE);
}


VOID __stdcall UnLockRead(ERESOURCE *lpLock)
{
    ExReleaseResourceLite(lpLock);
    KeLeaveCriticalRegion();
}


VOID __stdcall InitLock(ERESOURCE *lpLock)
{
    ExInitializeResourceLite(lpLock);
}

VOID __stdcall DeleteLock(ERESOURCE *lpLock)
{
    ExDeleteResourceLite(lpLock);
}

VOID __stdcall InitList(LIST_ENTRY *list)
{
    InitializeListHead(list);
}

VOID
CommonIrpCancel(
				IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp
				)
{
	KIRQL				CancelOldIrql	= Irp->CancelIrql;
	
	IoReleaseCancelSpinLock(DISPATCH_LEVEL);
	KeLowerIrql(CancelOldIrql);

	LockWrite(&g_PendingIrpListLock);
	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
	UnLockWrite(&g_PendingIrpListLock);
	
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}





NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath)
{

	HANDLE               hFile = NULL;
	ULONG                nNeedSize = 0;
	NTSTATUS             nStatus = STATUS_SUCCESS;
	NTSTATUS             nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
	PEPROCESS            Process = NULL;
	KAPC_STATE           ApcState = { 0 };
	PVOID                lpBuffer = NULL;
	OBJECT_ATTRIBUTES	 ObjectAttributes = { 0 };
	IO_STATUS_BLOCK      IoStatus = { 0 };
	PFILE_OBJECT         FileObject = NULL;
	PFILE_NAME_INFORMATION FileName = NULL;
	WCHAR                FileBuffer[MAX_PATH] = { 0 };
	DECLARE_UNICODE_STRING_SIZE(ProcessPath, MAX_PATH);
	DECLARE_UNICODE_STRING_SIZE(DosDeviceName, MAX_PATH);

	PAGED_CODE();

	nStatus = PsLookupProcessByProcessId(nPid, &Process);
	if (NT_ERROR(nStatus))
	{
		KdPrint(("%s error PsLookupProcessByProcessId.\n", __FUNCTION__));
		return nStatus;
	}



	__try
	{

		KeStackAttachProcess(Process, &ApcState);

		nStatus = ZwQueryInformationProcess(
			NtCurrentProcess(),
			ProcessImageFileName,
			NULL,
			NULL,
			&nNeedSize
		);

		if (STATUS_INFO_LENGTH_MISMATCH != nStatus)
		{
			KdPrint(("%s NtQueryInformationProcess error.\n", __FUNCTION__));
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;

		}

		lpBuffer = ExAllocatePoolWithTag(NonPagedPool, nNeedSize, 'GetP');
		if (lpBuffer == NULL)
		{
			KdPrint(("%s ExAllocatePoolWithTag error.\n", __FUNCTION__));
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;
		}

		nStatus = ZwQueryInformationProcess(
			NtCurrentProcess(),
			ProcessImageFileName,
			lpBuffer,
			nNeedSize,
			&nNeedSize
		);

		if (NT_ERROR(nStatus))
		{
			KdPrint(("%s NtQueryInformationProcess error2.\n", __FUNCTION__));
			__leave;
		}

		RtlCopyUnicodeString(&ProcessPath, (PUNICODE_STRING)lpBuffer);
		InitializeObjectAttributes(
			&ObjectAttributes,
			&ProcessPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);

		nStatus = ZwCreateFile(
			&hFile,
			FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
			NULL,
			0
		);

		if (NT_ERROR(nStatus))
		{
			hFile = NULL;
			__leave;
		}

		nStatus = ObReferenceObjectByHandle(
			hFile,
			NULL,
			*IoFileObjectType,
			KernelMode,
			(PVOID*)&FileObject,
			NULL
		);

		if (NT_ERROR(nStatus))
		{
			FileObject = NULL;
			__leave;
		}

		FileName = (PFILE_NAME_INFORMATION)FileBuffer;

		nStatus = ZwQueryInformationFile(
			hFile,
			&IoStatus,
			FileName,
			sizeof(WCHAR)*MAX_PATH,
			FileNameInformation
		);

		if (NT_ERROR(nStatus))
		{
			__leave;
		}

		if (FileObject->DeviceObject == NULL)
		{
			nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
			__leave;
		}

		nDeviceStatus = RtlVolumeDeviceToDosName(FileObject->DeviceObject, &DosDeviceName);

	}
	__finally
	{
		if (NULL != FileObject)
		{
			ObDereferenceObject(FileObject);
		}

		if (NULL != hFile)
		{
			ZwClose(hFile);
		}

		if (NULL != lpBuffer)
		{
			ExFreePool(lpBuffer);
		}

		KeUnstackDetachProcess(&ApcState);


	}

	if (NT_SUCCESS(nStatus))
	{
		RtlInitUnicodeString(&ProcessPath, FileName->FileName);

		if (NT_SUCCESS(nDeviceStatus))
		{
			RtlCopyUnicodeString(FullPath, &DosDeviceName);
			RtlUnicodeStringCat(FullPath, &ProcessPath);
			DbgPrint("uFullPath is %wZ\n", ProcessPath.Buffer);
			DbgPrint("uFullPath is %wZ\n", DosDeviceName.Buffer);
		}
		else
		{
			RtlCopyUnicodeString(FullPath, &ProcessPath);
		}
	}


	return nStatus;
}






VOID
PendingIrpToList(PIRP pIrp, PLIST_ENTRY pIrpList, PDRIVER_CANCEL pfnCancelRoutine)
{
	InsertTailList(pIrpList, &pIrp->Tail.Overlay.ListEntry);
	IoMarkIrpPending(pIrp);
	IoSetCancelRoutine(pIrp, pfnCancelRoutine);//R3:CancelIo(handle),//CancelIo from r3  or IoCancelIrp to call  
}

//����Ӧ�ò��read()����
NTSTATUS DispatchRead (
    IN PDEVICE_OBJECT	pDevObj,
    IN PIRP	lpIrp) 
{
	NTSTATUS			ntStatus		= STATUS_SUCCESS;
	ULONG				ulLength		= 0;
	PIO_STACK_LOCATION	lpIrpStack		= IoGetCurrentIrpStackLocation(lpIrp);
	OP_INFO				*lpOpInfoEntry	= NULL;
	LIST_ENTRY			*lpOpInfoList	= NULL;
	
	if (lpIrpStack->Parameters.Read.Length < sizeof(RING3_OP_INFO))
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		ulLength = 0;
		goto Completed;
	}
	
	LockWrite(&g_OperListLock);
	
	if (IsListEmpty(&g_OperList) == TRUE)
	{
		UnLockWrite(&g_OperListLock);
		
		LockWrite(&g_PendingIrpListLock);
		PendingIrpToList(lpIrp, &g_PendingIrpList, CommonIrpCancel);//����ȡ�����̵�ԭ����Ӧ�ò�������Ҫ�˳���pendingirpҪȡ����
		UnLockWrite(&g_PendingIrpListLock);
	
		goto Pended;
	}
	
	lpOpInfoList = g_OperList.Flink;
	lpOpInfoEntry = CONTAINING_RECORD(lpOpInfoList, OP_INFO, m_List);
	RemoveEntryList(lpOpInfoList);
	UnLockWrite(&g_OperListLock);
	
	RtlCopyMemory(lpIrp->AssociatedIrp.SystemBuffer, lpOpInfoEntry, sizeof(RING3_OP_INFO));
	ntStatus = STATUS_SUCCESS;
	ulLength = sizeof(RING3_OP_INFO);
	
	ExFreePool(lpOpInfoEntry);
	
Completed:
	
	lpIrp->IoStatus.Status = ntStatus;
	lpIrp->IoStatus.Information = ulLength;
	IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
	return ntStatus;
	
Pended:
	return STATUS_PENDING;
}

WAIT_LIST_ENTRY*
FindWaitEntryByID(PLIST_ENTRY pListHead, ULONG ulWaitID)
{
    PLIST_ENTRY			pList		= NULL;
    WAIT_LIST_ENTRY		*pEntry	= NULL;
	
    for (pList = pListHead->Flink; pList != pListHead; pList = pList->Flink)
    {
        pEntry = CONTAINING_RECORD(pList, WAIT_LIST_ENTRY, m_List);
        if (pEntry->m_ulWaitID == ulWaitID)
        {
            return pEntry;
        }
    }
    return NULL;
}

ULONG MakeWaitID()
{
    InterlockedIncrement(&g_ulCurrentWaitID);
    return g_ulCurrentWaitID;
}

BOOLEAN
CompletePendingIrp(LIST_ENTRY* pIrpListHead, OP_INFO* pOpInfo)
{
	LIST_ENTRY			*lpIrpList	= NULL;
	PIRP				lpIrp		= NULL;
	BOOLEAN				bFound		= FALSE;
	BOOLEAN				bReturn		= FALSE;
	
	if (IsListEmpty(pIrpListHead) == TRUE)
	{
		return bReturn;
	}
	
	for (lpIrpList = pIrpListHead->Flink; lpIrpList != pIrpListHead; lpIrpList = lpIrpList->Flink)
	{
		lpIrp = CONTAINING_RECORD(lpIrpList, IRP, Tail.Overlay.ListEntry);
		if (IoSetCancelRoutine(lpIrp, NULL))//returns the previous value of Irp->CancelRoutine. no Cancel routine, or cancellation in progress, returns NULL.
											//�����pendingirp��irp�ͻ�����һ��cance���̣��������־�˵���ҵ���Ȼ���������
		{
			RemoveEntryList(lpIrpList);
			bFound = TRUE;
			break;
		}
	}
	
	if (bFound == FALSE)
	{
		return bReturn;
	}
	
	RtlCopyMemory(lpIrp->AssociatedIrp.SystemBuffer, pOpInfo, sizeof(RING3_OP_INFO));//��Ϊ�����ڽṹ��������Կ������Ľṹ��ͺܷ����ˣ��պ�û�к�������ֻ��Ҫ����Ϣ
	
	lpIrp->IoStatus.Information = sizeof(RING3_OP_INFO);
	lpIrp->IoStatus.Status = STATUS_SUCCESS;
	
	IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
	bReturn = TRUE;
	
	return bReturn;
}


R3_RESULT __stdcall GetResultFromUser()//����ѹ������ݷŵ�operList��
{
    R3_RESULT			NotifyResult	= R3Result_Pass;
    BOOLEAN				bSuccess		=  FALSE;
    NTSTATUS			Status			= STATUS_SUCCESS;
    LARGE_INTEGER		WaitTimeOut		= {0};
    OP_INFO				*lpNewOpInfo	= NULL;
    WAIT_LIST_ENTRY		*lpNewWaitEntry = NULL;
    ULONG_PTR ulPtr = 0;
 
	UNICODE_STRING uFullPath = { 0 };
	uFullPath.MaximumLength = MAX_PATH* sizeof(WCHAR);
	uFullPath.Buffer=ExAllocatePoolWithTag(PagedPool, MAX_PATH * sizeof(WCHAR), 'ELIF');
	RtlZeroMemory(uFullPath.Buffer, MAX_PATH * sizeof(WCHAR));


    lpNewOpInfo = (OP_INFO*)ExAllocatePool(PagedPool, sizeof(OP_INFO));
	RtlZeroMemory(lpNewOpInfo, sizeof(OP_INFO));

    if (lpNewOpInfo == NULL)
    {
        return NotifyResult;
    }

    //�����¼���ص����ݣ����͸�R3���������ID�����֣�·�����Լ�����������������޸ģ�ɾ�����ȵ�
	//��Ȼ���������ֻ�Ǽ򵥵Ĳ�׽�˽��̵�ID�������ֵ�
    ulPtr = (ULONG_PTR)PsGetCurrentProcessId();//��ù����߽���PID
	//��ȫ·��


	GetProcessFullNameByPid((HANDLE)ulPtr, &uFullPath);
	DbgPrint("uFullPath is %wZ\n", uFullPath.Buffer);
	
	RtlCopyMemory(lpNewOpInfo->m_ProcessName, uFullPath.Buffer, uFullPath.Length);
	ExFreePool(uFullPath.Buffer);

    lpNewOpInfo->m_ulProcessID = (ULONG_PTR)ulPtr;

    lpNewOpInfo->m_ulWaitID = MakeWaitID();//����ͬ�¼���ID



    lpNewWaitEntry = (WAIT_LIST_ENTRY*)ExAllocatePool(NonPagedPool, sizeof(WAIT_LIST_ENTRY));
    if (lpNewWaitEntry == NULL)
    {
        goto End;
    }

    lpNewWaitEntry->m_ulWaitID = lpNewOpInfo->m_ulWaitID;
    KeInitializeEvent(&lpNewWaitEntry->m_ulWaitEvent, SynchronizationEvent, FALSE);
	
    // ����ȴ����У��ȴ�R3�·����
    LockWrite(&g_WaitListLock);
	InsertTailList(&g_WaitList, &lpNewWaitEntry->m_List);
    UnLockWrite(&g_WaitListLock);



    LockWrite(&g_PendingIrpListLock);
    bSuccess = CompletePendingIrp(&g_PendingIrpList, lpNewOpInfo);//�鿴�Ƿ���δ��ɵ�pendingIRP��ֱ�ӽ���OperInfo����R3
    UnLockWrite(&g_PendingIrpListLock);

	if (bSuccess == FALSE)	//���pending irpʧ�ܣ���lpNewOpInfo����operlist
	{
        LockWrite(&g_OperListLock);
        InsertTailList(&g_OperList, &lpNewOpInfo->m_List); //����OperList,�ȴ�R3����ȡ
        UnLockWrite(&g_OperListLock);
   
        lpNewOpInfo = NULL;
	}

	// ��40�룬��3��30�볬ʱ
    WaitTimeOut.QuadPart = -40 * 10000000;
	Status = KeWaitForSingleObject(&lpNewWaitEntry->m_ulWaitEvent, 
		Executive, KernelMode, FALSE, &WaitTimeOut);//�ȴ�R3�·��������ֹ����

    LockWrite(&g_WaitListLock);
    RemoveEntryList(&lpNewWaitEntry->m_List);
    UnLockWrite(&g_WaitListLock);

    if (Status != STATUS_TIMEOUT)
    {
        if (lpNewWaitEntry->m_bBlocked == TRUE)
        {
            NotifyResult = R3Result_Block;
        }
        else
        {
            NotifyResult = R3Result_Pass;
        }
    }
    else
    {
        NotifyResult =  R3Result_DefaultNon;
    }

End:
    if (lpNewWaitEntry != NULL)
    {
        ExFreePool(lpNewWaitEntry);
    }
    if (lpNewOpInfo != NULL)
    {
        ExFreePool(lpNewOpInfo);
    }
    return NotifyResult;
}


//����Ӧ�ò��DeviceIoControl()
NTSTATUS DispatchControl(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp 
    )
{
    PIO_STACK_LOCATION      	lpIrpStack			= NULL;
    PVOID                   	inputBuffer			= NULL;
    PVOID                   	outputBuffer		= NULL;
    ULONG                   	inputBufferLength	= 0;
    ULONG                   	outputBufferLength	= 0;
    ULONG                   	ioControlCode		= 0;
    NTSTATUS		     		ntStatus			= STATUS_SUCCESS;
	
    ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	//��ȡ��ǰIRP��ջλ��
	lpIrpStack = IoGetCurrentIrpStackLocation (Irp);
	//������뻺��ͳ���
	inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = lpIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//����������ͳ���
	outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = lpIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//��ȡ������
	ioControlCode = lpIrpStack->Parameters.DeviceIoControl.IoControlCode;
		
	switch (ioControlCode ) 
	{
		case IOCTL_SEND_RESULT_TO_R0://R3���ں˴��ݵ������������Ӧ��WaitID�¼������û�ѡ����
		{
				RING3_REPLY			*lpReply		= NULL;
				WAIT_LIST_ENTRY		*lpWaitEntry	= NULL;
							
				if (lpIrpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(RING3_REPLY))
				{
						Irp->IoStatus.Information = 0;
						Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
						break;
				}
				lpReply = (RING3_REPLY*)Irp->AssociatedIrp.SystemBuffer;
							
				LockWrite(&g_WaitListLock);
				lpWaitEntry = FindWaitEntryByID(&g_WaitList, lpReply->m_ulWaitID);//����WaitID���ҵ���Ӧ�������¼�
							
				if (lpWaitEntry != NULL)
				{
						lpWaitEntry->m_bBlocked = lpReply->m_ulBlocked;
						KeSetEvent(&lpWaitEntry->m_ulWaitEvent, 0, FALSE);//����EVENT�¼�������GetResultFromUser()��ĵȴ��¼�
				}
							
				UnLockWrite(&g_WaitListLock);
							
				Irp->IoStatus.Information = 0;
				ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

		case IOCTL_XXX_ATTACK://��������ģ��
		{
				R3_RESULT notifyResult = R3Result_DefaultNon; 

							
				notifyResult = GetResultFromUser();//��R3��õ�����������ֹ���ǷŹ�
				if (notifyResult == R3Result_Block)
				{
						DbgPrint("��ֹ\n");
						*(ULONG *)outputBuffer = 0;
						ntStatus = STATUS_SUCCESS;
				}
				else if (notifyResult == R3Result_Pass)
				{
						DbgPrint("����\n");
						*(ULONG *)outputBuffer = 1;
						ntStatus = STATUS_SUCCESS;
				}
				else
				{
						DbgPrint("��ʱ����\n");
						*(ULONG *)outputBuffer = 1;
						ntStatus = STATUS_SUCCESS;
				}

		}
		Irp->IoStatus.Information = sizeof(ULONG);
		Irp->IoStatus.Status = ntStatus;
		break;

		default:
		break;
	}
		
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return ntStatus;  
}

//����Unload��������
VOID DriverUnload (
    IN PDRIVER_OBJECT	pDriverObject) 
{
	UNICODE_STRING         deviceLink = {0};

	RtlInitUnicodeString( &deviceLink, LINK_NAME);
	IoDeleteSymbolicLink( &deviceLink);
	IoDeleteDevice( pDriverObject->DeviceObject );

	return;
}

//����Ӧ�ò��create()����
NTSTATUS DispatchCreate (
	IN PDEVICE_OBJECT	pDevObj,
	IN PIRP	pIrp) 
{
	//����IO״̬��Ϣ
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	//���IRP�����������²���������
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

//����Ӧ�ò��close()����
NTSTATUS DispatchClose (
    IN PDEVICE_OBJECT	pDevObj,
    IN PIRP	pIrp) 
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

//����������ڣ���ɸ��ֳ�ʼ�������������豸����
NTSTATUS DriverEntry (
    IN PDRIVER_OBJECT pDriverObject,
    IN PUNICODE_STRING pRegistryPath) 
{
	NTSTATUS 		status		= STATUS_SUCCESS;
	PDEVICE_OBJECT 	pDevObj		= NULL;
	UNICODE_STRING 	uDevName	= {0};
	UNICODE_STRING 	uLinkName	= {0};
	DbgPrint("Driver Load begin!\n");

	InitLock(&g_OperListLock);
	InitLock(&g_WaitListLock);
	InitLock(&g_PendingIrpListLock);
	
	InitList(&g_OperList);
	InitList(&g_WaitList);
	InitList(&g_PendingIrpList);


	//��ʼ����������

	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
				DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
				DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] =
				DispatchRead;//���������ȡOperList
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = 
				DispatchControl;//����Ӧ�ò㴦��ķ��ؽ�� 
	pDriverObject->DriverUnload	= 
				DriverUnload;

	RtlInitUnicodeString(&uDevName, DEVICE_NAME);
	//���������豸
	status = IoCreateDevice( pDriverObject,
			0,//sizeof(DEVICE_EXTENSION)
			&uDevName,
			FILE_DEVICE_UNKNOWN,
			0, FALSE,
			&pDevObj );
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice Failed:%x\n", status);
		return status;
	}

	pDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	//������������
	status = IoCreateSymbolicLink( &uLinkName, &uDevName );
	if (!NT_SUCCESS(status)) 
	{
		//STATUS_INSUFFICIENT_RESOURCES 	��Դ����
		//STATUS_OBJECT_NAME_EXISTS 		ָ������������
		//STATUS_OBJECT_NAME_COLLISION 	�������г�ͻ
		DbgPrint("IoCreateSymbolicLink Failed:%x\n", status);
		IoDeleteDevice( pDevObj );
		return status;
	}
	DbgPrint("Driver Load success!\n");
	return status;
}

