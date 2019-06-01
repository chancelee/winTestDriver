#include "hook.h"

//MLKF:����PID��ȡ����PATH
NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);

//����ShadowSSDT���ַ�ĺ�����ַ
__declspec(dllimport) _stdcall KeAddSystemServiceTable(PVOID, PVOID, PVOID, PVOID, PVOID);

//SSDT��
__declspec(dllimport)  ServiceDescriptorTableEntry KeServiceDescriptorTable;

//HOOK����������
static ULONG NtGdiBitBit_callnumber = 0;
static ULONG NtGdiStretchBit_callnumber = 0;

//csrss.exe������Ϣ
static PEPROCESS g_crsEProc = NULL;
//==============================HOOK   API===================================
typedef int(*NTGDIBITBIT)(
	IN HDC hdcDst,
	IN INT x,
	IN INT y,
	IN INT cx,
	IN INT cy,
	IN HDC hdcSrc,
	IN INT xSrc,
	IN INT ySrc,
	IN DWORD rop4,
	IN DWORD crBackColor,
	IN FLONG fl);

typedef int(*NTGDISTRETCHBIT)(
	IN HDC hdcDst,
	IN INT xDst,
	IN INT yDst,
	IN INT cxDst,
	IN INT cyDst,
	IN HDC hdcSrc,
	IN INT xSrc,
	IN INT ySrc,
	IN INT cxSrc,
	IN INT cySrc,
	IN DWORD dwRop,
	IN DWORD dwBackColor);
#define MAX_PATH (260)


EXTERN_C NTSYSAPI NTSTATUS NTAPI
ZwQueryInformationProcess(
	__in       HANDLE ProcessHandle,
	__in       PROCESSINFOCLASS ProcessInformationClass,
	__out      PVOID ProcessInformation,
	__in       ULONG ProcessInformationLength,
	__out_opt  PULONG ReturnLength
);

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
			0,
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
			0,
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
		}
		else
		{
			RtlCopyUnicodeString(FullPath, &ProcessPath);
		}
	}


	return nStatus;
}

//===========================================================================
//==============================NATIVR API===================================

//��ȡϵͳ��Ϣ
NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength);
/*
//�������
NTSTATUS ZwDuplicateObject(
	IN HANDLE                 SourceProcessHandle,
	IN PHANDLE                 SourceHandle,
	IN HANDLE                 TargetProcessHandle,
	OUT PHANDLE               TargetHandle,
	IN ACCESS_MASK             DesiredAccess OPTIONAL,
	IN BOOLEAN                 InheritHandle,
	IN ULONG                   Options );

//��ȡ������Ϣ
NTSTATUS ZwQueryObject(
	IN HANDLE                ObjectHandle,
	IN ULONG                 ObjectInformationClass,
	OUT PVOID                ObjectInformation,
	IN ULONG                 ObjectInformationLength,
	OUT PULONG               ReturnLength OPTIONAL);

//���ݽ���ID��ȡEPROCESS
NTSTATUS PsLookupProcessByProcessId(
	IN ULONG               ulProcId,
	OUT PEPROCESS *        pEProcess);

//�л�����������
NTSTATUS KeAttachProcess(PEPROCESS pPeb);
NTSTATUS KeDetachProcess();
*/
//===========================================================================
//ԭʼ��ַ
static NTGDIBITBIT g_OriginalNtGdiBitBit = NULL;
static NTGDISTRETCHBIT g_OriginalNtGdiStretchBit = NULL;


PVOID GetInfoTable(ULONG ATableType);
HANDLE GetCsrPid();

//˯�ߺ���(����)
BOOLEAN Sleep(ULONG MillionSecond)
{
	NTSTATUS st;
	LARGE_INTEGER DelayTime;
	//DelayTime = RtlConvertLongToLargeInteger((LONG)(-10000*MillionSecond));
	DelayTime.QuadPart = DELAY_ONE_MILLISECOND;
	DelayTime.QuadPart *= MillionSecond;
	st = KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	return (NT_SUCCESS(st));
}

//����ƥ��
BOOLEAN IsPatternMatch(PUNICODE_STRING Expression, PUNICODE_STRING Name, BOOLEAN IgnoreCase)
{
	return FsRtlIsNameInExpression(
		Expression,
		Name,
		IgnoreCase,//�����������ΪTRUE,��ôExpression�����Ǵ�д��
		NULL
	);
}
//SSDT��
__declspec(dllimport)  ServiceDescriptorTableEntry KeServiceDescriptorTable;

//��ȡShadowSSDT�ĵ�ַ
unsigned int getAddressOfShadowTable()
{
	unsigned int i;
	unsigned char *p;
	unsigned int dwordatbyte;

	p = (unsigned char*)KeAddSystemServiceTable;

	for (i = 0; i < 4096; i++, p++)
	{
		__try
		{
			dwordatbyte = *(unsigned int*)p;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}

		if (MmIsAddressValid((PVOID)dwordatbyte))
		{
			if (memcmp((PVOID)dwordatbyte, &KeServiceDescriptorTable, 16) == 0)
			{
				//�����ַ��SSDT��ͬ��������������
				if ((PVOID)dwordatbyte == &KeServiceDescriptorTable)
				{
					continue;
				}

				return dwordatbyte;
			}
		}
	}
	return 0;
}

ULONG getShadowTable()
{
	KeServiceDescriptorTableShadow = (PServiceDescriptorTableEntry)getAddressOfShadowTable();

	if (KeServiceDescriptorTableShadow == NULL)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hooker.sys: Couldnt find shadowtable!\n"));
		return FALSE;
	}
	else
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hooker.sys: Shadowtable entries: %d\n", KeServiceDescriptorTableShadow[1].NumberOfServices));
		return TRUE;
	}
}

//���ݲ���ϵͳ��ȷ�����庯���ķ���� ��FUCK Ӳ���룩
VOID InitCallNumber()
{
	ULONG majorVersion, minorVersion;
	PsGetVersion(&majorVersion, &minorVersion, NULL, NULL);
	if (majorVersion == 5 && minorVersion == 2)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "comint32: Running on Windows 2003\n"));

	}
	else if (majorVersion == 5 && minorVersion == 1)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "comint32: Running on Windows XP\n"));
		NtGdiBitBit_callnumber = 0x0d;
		NtGdiStretchBit_callnumber = 0x124;
	}
	else if (majorVersion == 5 && minorVersion == 0)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "comint32: Running on Windows 2000\n"));
	}
	else if (majorVersion == 6 && minorVersion == 1)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "comint32: Running on Windows 7\n"));
		NtGdiBitBit_callnumber = 0x0e;
		NtGdiStretchBit_callnumber = 0x12e;
	}
}

//��ȡϵͳ��Ϣ��FUCK���������ڴ棩
PVOID GetInfoTable(ULONG ATableType)
{
	ULONG mSize = 0x4000;
	PVOID mPtr = NULL;
	NTSTATUS St;
	do
	{
		mPtr = ExAllocatePoolWithTag(PagedPool, mSize, 'ONIS');
		memset(mPtr, 0, mSize);
		if (mPtr)
		{
			St = ZwQuerySystemInformation(ATableType, mPtr, mSize, NULL);
		}
		else return NULL;
		if (St == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(mPtr);
			mSize = mSize * 2;
		}
	} while (St == STATUS_INFO_LENGTH_MISMATCH);
	if (St == STATUS_SUCCESS) return mPtr;
	ExFreePool(mPtr);
	return NULL;
}


//��ȡ CSRSS.exe���
HANDLE GetCsrPid()
{
	HANDLE Process, hObject;
	HANDLE CsrId = (HANDLE)0;
	OBJECT_ATTRIBUTES obj;
	CLIENT_ID cid;
	UCHAR Buff[0x100];
	POBJECT_NAME_INFORMATION ObjName = (PVOID)&Buff;
	PSYSTEM_HANDLE_INFORMATION_EX Handles;
	ULONG r;

	Handles = GetInfoTable(SystemHandleInformation);

	if (!Handles) return CsrId;

	for (r = 0; r < Handles->NumberOfHandles; r++)
	{
		//Port object
		if (Handles->Information[r].ObjectTypeNumber == 21 ||   //xp
			Handles->Information[r].ObjectTypeNumber == 36)    //win7
		{
			InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			cid.UniqueProcess = (HANDLE)Handles->Information[r].ProcessId;
			cid.UniqueThread = 0;

			if (NT_SUCCESS(NtOpenProcess(&Process, PROCESS_DUP_HANDLE, &obj, &cid)))
			{
				if (NT_SUCCESS(ZwDuplicateObject(Process, (HANDLE)Handles->Information[r].Handle, NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
				{
					if (NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation, ObjName, 0x100, NULL)))
					{
						if (ObjName->Name.Buffer && !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
						{
							CsrId = (HANDLE)Handles->Information[r].ProcessId;
							KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwQueryObject��%wZ ID:%d  Type::%d\n", &ObjName->Name, Handles->Information[r].ProcessId, Handles->Information[r].ObjectTypeNumber));
						}
					}

					ZwClose(hObject);
				}

				ZwClose(Process);
			}
		}
	}

	ExFreePool(Handles);
	return CsrId;
}


//�����ͼ��
int APIENTRY MyNtGdiBitBlt(
	HDC hDCDest,
	INT XDest,
	INT YDest,
	INT Width,
	INT Height,
	HDC hDCSrc,
	INT XSrc,
	INT YSrc,
	DWORD ROP,
	DWORD crBackColor,
	FLONG fl)
{
	ULONG_PTR ulPtr = 0;
	DECLARE_UNICODE_STRING_SIZE(StrProcessName, 260);
	UNICODE_STRING uExpression;
	//�򵥹����£����ǽ���������ͷŹ�
	RtlInitUnicodeString(&uExpression, L"*FSCAPTURE.EXE");
	ulPtr = (ULONG_PTR)PsGetCurrentProcessId();
	GetProcessFullNameByPid((HANDLE)ulPtr, &StrProcessName);
	if (IsPatternMatch(&uExpression, &StrProcessName, TRUE))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hook MyNtGdiBitBlt Enter PRocess��%wZ\n", &StrProcessName));
		return FALSE;
	}
	return g_OriginalNtGdiBitBit(hDCDest,
		XDest,
		YDest,
		Width,
		Height,
		hDCSrc,
		XSrc,
		YSrc,
		ROP,
		crBackColor,
		fl);
}

//ȫ�������ڽ�ͼ
int APIENTRY MyNtGdiStretchBlt(
	HDC hDCDest,
	INT XOriginDest,
	INT YOriginDest,
	INT WidthDest,
	INT HeightDest,
	HDC hDCSrc,
	INT XOriginSrc,
	INT YOriginSrc,
	INT WidthSrc,
	INT HeightSrc,
	DWORD ROP,
	DWORD dwBackColor)
{
	ULONG_PTR ulPtr = 0;
	UNICODE_STRING uExpression;
	DECLARE_UNICODE_STRING_SIZE(StrProcessName, 260);

	//�򵥹����£����ǽ���������ͷŹ�
	RtlInitUnicodeString(&uExpression, L"*FSCAPTURE.EXE");
	ulPtr = (ULONG_PTR)PsGetCurrentProcessId();
	GetProcessFullNameByPid((HANDLE)ulPtr, &StrProcessName);
	if (IsPatternMatch(&uExpression, &StrProcessName, TRUE))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hook MyNtGdiStretchBlt Enter PRocess��%wZ\n", &StrProcessName));
		return TRUE;
	}
	return g_OriginalNtGdiStretchBit(hDCDest,
		XOriginDest,
		YOriginDest,
		WidthDest,
		HeightDest,
		hDCSrc,
		XOriginSrc,
		YOriginSrc,
		WidthSrc,
		HeightSrc,
		ROP,
		dwBackColor);
}

VOID SetHook()
{
	NTSTATUS status;
	//��ȡCsrss.exe�Ľ�����Ϣ
	status = PsLookupProcessByProcessId(GetCsrPid(), &g_crsEProc);
	if (!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PsLookupProcessByProcessId() error Error=%x\n", status));
		return;
	}
	KeAttachProcess(g_crsEProc);
	__try
	{
		//�ر�д������FUCK  PatchGuard��
		_asm
		{
			CLI                    //dissable interrupt
			MOV    EAX, CR0        //move CR0 register into EAX
			AND    EAX, NOT 10000H //disable WP bit 
			MOV    CR0, EAX        //write register back
		}
		if ((KeServiceDescriptorTableShadow != NULL) &&
			(NtGdiBitBit_callnumber != 0) &&
			(NtGdiStretchBit_callnumber != 0))
		{
			g_OriginalNtGdiBitBit = (NTGDIBITBIT)InterlockedExchange((PLONG)&KeServiceDescriptorTableShadow[1].ServiceTableBase[NtGdiBitBit_callnumber], (LONG)MyNtGdiBitBlt);
			g_OriginalNtGdiStretchBit = (NTGDISTRETCHBIT)InterlockedExchange((PLONG)&KeServiceDescriptorTableShadow[1].ServiceTableBase[NtGdiStretchBit_callnumber], (LONG)MyNtGdiStretchBlt);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SetHook Success\n"));
		}
		else
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SetHook faile\n"));
		}
		//�ָ�д����
		_asm
		{
			MOV    EAX, CR0        //move CR0 register into EAX
			OR     EAX, 10000H     //enable WP bit     
			MOV    CR0, EAX        //write register back        
			STI                    //enable interrupt
		}
	}
	__finally
	{
		KeDetachProcess();   //�л�����������Ǻ�.
		Sleep(50);
	}
}

VOID UnHook()
{
	NTSTATUS status;
	//�л���Session Leader csrss.exe
	status = PsLookupProcessByProcessId(GetCsrPid(), &g_crsEProc);
	if (!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PsLookupProcessByProcessId() error=%x\n", status));
		return;
	}
	KeAttachProcess(g_crsEProc);
	//ж��HOOK
	__try
	{
		_asm
		{
			CLI                    //dissable interrupt
			MOV    EAX, CR0        //move CR0 register into EAX
			AND EAX, NOT 10000H    //disable WP bit 
			MOV    CR0, EAX        //write register back
		}
		if ((KeServiceDescriptorTableShadow != NULL) &&
			(NtGdiBitBit_callnumber != 0) &&
			(NtGdiStretchBit_callnumber != 0))
		{
			InterlockedExchange((PLONG)&KeServiceDescriptorTableShadow[1].ServiceTableBase[NtGdiBitBit_callnumber], (LONG)g_OriginalNtGdiBitBit);
			InterlockedExchange((PLONG)&KeServiceDescriptorTableShadow[1].ServiceTableBase[NtGdiStretchBit_callnumber], (LONG)g_OriginalNtGdiStretchBit);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "UnHook Success\n"));
		}
		else
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "UnHook Success\n"));
		}
		_asm
		{
			MOV    EAX, CR0        //move CR0 register into gEAX
			OR     EAX, 10000H     //enable WP bit     
			MOV    CR0, EAX        //write register back        
			STI                    //enable interrupt
		}
	}
	__finally
	{
		KeDetachProcess();  //�л�����������Ǻ�.
		Sleep(50);
	}
}

void DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextObj = NULL;
	NTSTATUS status;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Enter DriverUnload\n"));
	//UnHook
	UnHook();
	//ѭ��ɾ�����������󴴽����豸
	pNextObj = pDriverObject->DeviceObject;
	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pNextObj->DeviceExtension;
		//ɾ����������
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
		IoDeleteSymbolicLink(&pLinkName);
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice(pDevExt->pDevice);
	}
}


NTSTATUS DDKDispatchRoutine(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Enter DispatchRoutine\n"));
	// ���IRP
	irpStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (irpStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_CREATE IRPS\n"));
		break;
	}
	case IRP_MJ_CLOSE:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_CLOSE IRPS\n"));
		break;
	}
	case IRP_MJ_READ:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_READ IRPS\n"));
		break;
	}
	case IRP_MJ_WRITE:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_WRITE IRPS\n"));
		break;
	}
	default:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "UnKnorwn IRPS\n"));
		break;
	}
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStates;
	PDEVICE_OBJECT pDeviceObject = NULL;
	PDEVICE_EXTENSION pDevExt = NULL;
	UNICODE_STRING devname;
	UNICODE_STRING symLinkName;
	do
	{
		RtlInitUnicodeString(&devname, DEVICE_NAME);
		//�����豸
		ntStates = IoCreateDevice(pDriverObject,
			sizeof(DEVICE_EXTENSION),
			&devname,
			FILE_DEVICE_UNKNOWN,
			0, TRUE,
			&pDeviceObject);

		if (!NT_SUCCESS(ntStates))
		{
			break;
		}

		pDeviceObject->Flags |= DO_BUFFERED_IO;     //ʹ�û�������ʽ��ͨ�ŷ�ʽ   DO_DIRECT_IO����R3���ڴ������ڴ棬MDL �ں�ͬ�����ʸ��ڴ棬���ڴ�ɷ����ڴ�Ҳ��������һ�飩
		pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
		pDevExt->pDevice = pDeviceObject;
		pDevExt->ustrDeviceName = devname;
		//������������

		RtlInitUnicodeString(&symLinkName, LINE_NAME);
		pDevExt->ustrSymLinkName = symLinkName;

		ntStates = IoCreateSymbolicLink(&symLinkName, &devname);
		if (!NT_SUCCESS(ntStates))
		{
			IoDeleteDevice(pDeviceObject);
			break;
		}
		ntStates = STATUS_SUCCESS;
	} while (FALSE);
	return ntStates;
}


NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispathClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(
	PDEVICE_OBJECT pDevObj,
	PIRP pIrp
)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack = NULL;
	ULONG uIoControlCode = 0;
	PVOID pIoBuffer = NULL;
	ULONG uInSize = 0;
	ULONG uOutSize = 0;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode; //������
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case IOCTL_HELLO:
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[NTModelDrv] Hello\n"));
		status = STATUS_SUCCESS;
	}
	break;
	}

	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;

	/////////////////////////////////////
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}







#pragma INITCODE
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	int i = 0;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Enter DriverEntry\n"));
	pDriverObject->DriverUnload = DriverUnload;     //ж������
	//����Ĭ����ǲ����
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DDKDispatchRoutine;
	}
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispathClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;


	//���shadow�ĵ�ַ
	getShadowTable();
	//��ȡHOOK��������
	InitCallNumber();

	//�����豸
	status = CreateDevice(pDriverObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	//HOOK
	SetHook();
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DriverEntry end\n"));
	return status;
}