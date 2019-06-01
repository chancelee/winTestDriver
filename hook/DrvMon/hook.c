#include "precomp.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define NUM(x) *(PULONG)((PUCHAR)x+1)
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SDT     SYSTEMSERVICE
#define KSDT KeServiceDescriptorTable

void StartHook(void);
void RemoveHook(void);



typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, *PPORT_MESSAGE;
//typedef struct _PORT_MESSAGE *PPORT_MESSAGE;
typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;



NTKERNELAPI NTSTATUS ZwLoadDriver(
	IN PUNICODE_STRING DriverServiceName);

NTSYSCALLAPI NTSTATUS NTAPI	 ZwAlpcSendWaitReceivePort(
	_In_ HANDLE PortHandle,
	_In_ ULONG 	Flags,
	_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE 	SendMessage,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	SendMessageAttributes,
	_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
	_Inout_opt_ PSIZE_T 	BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	ReceiveMessageAttributes,
	_In_opt_ PLARGE_INTEGER 	Timeout
);



NTSTATUS Hook_ZwLoadDriver(
	IN PUNICODE_STRING DriverServiceName);


NTSTATUS Hook_NtAlpcSendWaitReceivePort(HANDLE PortHandle,
	ULONG Flags,
	PPORT_MESSAGE SendMessage,
	PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
	PPORT_MESSAGE ReceiveMessage,
	PSIZE_T BufferLength,
	PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
	PLARGE_INTEGER 	Timeout);


//定义函数指针
typedef NTSTATUS(*ZWLOADDRIVER)(
	IN PUNICODE_STRING DriverServiceName);




typedef NTSTATUS(*RealNTALPCSENDWAITRECEIVEPORT)(_In_ HANDLE PortHandle,
	_In_ ULONG 	Flags,
	_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE 	SendMessage,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	SendMessageAttributes,
	_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
	_Inout_opt_ PSIZE_T 	BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	ReceiveMessageAttributes,
	_In_opt_ PLARGE_INTEGER 	Timeout);

static RealNTALPCSENDWAITRECEIVEPORT OldNtAlpcSendWaitReceivePort;


static ZWLOADDRIVER              OldZwLoadDriver;



static HANDLE g_Pid = 0;    //加载驱动的进程PID

//正则匹配
BOOLEAN IsPatternMatch(PUNICODE_STRING Expression, PUNICODE_STRING Name, BOOLEAN IgnoreCase)
{
	return FsRtlIsNameInExpression(
		Expression,
		Name,
		IgnoreCase,//如果这里设置为TRUE,那么Expression必须是大写的
		NULL
	);
}


NTSTATUS Hook_ZwLoadDriver(
	IN PUNICODE_STRING DriverServiceName)//服务名，在注册表
{
	UNICODE_STRING			uPath = { 0 };
	NTSTATUS				status = STATUS_SUCCESS;
	BOOL					skipOriginal = FALSE;
	WCHAR					szTargetDriver[MAX_PATH] = { 0 };
	WCHAR					szTarget[MAX_PATH] = { 0 };
	R3_RESULT				CallBackResult = R3Result_Pass;
	WCHAR					wszPath[MAX_PATH] = { 0 };
	UNICODE_STRING ustrProcessPath = { 0 };
	WCHAR				wszProcessPath[MAX_PATH] = { 0 };
	__try
	{
		UNICODE_STRING CapturedName;

		if ((ExGetPreviousMode() == KernelMode) ||
			(DriverServiceName == NULL))
		{
			skipOriginal = TRUE;
			status = OldZwLoadDriver(DriverServiceName);
			return status;
		}

		uPath.Length = 0;
		uPath.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uPath.Buffer = wszPath;


		CapturedName = ProbeAndReadUnicodeString(DriverServiceName);

		ProbeForRead(CapturedName.Buffer,
			CapturedName.Length,
			sizeof(WCHAR));

		RtlCopyUnicodeString(&uPath, &CapturedName);

		if (ntGetDriverImagePath(&uPath, szTargetDriver))
		{

			// 			if(ntIsDosDeviceName(szTargetDriver))
			// 			{
			// 				if( ntGetNtDeviceName(szTargetDriver, 
			// 					szTarget))
			// 				{
			// 					RtlStringCbCopyW(szTargetDriver, 
			// 						sizeof(szTargetDriver), 
			// 						szTarget);
			// 				}
			// 			}
			DbgPrint("Driver:%ws will be loaded\n", szTargetDriver);
			ustrProcessPath.Buffer = wszProcessPath;
			ustrProcessPath.Length = 0;
			ustrProcessPath.MaximumLength = sizeof(wszProcessPath);
			GetProcessFullNameByPid(PsGetCurrentProcessId(), &ustrProcessPath);
			DbgPrint("Parent:%wZ\n", &ustrProcessPath);

			//CallBackResult = hipsGetResultFromUser(L"加载", szTargetDriver, NULL,User_DefaultNon);//弹窗
			if (CallBackResult == R3Result_Block)
			{
				return STATUS_ACCESS_DENIED;
			}

			skipOriginal = TRUE;
			status = OldZwLoadDriver(DriverServiceName);
			return status;
		}


	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (skipOriginal)
		return status;

	return OldZwLoadDriver(DriverServiceName);
}



NTSTATUS Hook_NtAlpcSendWaitReceivePort(HANDLE PortHandle,
	ULONG Flags,
	PPORT_MESSAGE SendMessage,
	PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
	PPORT_MESSAGE ReceiveMessage,
	PSIZE_T BufferLength,
	PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
	PLARGE_INTEGER 	Timeout)
{
	UNICODE_STRING StrProcessName = { 0 };
	StrProcessName.MaximumLength = MAX_PATH * sizeof(WCHAR);
	StrProcessName.Length = 0;
	WCHAR tmp[MAX_PATH] = { 0 };
	StrProcessName.Buffer = tmp;
	UNICODE_STRING uExpression = { 0 };
	RtlInitUnicodeString(&uExpression, L"*SERVICES.EXE");
	__try {
		if (SendMessage)
		{
			g_Pid = PsGetCurrentProcessId();
			DbgPrint("DriverLoad PID=%d\n", g_Pid);
			GetProcessFullNameByPid((HANDLE)g_Pid, &StrProcessName);
			if (IsPatternMatch(&uExpression, &StrProcessName, TRUE))
			{
				DbgPrint("Parent:%wZ\n", &StrProcessName);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
		return OldNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage,
			SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes,
			Timeout);
}




NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED *Dst,
	IN CONST VOID UNALIGNED *Src,
	IN ULONG Length)
{
	PMDL pmdl = IoAllocateMdl(Dst, Length, 0, 0, NULL);
	if (pmdl == NULL)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(pmdl);
	unsigned int *Mapped = (unsigned int *)MmMapLockedPages(pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(pmdl);
		return STATUS_UNSUCCESSFUL;
	}

	KIRQL kirql = KeRaiseIrqlToDpcLevel();

	RtlCopyMemory(Mapped, Src, Length);

	KeLowerIrql(kirql);

	MmUnmapLockedPages((PVOID)Mapped, pmdl);
	IoFreeMdl(pmdl);

	return STATUS_SUCCESS;

}

void StartHook(void)
{
	//获取未导出的服务函数索引号
	HANDLE    hFile;
	PCHAR    pDllFile;
	ULONG  ulSize;
	ULONG  ulByteReaded;


	OldZwLoadDriver = SDT(ZwLoadDriver);
	ULONG hookAddr = (ULONG)Hook_ZwLoadDriver;
	OldNtAlpcSendWaitReceivePort = SDT(ZwAlpcSendWaitReceivePort);
	ULONG hookAddr1 = (ULONG)Hook_NtAlpcSendWaitReceivePort;
	
	
	
	
	RtlSuperCopyMemory(&SDT(ZwLoadDriver), &hookAddr, 4);    //关闭
	
	
	RtlSuperCopyMemory(&SDT(ZwAlpcSendWaitReceivePort), &hookAddr1, 4);
	return;
}

void RemoveHook(void)
{
	
	ULONG hookAddr = (ULONG)OldZwLoadDriver;
	RtlSuperCopyMemory(&SDT(ZwLoadDriver), &hookAddr, 4);    //关闭

	ULONG hookAddr1 = (ULONG)OldNtAlpcSendWaitReceivePort;
	RtlSuperCopyMemory(&SDT(ZwAlpcSendWaitReceivePort), &hookAddr1, 4);    //关闭

}




