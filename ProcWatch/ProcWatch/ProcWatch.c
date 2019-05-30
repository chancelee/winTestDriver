#include "ntddk.h"
#include "windef.h"
#include "string.h"

#define SYSNAME "System"
ULONG ProcessNameOffset =0;

ULONG GetProcessNameOffset();

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS CommonDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS PsLookupProcessByProcessId(IN ULONG ulProcId, OUT PEPROCESS *pEProcess);

VOID ProcessCreateMon( IN HANDLE hParentId, IN HANDLE PId, IN BOOLEAN bCreate);
VOID ThreadCreateMon(IN HANDLE PId, IN HANDLE TId, IN BOOLEAN bCreate);
//VOID ImageCreateMon(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo );

// 驱动入口
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath ) 

{
	UNICODE_STRING	nameString, linkString;
	PDEVICE_OBJECT	deviceObject;
	NTSTATUS		status;
	int				i;
	//建立设备

	RtlInitUnicodeString( &nameString, L"\\Device\\ProcWatch" );
	status = IoCreateDevice( DriverObject,
		0,
		&nameString,
		FILE_DEVICE_UNKNOWN,
		0,
		TRUE,
		&deviceObject
		);           

	if (!NT_SUCCESS( status ))
	{
		return status;
	}

	RtlInitUnicodeString( &linkString, L"\\DosDevices\\ProcWatch" );
	status = IoCreateSymbolicLink(&linkString, &nameString);

	if (!NT_SUCCESS( status ))
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}  
	ProcessNameOffset = GetProcessNameOffset();
	if (ProcessNameOffset == 0)
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}
	//status = PsSetLoadImageNotifyRoutine(ImageCreateMon);

	//if (!NT_SUCCESS( status ))
	//{
	//	IoDeleteDevice(DriverObject->DeviceObject);
	//	DbgPrint("PsSetLoadImageNotifyRoutine()\n");
	//	return status;
	//}

	status = PsSetCreateThreadNotifyRoutine(ThreadCreateMon);
	if (!NT_SUCCESS( status ))
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		DbgPrint("PsSetCreateThreadNotifyRoutine()\n");
		return status;
	}  

	status = PsSetCreateProcessNotifyRoutine(ProcessCreateMon, FALSE);
	if (!NT_SUCCESS( status ))
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		DbgPrint("PsSetCreateProcessNotifyRoutine()\n");
		return status;
	}  

	for ( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)  
	{
		DriverObject->MajorFunction[i] = CommonDispatch;
	}

	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS; 
} 

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING linkString;
	//PsRemoveLoadImageNotifyRoutine(ImageCreateMon);
	PsRemoveCreateThreadNotifyRoutine(ThreadCreateMon);
	PsSetCreateProcessNotifyRoutine(ProcessCreateMon, TRUE);
	RtlInitUnicodeString(&linkString, L"\\DosDevices\\ProcWatch");
	IoDeleteSymbolicLink(&linkString);
	IoDeleteDevice(DriverObject->DeviceObject);
}

//处理设备对象操作
NTSTATUS CommonDispatch (IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)

{ 
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0L;
	IoCompleteRequest( Irp, 0 );
	return Irp->IoStatus.Status;
}

HANDLE g_dwProcessId;
BOOL g_bMainThread;

VOID ProcessCreateMon ( IN HANDLE hParentId, IN HANDLE PId,IN BOOLEAN bCreate )
{
	PEPROCESS	EProcess;
	ULONG		ulCurrentProcessId;
	LPTSTR		lpCurProc;
	NTSTATUS	status;

#ifdef _AMD64_
	ULONG ProcessId = HandleToUlong(PId);
	status = PsLookupProcessByProcessId( ProcessId, &EProcess);
#else
	HANDLE ProcessId =PId;
	status = PsLookupProcessByProcessId( (ULONG)PId, &EProcess);
#endif

	if (!NT_SUCCESS( status ))
	{
		DbgPrint("PsLookupProcessByProcessId()\n");
		return;
	}

	if ( bCreate )
	{
		g_bMainThread = TRUE;
		lpCurProc = (LPTSTR)EProcess;
		lpCurProc = lpCurProc + ProcessNameOffset;
		DbgPrint( "CREATE PROCESS = PROCESS NAME: %s , PROCESS PARENTID: %d, PROCESS ID: %d, PROCESS ADDRESS %x:\n", 
			lpCurProc,
			hParentId,
			PId,
			EProcess );
	}
	else
	{
		DbgPrint( "TERMINATED == PROCESS ID: %d\n", PId);
	}
}


VOID ThreadCreateMon (IN HANDLE PId, IN HANDLE TId, IN BOOLEAN bCreate)

{
	PEPROCESS  EProcess,ParentEProcess;
	LPTSTR     lpCurProc,lpParnentProc;
	NTSTATUS   status;

#ifdef _AMD64_
	ULONG System = 4;
	ULONG dwParentPID = HandleToUlong(PsGetCurrentProcessId());//创建该线程的进程
	ULONG ProcessId = HandleToUlong(PId);
	status = PsLookupProcessByProcessId( ProcessId, &EProcess);
	status = PsLookupProcessByProcessId( dwParentPID, &ParentEProcess);
#else
	HANDLE System = (HANDLE)4;
	HANDLE dwParentPID = PsGetCurrentProcessId();//创建该线程的进程
	HANDLE ProcessId = PId;//ProcessId 是进程号，这里的进程号是指向包括该线程的进程，而不是创建该线程的进程
	status = PsLookupProcessByProcessId( (ULONG)ProcessId, &EProcess);
	status = PsLookupProcessByProcessId( (ULONG)dwParentPID, &ParentEProcess);
#endif

	if (!NT_SUCCESS( status ))
	{
		DbgPrint("PsLookupProcessByProcessId()\n");
		return;
	}  

	if ( bCreate )
	{
		if((g_bMainThread==TRUE)&&(ProcessId!=System)&&(ProcessId!=dwParentPID))
		{
			HANDLE dwParentTID = PsGetCurrentThreadId();
			lpCurProc  = (LPTSTR)EProcess;
			lpParnentProc = (LPTSTR)ParentEProcess;
			lpCurProc  +=  ProcessNameOffset;
			lpParnentProc += ProcessNameOffset;
			DbgPrint("caller: Name=%s PID=%d TID=%d\t\tcalled: Name=%s PID=%d TID=%d\n", \
				lpParnentProc, dwParentPID, dwParentTID, lpCurProc, ProcessId, TId);
			g_bMainThread = FALSE;
		}

		lpCurProc  = (LPTSTR)EProcess;
		lpCurProc  = lpCurProc + ProcessNameOffset;
		DbgPrint( "CREATE THREAD = PROCESS NAME: %s PROCESS ID: %d, THREAD ID: %d\n", lpCurProc, PId, TId );            
	}
	else
	{
		DbgPrint( "TERMINATED == THREAD ID: %d\n", TId);
	}
}

VOID ImageCreateMon (IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo )

{
	DbgPrint("FullImageName: %S,Process ID: %d\n",FullImageName->Buffer,ProcessId);
	DbgPrint("ImageBase: %x,ImageSize: %d\n",ImageInfo->ImageBase,ImageInfo->ImageSize);
}

ULONG GetProcessNameOffset()
{
	PEPROCESS	curproc;
	int			i;

	curproc = PsGetCurrentProcess();

	//
	// Scan for 12KB, hopping the KPEB never grows that big!
	//
	for( i = 0; i < 3*PAGE_SIZE; i++ ) 
	{

		if( !strncmp( SYSNAME, (PCHAR) curproc + i, strlen(SYSNAME) )) 
		{
			return i;
		}
	}

	//a
	// Name not found - oh, well
	//
	return 0;
}

