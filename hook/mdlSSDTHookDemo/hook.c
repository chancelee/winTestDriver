#include <ntddk.h>
#include <ntimage.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()



__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SDT     SYSTEMSERVICE
#define KSDT KeServiceDescriptorTable



typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT DeviceObject;
	PKEVENT Event;

	BOOLEAN bPCreate;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


//    全局设备对象
PDEVICE_OBJECT g_pDeviceObject;

UNICODE_STRING g_RegPath;

typedef NTSTATUS(*ZWCREATESECTION)(

	OUT PHANDLE            		SectionHandle,
	IN ULONG                		DesiredAccess,
	IN POBJECT_ATTRIBUTES  	ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER     	 MaximumSize OPTIONAL,
	IN ULONG                		PageAttributess,
	IN ULONG                		SectionAttributes,
	IN HANDLE              		FileHandle OPTIONAL);
//定义函数指针保存原函数地址，用于恢复

static ZWCREATESECTION            OldZwCreateSection;



NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED *Dst,
	IN CONST VOID UNALIGNED *Src,
	IN ULONG Length)
{
	//MDL是一个对物理内存的描述，负责把虚拟内存映射到物理内存
	PMDL pmdl = IoAllocateMdl(Dst, Length, 0, 0, NULL);//分配mdl
	if (pmdl == NULL)
		return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(pmdl);//build mdl
	unsigned int *Mapped = (unsigned int *)MmMapLockedPages(pmdl, KernelMode);//锁住内存
	if (!Mapped) {
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



NTSTATUS NTAPI HOOK_NtCreateSection(PHANDLE SectionHandle,

	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER SectionSize,
	ULONG Protect,
	ULONG Attributes,
	HANDLE FileHandle)
{

	return OldZwCreateSection(SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		SectionSize,
		Protect,
		Attributes,
		FileHandle);

}


void StartHook(void)

{

	//获取未导出的服务函数索引号

	OldZwCreateSection = SDT(ZwCreateSection);
	ULONG hookAddr = (ULONG)HOOK_NtCreateSection;
	RtlSuperCopyMemory(&SDT(ZwCreateSection), &hookAddr, 4);



	return;

}




void RemoveHook(void)
{
	ULONG oldAddr = (ULONG)OldZwCreateSection;
	RtlSuperCopyMemory(&SDT(ZwCreateSection), &oldAddr, 4);
	return;
}




void UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  uszDeviceString;
	NTSTATUS        ntStatus;


	//移除挂接
	RemoveHook();

	IoDeleteDevice(DriverObject->DeviceObject);

	RtlInitUnicodeString(&uszDeviceString, L"\\DosDevices\\ITSys");
	IoDeleteSymbolicLink(&uszDeviceString);

}

NTSTATUS DispatchIoCtrl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

	NTSTATUS              ntStatus = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION    irpStack = IoGetCurrentIrpStackLocation(Irp);
	PDEVICE_EXTENSION    extension = DeviceObject->DeviceExtension;

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	default:
		break;
	}

	Irp->IoStatus.Status = ntStatus;

	// 设置返回给用户层程序的数据的字节数
	if (ntStatus == STATUS_SUCCESS)
		Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	else
		Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}



NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS rc;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	rc = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return rc;
}




NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
)
{
	NTSTATUS        ntStatus;
	UNICODE_STRING  uszDriverString;
	UNICODE_STRING  uszDeviceString;
	UNICODE_STRING  uszEventString;

	PDEVICE_OBJECT    pDeviceObject;
	PDEVICE_EXTENSION extension;
	// 初始化设备对象名
	RtlInitUnicodeString(&uszDriverString, L"\\Device\\ITSys");
	// 创建并初始化对象
	ntStatus = IoCreateDevice(
		DriverObject,
		sizeof(DEVICE_EXTENSION),
		&uszDriverString,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDeviceObject
	);
	if (ntStatus != STATUS_SUCCESS)
		return ntStatus;
	extension = pDeviceObject->DeviceExtension;
	RtlInitUnicodeString(&uszDeviceString, L"\\DosDevices\\ITSys");
	// 创建用户可见连接名称
	ntStatus = IoCreateSymbolicLink(&uszDeviceString, &uszDriverString);
	if (ntStatus != STATUS_SUCCESS)
	{
		// 创建失败，删除对象并返回错误值
		IoDeleteDevice(pDeviceObject);
		return ntStatus;
	}
	// 赋值全局设备对象指针

	// Assign global pointer to the device object for use by the callback functions
	g_pDeviceObject = pDeviceObject;
	// 设置所有可用的DeviceIoControl的处理IRP的函数

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoCtrl;

#if DBG
	KdPrint(("RegistryPath : %ws\n", RegistryPath->Buffer));
#endif

	//SDT挂接
	StartHook();

	return ntStatus;
}