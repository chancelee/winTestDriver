#ifdef __cplusplus
extern "C"
{
#endif
	/*����ͷ�ļ�*/
	///////////////////
#include <Ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntddk.h>
#include <Ntstrsafe.h>
	
//////////////////
#ifdef __cplusplus
}
#endif

#define IOCTL_BASE	0x800
#define MY_CTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HELLO	MY_CTL_CODE(0)


#define DEVICE_NAME L"\\Device\\MyShaDow"
#define LINE_NAME L"\\??\\MyShaDow"                //"\\dosdevices\\HelloDDK"

#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)

#define PAGEDCODE  code_seg("PAGE")   //����ŵ���ҳ�ڴ�
#define LOCKEDCODE code_seg()
#define INITCODE   code_seg("INIT")

#define PAGEDDATA  data_seg("PAGE")   //���ݷŵ���ҳ�ڴ�
#define LOCKEDDATA data_seg()
#define INITDATA   data_seg("INIT")

//������Ĵ�С
#define arraysize(p) (sizeof(p)/sizeof((p)[0]))



//������չ�ṹ��
typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pDevice;         //�豸���
	UNICODE_STRING ustrDeviceName;	//�豸����
	UNICODE_STRING ustrSymLinkName;	//����������
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;


///////////////////////////////////////////////////////////////////////////////////////////
//SSDT��ṹ
typedef struct ServiceDescriptorEntry
{
	PVOID *ServiceTableBase;
	ULONG *ServiceCounterTableBase; //Used only in checked build
	ULONG NumberOfServices;
	PVOID *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;

//ShadowSSDT��ĵ�ַ
PServiceDescriptorTableEntry KeServiceDescriptorTableShadow = NULL;



#define ObjectNameInformation  1          

#define SystemHandleInformation 0x10

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} _SYSTEM_HANDLE_INFORMATION, *P_SYSTEM_HANDLE_INFORMATION;


typedef struct _SYSTEM_HANDLE_INformATION_EX {
	ULONG NumberOfHandles;
	_SYSTEM_HANDLE_INFORMATION Information[1];
} _SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
//////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////

/*
ULONG KdPrintEx(
_In_  ULONG ComponentId,
_In_  ULONG Level,
_In_  PCSTR Format,
... arguments
);

ComponentId��ָ�����ô����̵����
	DPFLTR_IHVVIDEO_ID��    ��Ƶ��������
	DPFLTR_IHVAUDIO_ID��    ��Ƶ��������
	DPFLTR_IHVNETWORK_ID��  ������������
	DPFLTR_IHVSTREAMING_ID���ں�����������
	DPFLTR_IHVBUS_ID��      ������������
	DPFLTR_IHVDRIVER_ID��   �κ��������͵���������


Level����Ϣ��Ҫ��λ���� ComponentId ָ���������ɸѡ��������Ƚ�
*/

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath);

//ж������
void DriverUnload(IN PDRIVER_OBJECT pDriverObject);
//Ĭ��ж������
NTSTATUS DDKDispatchRoutine(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
//�����豸
NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject);