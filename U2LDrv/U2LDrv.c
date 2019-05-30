
/*
\\servername\sharename\directory\filename�������
\\\\192.168.0.1\\mydocs\\x.txt->D:\\tete\\x.txt,���������ע���

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServe\Shares����ӳ���ϵ��mydocsӳ���ű���·����һ���ڰ�ȫ����¹����ڱ���·��������Ҫ��UNC·��ת���ɱ���·����
---------------------
���ߣ�kernweak
��Դ��CSDN
ԭ�ģ�https://blog.csdn.net/youyou519/article/details/90523662
��Ȩ����������Ϊ����ԭ�����£�ת���븽�ϲ������ӣ�
*/

#include<ntddk.h>
#include<ntstrsafe.h>


#ifndef MAX_PATH
#define MAX_PATH 260
#endif // !MAX_PATH

#define REG_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares"
#define DEVICE_NAME L"\\device\\U2LDrv" 
#define LINK_NAME L"\\dosdevices\\U2LDrv"

//ʵ��strchr

WCHAR*  RTLUnicodeStringChr(PUNICODE_STRING IN pStr, WCHAR chr)
{
	ULONG i = 0;
	ULONG size = pStr->Length>>1;
	for (i = 0; i < size ; i++) {
		if (pStr->Buffer[i] == chr) {
			return pStr->Buffer + i;
		}
		
	}
	return NULL;
}



//ʵ��strstr

WCHAR*  RTLUnicodeStringStr(const PUNICODE_STRING IN pStr, const PUNICODE_STRING IN pSubStr)
{
	USHORT uLengthStep = 0;
	USHORT uStrlen = pStr->Length;
	USHORT uSubStrlen = pSubStr->Length;
	USHORT i = 0;
	UNICODE_STRING str1 = { 0 };
	str1.MaximumLength = uStrlen;
	UNICODE_STRING str2 = { 0 };
	str2.MaximumLength = uSubStrlen;
	str2.Buffer = pSubStr->Buffer;
	//str2.Length = pSubStr->Length;
	if (pStr == NULL || pSubStr == NULL|| uStrlen < uSubStrlen) {
		return NULL;
	}
	uLengthStep = ((uStrlen - uSubStrlen) >> 1 )+ 1;
	for (i = 0; i < uLengthStep; i++) {
		str1.Length = str1.MaximumLength = (USHORT)uSubStrlen;
		str2.Length = str2.MaximumLength = (USHORT)uSubStrlen;
		str1.Buffer = pStr->Buffer + i;
		str2.Buffer = pSubStr->Buffer;
		if (0 == RtlCompareUnicodeString(&str1, &str2, TRUE)) {
			return pStr->Buffer + i;
		}
	}
	return NULL;
	
}

UNICODE_STRING* getShareName(PUNICODE_STRING IN pStrUnc, PUNICODE_STRING OUT pStrShare) {
	WCHAR * pTmp = pStrUnc->Buffer;
	
	
	WCHAR *pSharStart = NULL;
	WCHAR *pSharEnd = NULL;
	ULONG uShareLen = 0;//share����

	ULONG i = 0;
	ULONG uSize = (pStrUnc->Length) >> 1;
	//��ȡSharedDocs�۲��shareDocs��ͷ�ǵ�����'\\',�����ǵ��ĸ���\\��,�����漰��������
	ULONG uTmp = 1;//ȡ������'\\'��־λ


	if (pTmp == NULL) {
		return NULL;
	}
	//ȡShareDocs
	for (i = 0; i < uSize; i++)
	{
		if (pStrUnc->Buffer[i] == L'\\') {
			if (uTmp == 3)
			{
				pSharStart = pStrUnc->Buffer + i + 1;
			}
			else if (uTmp == 4) {
				pSharEnd = pStrUnc->Buffer + i - 1;
			}
			uTmp++;
		}
	}
	if (NULL == pSharStart || NULL == pSharEnd) {
		return NULL;
	}

	uShareLen = pSharEnd - pSharStart + 1;

	pStrShare->Buffer = pSharStart;
	pStrShare->Length = uShareLen * sizeof(WCHAR);
	return pStrShare;

}
//�߼���ȡshare���в�࣬���Ա���ע����Щ��û��
UNICODE_STRING* getFileName(PUNICODE_STRING IN pStrUnc, PUNICODE_STRING OUT pStrShare) {
	WCHAR * pTmp = pStrUnc->Buffer;


	WCHAR *pSharStart = NULL;
	WCHAR *pSharEnd = NULL;
	ULONG uShareLen = 0;//share����

	ULONG i = 0;
	ULONG uSize = (pStrUnc->Length) >> 1;
	//��ȡSharedDocs�۲�ÿ�ʼ�ǵ��ĸ���\\��,�����漰��������
	ULONG uTmp = 1;//ȡ���ĸ�'\\'��־λ


	if (pTmp == NULL) {
		return NULL;
	}
	//ȡShareDocs
	for (i = 0; i < uSize; i++)
	{
		if (pStrUnc->Buffer[i] == L'\\') {
			if (uTmp == 4)
			{
				pSharStart = pStrUnc->Buffer + i ;

				break;
			}
			uTmp++;
		}
	}
	if (NULL == pSharStart) {
		return NULL;
	}

	uShareLen = pStrUnc->Length - (i)* sizeof(WCHAR);

	pStrShare->Buffer = pSharStart;
	pStrShare->Length = uShareLen;
	return pStrShare;

}


//\\servername\SharedDocs\xxxx -> C:\\Documents and Settings\\All Users\\Documents\\xxx
NTSTATUS UNC2Local(PUNICODE_STRING IN pStrUnc, PUNICODE_STRING OUT pStrLocal)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//�ҵ�˼·���Ƚ�L"Doc\\1.txt"�Ľ�ȡ��Doc��Ȼ��ȥ��ע����ҵ�Path���ٰѺ���ƴ������
	UNICODE_STRING StrShare = { 0 };
	StrShare.MaximumLength = MAX_PATH;
	StrShare.Length = 0;
	UNICODE_STRING uStrReg = { 0 };
	ULONG ulResult = 0;//�ų���
	PKEY_VALUE_PARTIAL_INFORMATION	pvpi = NULL;

	UNICODE_STRING StrFile = { 0 };
	StrFile.MaximumLength = MAX_PATH;
	StrFile.Length = 0;

	getShareName(pStrUnc, &StrShare);
	getFileName(pStrUnc, &StrFile);

	OBJECT_ATTRIBUTES objectAttr = { 0 };
	HANDLE hRegister = NULL;
	
	DbgPrint("ShareName is %wZ\n", &StrShare);
	DbgPrint("file is %wZ\n", &StrFile);
	//��ѯע���shared��Ϣ
	RtlInitUnicodeString(&uStrReg, REG_PATH);
	InitializeObjectAttributes(&objectAttr,
		&uStrReg,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttr);
	if (!NT_SUCCESS(status))

	{

		DbgPrint("[RegQueryValueKey]ZwOpenKey failed!\n");

		return status;

	}
	status = ZwQueryValueKey(hRegister,
		&StrShare,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulResult);

	if (status != STATUS_BUFFER_OVERFLOW &&
		status != STATUS_BUFFER_TOO_SMALL)
	{
		ZwClose(hRegister);
		return status;
	}

	pvpi =
		(PKEY_VALUE_PARTIAL_INFORMATION)
		ExAllocatePoolWithTag(PagedPool, ulResult, 'SGER');
	if (pvpi == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryValueKey(hRegister,
		&StrShare,
		KeyValuePartialInformation,
		pvpi,
		ulResult,
		&ulResult);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pvpi);
		ZwClose(hRegister);
		return status;
	}

	if (pvpi->Type != REG_MULTI_SZ) {
		if (pvpi)
		{
			ExFreePool(pvpi);
		}
		if (hRegister)
		{
			ZwClose(hRegister);
		}

		return status;
	}
	//Ȼ�����path=
	UNICODE_STRING uszLoc = { 0 };
	uszLoc.Length = (USHORT)pvpi->DataLength;
	uszLoc.MaximumLength = (USHORT)pvpi->DataLength;
	uszLoc.Buffer = (WCHAR*)(pvpi->Data);
	DbgPrint("uszLoc is %wZ\n", &uszLoc);//�м����������鴦��
	UNICODE_STRING uszLoc2 = { 0 }; //�м����
	WCHAR * pTmp = 0;
	RtlInitUnicodeString(&uszLoc2, L"Path=");
	pTmp=RTLUnicodeStringStr(&uszLoc, &uszLoc2);
	//DbgPrint("pTmp is %wZ\n", *pTmp);
	if (NULL == pTmp)
	{
		status = STATUS_UNSUCCESSFUL;
		if (pvpi)
		{
			ExFreePool(pvpi);
		}
		if (hRegister)
		{
			ZwClose(hRegister);
		}
	
		return status;
	}
	else {

		WCHAR* i = 0;
		RtlInitUnicodeString(&uszLoc2, pTmp + wcslen(L"Path="));
		
		RtlAppendUnicodeStringToString(pStrLocal,&uszLoc2);
		DbgPrint("pStrLocal is %wZ\n", *pStrLocal);

		RtlAppendUnicodeStringToString(pStrLocal, &StrFile);
		DbgPrint("pStrLocal is %wZ\n", *pStrLocal);
		status = STATUS_SUCCESS;
		if (pvpi)
		{
			ExFreePool(pvpi);
		}
		if (hRegister)
		{
			ZwClose(hRegister);
		}
	
	}
	
	
	return status;
	

}

NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING uLinkName = { 0 };
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&uLinkName);

	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, UNICODE_STRING pReg)
{
	UNREFERENCED_PARAMETER(pReg);
	UNICODE_STRING uDeviceName = { 0 };
	UNICODE_STRING uLinkName = { 0 };
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i = 0;
	DbgPrint("Driver load begin\n");

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING strUnc = { 0 };
	UNICODE_STRING strLocal = { 0 };
	strLocal.MaximumLength = MAX_PATH;
	strLocal.Length = 0;
	strLocal.Buffer = ExAllocatePoolWithTag(PagedPool, MAX_PATH * sizeof(WCHAR), 'TSET');
	RtlZeroMemory(strLocal.Buffer, MAX_PATH * sizeof(WCHAR));
	RtlInitUnicodeString(&strUnc, L"\\\\127.0.0.1\\Doc\\1.txt");//����д�����Ѿ��ڸ�Ŀ¼�·������ļ�

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	//�豸�������������Ĺ�ϵ
	//���߻�ָ
	status = IoCreateDevice(pDriverObject,
		0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice failed:%x", status);
		return status;
	}
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	//�������ӵ�����
	status = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed:%x\n", status);
		return status;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}
	pDriverObject->DriverUnload = DriverUnload;
	DbgPrint("Driver load ok!\n");
	status = UNC2Local(&strUnc, &strLocal);
	if (!NT_SUCCESS(status)) {
		DbgPrint("û�ҵ�\n");
	}
	else
	{
		DbgPrint("%wZ\n", &strLocal);
	}
	ExFreePool(strLocal.Buffer);
	
	return status;

}