#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "include/protocol_examples_common.h"
#include "esp_sntp.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "esp_tls.h"
#include "sdkconfig.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE && CONFIG_EXAMPLE_USING_ESP_TLS_MBEDTLS
#include "esp_crt_bundle.h"
#endif
#include "time_sync.h"
#include "cJSON.h"
#include <arpa/inet.h>  // 添加头文件以使用 inet_ntop 函数
#include <ctype.h>      // 添加头文件以使用 tolower 函数
#include <stdio.h>      // 添加头文件以使用文件操作函数
#include <arpa/inet.h>  // 添加头文件以使用 inet_aton 函数
#include <sys/socket.h> // 添加头文件以使用 socket 函数

// 添加 WiFi SSID 和密码的全局变量

// Move the function prototype after all #include statements
static void save_config_to_nvs(cJSON *json);

// 定义 INVALID_SOCK 和 YIELD_TO_ALL_MS
#define INVALID_SOCK (-1)
#define YIELD_TO_ALL_MS 50
/* Constants that aren't configurable in menuconfig */
#define WEB_PORT "443"
#define WEB_SERVER "api.cloudflare.com"
#define WEB_URL "https://api.cloudflare.com/client/v4/zones"
#define DOMAIN_NAME "123456.xyz"
#define AAAA_NAME "test"

#define CLOUDFLARE_TOKEN ""
// cloud flare的token 创建令牌->编辑区域 DNS (使用模板)》https://dash.cloudflare.com/profile/api-tokens
#define SERVER_URL_MAX_SZ 256

#define SERVER_ADDRESS "::" // 修改为支持 IPv6 的地址
#define SERVER_PORT "8080"
#define TOKEN "123456"

// 添加 WiFi SSID 和密码的默认定义
#define WIFI_SSID "ATRI"
#define WIFI_PASSWD "08280828"
#define WOL_MAC "11:22:33:44:55:66" // 默认 MAC 地址
#define WOL_ADDR "192.168."         // 默认地址
#define WOL_PORT "9"                // 默认端口号

#define NVS_NAMESPACE "config"
#define COOKIE_LENGTH 128
// 默认配置
static char domain_name[64] = DOMAIN_NAME;
static char aaaa_name[64] = AAAA_NAME;
static char cloudflare_token[128] = CLOUDFLARE_TOKEN;
static char token[64] = TOKEN;
static char server_port[8] = SERVER_PORT;
static char wifi_ssid[64] = WIFI_SSID;
static char wifi_passwd[64] = WIFI_PASSWD;
static char wol_mac[18] = WOL_MAC;
static char wol_addr[16] = WOL_ADDR;
static char wol_port[8] = WOL_PORT;
char cookie[COOKIE_LENGTH];

static const char *TAG = "HBWuChang_IPv6_WOL";

/* Timer interval once every day (24 Hours) */
#define TIME_PERIOD (86400000000ULL)
#include <stdlib.h>
#include <time.h>
static esp_timer_handle_t http_request_watchdog_timer;

// 定时器回调函数
static void http_request_watchdog_callback(void *arg)
{
    ESP_LOGW(TAG, "No HTTP request received in the last hour. Rebooting...");
    esp_restart();
}
static char *generate_cookie_header(char *cookie, size_t length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_size = sizeof(charset) - 1;

    // 生成随机 Cookie
    for (size_t i = 0; i < length - 1; i++)
    {
        cookie[i] = charset[rand() % charset_size];
    }
    cookie[length - 1] = '\0'; // 确保字符串以 null 结尾

    // 保存生成的 Cookie 到 NVS
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err == ESP_OK)
    {
        char existing_cookies[COOKIE_LENGTH * 4] = {0}; // 用于存储最多 4 个拼接的 Cookie
        size_t size = sizeof(existing_cookies);

        // 从 NVS 中读取现有的 Cookie
        if (nvs_get_str(nvs_handle, "cookie", existing_cookies, &size) == ESP_OK)
        {
            ESP_LOGI(TAG, "Existing cookies: %s", existing_cookies);
        }

        // 拼接新旧 Cookie
        char new_cookies[COOKIE_LENGTH * 4] = {0};
        snprintf(new_cookies, sizeof(new_cookies), "%s%s", cookie, existing_cookies);

        // 截取最多 4 个 Cookie 的长度
        size_t new_length = strlen(new_cookies);
        if (new_length > COOKIE_LENGTH * 4 - 1)
        {
            memmove(new_cookies, new_cookies + (new_length - COOKIE_LENGTH * 4), COOKIE_LENGTH * 4);
            new_cookies[COOKIE_LENGTH * 4 - 1] = '\0';
        }

        // 保存拼接后的 Cookie 到 NVS
        nvs_set_str(nvs_handle, "cookie", new_cookies);
        err = nvs_commit(nvs_handle);
        if (err == ESP_OK)
        {
            ESP_LOGI(TAG, "Generated and saved cookies to NVS: %s", new_cookies);
        }
        else
        {
            ESP_LOGE(TAG, "Failed to commit cookies to NVS: %s", esp_err_to_name(err));
        }
        nvs_close(nvs_handle);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to open NVS for saving cookies: %s", esp_err_to_name(err));
    }

    // 构造 HTTP 响应头
    static char header[256];
    snprintf(header, sizeof(header), "set-cookie: HBWuChang_IPv6_WOL=%s; path=/; HttpOnly;", cookie);
    return header;
}

static bool check_cookie(char *rx_buffer)
{
    char *cookie_header = strstr(rx_buffer, "Cookie: ");
    if (cookie_header)
    {
        char *cookie_value = cookie_header + strlen("Cookie: ");
        char *end_of_cookie = strstr(cookie_value, "\r\n");
        // HBWuChang_IPv6_WOL=
        char *cookie_start = strstr(cookie_value, "HBWuChang_IPv6_WOL=");
        if (cookie_start)
        {
            cookie_value = cookie_start + strlen("HBWuChang_IPv6_WOL=");
        }
        else
        {
            ESP_LOGI(TAG, "Cookie not found in request");
            return false;
        }
        if (end_of_cookie)
        {
            *end_of_cookie = '\0'; // 将结束符替换为 null 字符
            ESP_LOGI(TAG, "Received cookie: %s", cookie_value);
            
            // 从 NVS 中读取所有存储的 Cookie
            nvs_handle_t nvs_handle;
            esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
            if (err == ESP_OK)
            {
                char stored_cookies[COOKIE_LENGTH * 4] = {0};
                size_t size = sizeof(stored_cookies);

                if (nvs_get_str(nvs_handle, "cookie", stored_cookies, &size) == ESP_OK)
                {
                    ESP_LOGI(TAG, "Stored cookies: %s", stored_cookies);

                    // 检查 cookie_value 是否在 stored_cookies 中
                    if (strstr(stored_cookies, cookie_value) != NULL)
                    {
                        nvs_close(nvs_handle);
                        ESP_LOGI(TAG, "Cookie verified successfully");
                        return true;
                    }
                }
                nvs_close(nvs_handle);
            }
            else
            {
                ESP_LOGE(TAG, "Failed to open NVS for reading cookies: %s", esp_err_to_name(err));
            }
        }
    }
    ESP_LOGI(TAG, "Cookie verification failed");
    return false;
}
void init_random_generator()
{
    srand((unsigned int)time(NULL)); // 初始化随机数生成器
}
static char *https_get_request(esp_tls_cfg_t cfg, const char *WEB_SERVER_URL, const char *REQUEST)
{
    char buf[512];
    int ret, len;
    char *response = NULL;
    size_t response_size = 0;

    esp_tls_t *tls = esp_tls_init();
    if (!tls)
    {
        ESP_LOGE(TAG, "Failed to allocate esp_tls handle!");
        goto exit;
    }

    if (esp_tls_conn_http_new_sync(WEB_SERVER_URL, &cfg, tls) == 1)
    {
        ESP_LOGI(TAG, "Connection established...");
    }
    else
    {
        ESP_LOGE(TAG, "Connection failed...");
        int esp_tls_code = 0, esp_tls_flags = 0;
        esp_tls_error_handle_t tls_e = NULL;
        esp_tls_get_error_handle(tls, &tls_e);
        ret = esp_tls_get_and_clear_last_error(tls_e, &esp_tls_code, &esp_tls_flags);
        if (ret == ESP_OK)
        {
            ESP_LOGE(TAG, "TLS error = -0x%x, TLS flags = -0x%x", esp_tls_code, esp_tls_flags);
        }
        goto cleanup;
    }

    size_t written_bytes = 0;
    do
    {
        ret = esp_tls_conn_write(tls,
                                 REQUEST + written_bytes,
                                 strlen(REQUEST) - written_bytes);
        if (ret >= 0)
        {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        }
        else if (ret != ESP_TLS_ERR_SSL_WANT_READ && ret != ESP_TLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "esp_tls_conn_write  returned: [0x%02X](%s)", ret, esp_err_to_name(ret));
            goto cleanup;
        }
    } while (written_bytes < strlen(REQUEST));

    ESP_LOGI(TAG, "Reading HTTP response...");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0x00, sizeof(buf));
        ret = esp_tls_conn_read(tls, (char *)buf, len);
        ESP_LOGI(TAG, "esp_tls_conn_read returned: [0x%02X](%s)", ret, esp_err_to_name(ret));
        if (ret < 0)
        {
            ESP_LOGE(TAG, "esp_tls_conn_read  returned [-0x%02X](%s)", -ret, esp_err_to_name(ret));
            break;
        }
        else if (ret == 0)
        {
            ESP_LOGI(TAG, "connection closed");
            break;
        }

        len = ret;
        ESP_LOGD(TAG, "%d bytes read", len);
        char *new_response = realloc(response, response_size + len + 1);
        if (!new_response)
        {
            ESP_LOGE(TAG, "Failed to allocate memory for response");
            free(response);
            response = NULL;
            goto cleanup;
        }
        response = new_response;
        memcpy(response + response_size, buf, len);
        response_size += len;
        response[response_size] = '\0';

        // Stop reading if the specific condition is met
        if (ret == 0x05)
        {
            ESP_LOGI(TAG, "End of response detected based on condition");
            break;
        }
    } while (1);

    ESP_LOGI(TAG, "HTTPS response reading completed");

cleanup:
    esp_tls_conn_destroy(tls);
exit:
    return response;
}

// 获取当前全局 IPv6 地址的函数
static bool get_global_ipv6_address(char *ipv6_address, size_t max_len)
{
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif)
    {
        ESP_LOGE(TAG, "Failed to get network interface");
        return false;
    }

    esp_ip6_addr_t ip6_addr;
    if (esp_netif_get_ip6_global(netif, &ip6_addr) == ESP_OK)
    {
        // 使用 inet_ntop 将 IPv6 地址转换为字符串
        if (inet_ntop(AF_INET6, &ip6_addr.addr, ipv6_address, max_len) == NULL)
        {
            ESP_LOGE(TAG, "Failed to convert IPv6 address to string");
            return false;
        }

        // 将 IPv6 地址中的字母转为小写
        for (size_t i = 0; i < strlen(ipv6_address); i++)
        {
            ipv6_address[i] = tolower((unsigned char)ipv6_address[i]);
        }

        ESP_LOGI(TAG, "Global IPv6 address: %s", ipv6_address);
        return true;
    }
    else
    {
        ESP_LOGE(TAG, "Failed to get global IPv6 address");
        return false;
    }
}

static cJSON *https_get_request_without_cert(const char *url, const char *request_headers)
{
    ESP_LOGI(TAG, "https_request without cert");
    esp_tls_cfg_t cfg = {
        .skip_common_name = true, // 跳过服务器证书的通用名称验证
    };

    char *response = NULL;
    char *second_response = NULL; // 定义 second_response
    char *post_response = NULL;   // 定义 post_response
    cJSON *json = NULL;           // 定义 json

    response = https_get_request(cfg, url, request_headers);
    if (response)
    {

        // Find the start of the JSON data
        const char *json_start = strstr(response, "{");
        if (!json_start)
        {
            ESP_LOGE(TAG, "Failed to find JSON data in response");
            free(response);
            return NULL;
        }

        // Parse the JSON data
        json = cJSON_Parse(json_start);
        if (!json)
        {
            ESP_LOGE(TAG, "Failed to parse JSON");
            free(response);
            return NULL;
        }

        // Extract the ID from the JSON
        cJSON *result_array = cJSON_GetObjectItem(json, "result");
        if (cJSON_IsArray(result_array))
        {
            cJSON *first_result = cJSON_GetArrayItem(result_array, 0);
            if (first_result)
            {
                cJSON *id = cJSON_GetObjectItem(first_result, "id");
                if (cJSON_IsString(id))
                {
                    ESP_LOGI(TAG, "Extracted ID: %s", id->valuestring);
                    char second_url[SERVER_URL_MAX_SZ];
                    snprintf(second_url, sizeof(second_url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s.%s&type=AAAA", id->valuestring, aaaa_name, domain_name);

                    char second_request_headers[512];
                    snprintf(second_request_headers, sizeof(second_request_headers),
                             "GET /client/v4/zones/%s/dns_records?name=%s.%s&type=AAAA HTTP/1.1\r\n"
                             "Host: api.cloudflare.com\r\n"
                             "Authorization: Bearer %s\r\n"
                             "\r\n",
                             id->valuestring, aaaa_name, domain_name, cloudflare_token);

                    // Perform the second request
                    second_response = https_get_request(cfg, second_url, second_request_headers);
                    if (second_response)
                    {

                        // Parse the JSON data from the second response
                        const char *json_start = strstr(second_response, "{");
                        if (json_start)
                        {
                            cJSON *second_json = cJSON_Parse(json_start);
                            if (second_json)
                            {
                                // Print the formatted JSON
                                char *formatted_json = cJSON_Print(second_json);
                                if (formatted_json)
                                {
                                    ESP_LOGI(TAG, "Formatted JSON:\n%s", formatted_json);
                                    free(formatted_json);
                                }
                                result_array = cJSON_GetObjectItem(second_json, "result");
                                // 获取当前全局 IPv6 地址
                                char ipv6_address[64];
                                if (!get_global_ipv6_address(ipv6_address, sizeof(ipv6_address)))
                                {
                                    ESP_LOGE(TAG, "Unable to proceed without a global IPv6 address");
                                    goto cleanup; // 如果无法获取 IPv6 地址，退出
                                }
                                ESP_LOGI(TAG, "Global IPv6 address: %s", ipv6_address);
                                if (cJSON_IsArray(result_array) && cJSON_GetArraySize(result_array) > 0)
                                {
                                    cJSON *first_result = cJSON_GetArrayItem(result_array, 0);
                                    if (first_result)
                                    {
                                        cJSON *content = cJSON_GetObjectItem(first_result, "content");
                                        if (content && cJSON_IsString(content))
                                        {
                                            // 确保 content 存在且是字符串
                                            ESP_LOGI(TAG, "First result content: %s", content->valuestring);

                                            // 检查 content 是否与当前 IPv6 地址相同
                                            if (strcmp(content->valuestring, ipv6_address) != 0)
                                            {
                                                ESP_LOGI(TAG, "Content differs from current IPv6 address, constructing PUT request");

                                                // 构建第四次请求的 URL
                                                char put_url[SERVER_URL_MAX_SZ];
                                                snprintf(put_url, sizeof(put_url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", id->valuestring, cJSON_GetObjectItem(first_result, "id")->valuestring);

                                                // 构建第四次请求的头部和请求体
                                                char put_body[256];
                                                snprintf(put_body, sizeof(put_body),
                                                         "{\r\n"
                                                         "  \"type\": \"AAAA\",\r\n"
                                                         "  \"name\": \"%s.%s\",\r\n"
                                                         "  \"content\": \"%s\"\r\n"
                                                         "}",
                                                         aaaa_name, domain_name, ipv6_address);

                                                // 增加缓冲区大小
                                                char put_request_headers[1024]; // 将缓冲区大小从 512 增加到 1024

                                                snprintf(put_request_headers, sizeof(put_request_headers),
                                                         "PUT /client/v4/zones/%s/dns_records/%s HTTP/1.1\r\n"
                                                         "Host: api.cloudflare.com\r\n"
                                                         "Connection: keep-alive\r\n"
                                                         "Content-Length: %d\r\n"
                                                         "User-Agent: Reqable/2.33.4\r\n"
                                                         "Authorization: Bearer %s\r\n"
                                                         "\r\n"
                                                         "%s",
                                                         id->valuestring, cJSON_GetObjectItem(first_result, "id")->valuestring, strlen(put_body), cloudflare_token, put_body);

                                                // 发送 PUT 请求
                                                char *put_response = https_get_request(cfg, put_url, put_request_headers);
                                                if (put_response)
                                                {
                                                    ESP_LOGI(TAG, "PUT HTTP Response:\n%s", put_response);

                                                    // 解析 PUT 响应中的 JSON 数据
                                                    const char *json_start = strstr(put_response, "{");
                                                    if (json_start)
                                                    {
                                                        cJSON *put_json = cJSON_Parse(json_start);
                                                        if (put_json)
                                                        {
                                                            // 打印格式化的 JSON
                                                            char *formatted_json = cJSON_Print(put_json);
                                                            if (formatted_json)
                                                            {
                                                                ESP_LOGI(TAG, "Formatted PUT Response JSON:\n%s", formatted_json);
                                                                free(formatted_json);
                                                            }
                                                            cJSON_Delete(put_json);
                                                        }
                                                        else
                                                        {
                                                            ESP_LOGE(TAG, "Failed to parse PUT JSON response");
                                                        }
                                                    }
                                                    else
                                                    {
                                                        ESP_LOGE(TAG, "Failed to find JSON data in PUT response");
                                                    }

                                                    free(put_response);
                                                }
                                                else
                                                {
                                                    ESP_LOGE(TAG, "Failed to get PUT HTTP response");
                                                }
                                            }
                                            else
                                            {
                                                ESP_LOGI(TAG, "Content matches current IPv6 address, no update needed");
                                            }
                                        }
                                        else
                                        {
                                            ESP_LOGI(TAG, "First result has no 'content' field or it is not a string");
                                            goto third_request;
                                        }
                                    }
                                    else
                                    {
                                        ESP_LOGI(TAG, "Failed to get the first result");
                                        goto third_request;
                                    }
                                }
                                else
                                {
                                third_request:
                                    ESP_LOGI(TAG, "No records found in result");

                                    // 构建第三次请求的 URL
                                    char post_url[SERVER_URL_MAX_SZ];
                                    snprintf(post_url, sizeof(post_url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records", id->valuestring);

                                    // 构建第三次请求的头部和请求体
                                    char post_body[256];
                                    snprintf(post_body, sizeof(post_body),
                                             "{\r\n"
                                             "  \"type\": \"AAAA\",\r\n"
                                             "  \"name\": \"%s.%s\",\r\n"
                                             "  \"content\": \"%s\"\r\n"
                                             "}",
                                             aaaa_name, domain_name, ipv6_address);

                                    char post_request_headers[512];
                                    snprintf(post_request_headers, sizeof(post_request_headers),
                                             "POST /client/v4/zones/%s/dns_records HTTP/1.1\r\n"
                                             "Host: api.cloudflare.com\r\n"
                                             "Content-Length: %d\r\n"
                                             "Authorization: Bearer %s\r\n"
                                             "\r\n"
                                             "%s",
                                             id->valuestring, strlen(post_body), cloudflare_token, post_body);

                                    // 发送 POST 请求
                                    post_response = https_get_request(cfg, post_url, post_request_headers);
                                    if (post_response)
                                    {
                                        ESP_LOGI(TAG, "POST HTTP Response:\n%s", post_response);

                                        // 解析 POST 响应中的 JSON 数据
                                        const char *json_start = strstr(post_response, "{");
                                        if (json_start)
                                        {
                                            cJSON *post_json = cJSON_Parse(json_start);
                                            if (post_json)
                                            {
                                                // 打印格式化的 JSON
                                                char *formatted_json = cJSON_Print(post_json);
                                                if (formatted_json)
                                                {
                                                    ESP_LOGI(TAG, "Formatted POST Response JSON:\n%s", formatted_json);
                                                    free(formatted_json);
                                                }
                                                cJSON_Delete(post_json);
                                            }
                                            else
                                            {
                                                ESP_LOGE(TAG, "Failed to parse POST JSON response");
                                            }
                                        }
                                        else
                                        {
                                            ESP_LOGE(TAG, "Failed to find JSON data in POST response");
                                        }

                                        free(post_response);
                                    }
                                    else
                                    {
                                        ESP_LOGE(TAG, "Failed to get POST HTTP response");
                                    }
                                }
                                cJSON_Delete(second_json);
                            }
                            else
                            {
                                ESP_LOGE(TAG, "Failed to parse second JSON response");
                            }
                        }
                        else
                        {
                            ESP_LOGE(TAG, "Failed to find JSON data in second response");
                        }

                        free(second_response);
                    }
                    else
                    {
                        ESP_LOGE(TAG, "Failed to get second HTTP response");
                    }
                }
                else
                {
                    ESP_LOGE(TAG, "ID is not a string");
                }
            }
            else
            {
                ESP_LOGE(TAG, "Failed to get first result");
            }
        }
        else
        {
            ESP_LOGE(TAG, "Result is not an array");
        }
        free(response);
        return json;
    }
    else
    {
        ESP_LOGE(TAG, "Failed to get HTTP response");
        return NULL;
    }

cleanup:
    if (response)
    {
        free(response);
    }
    if (second_response)
    {
        free(second_response);
    }
    if (post_response)
    {
        free(post_response);
    }
    if (json)
    {
        cJSON_Delete(json);
    }
    return NULL;
}

static void https_request_task(void *pvparameters)
{
    ESP_LOGI(TAG, "Start https_request example");

    // 替换硬编码的值为从 NVS 加载的配置数据
    const char *url = "https://api.cloudflare.com/client/v4/zones?name=";
    char full_url[SERVER_URL_MAX_SZ];
    snprintf(full_url, sizeof(full_url), "%s%s", url, domain_name);
    char CLOUDFLARE_GET_ID_REQUEST[512];
    snprintf(CLOUDFLARE_GET_ID_REQUEST, sizeof(CLOUDFLARE_GET_ID_REQUEST),
             "GET /client/v4/zones?name=%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Authorization: Bearer %s\r\n"
             "\r\n",
             domain_name, WEB_SERVER, cloudflare_token);

    cJSON *json = https_get_request_without_cert(full_url, CLOUDFLARE_GET_ID_REQUEST);

    if (json)
    {
        ESP_LOGI(TAG, "Parsed JSON successfully");
        cJSON_Delete(json);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to parse JSON");
        esp_restart();
    }
    ESP_LOGI(TAG, "Finish https_request example");
    vTaskDelete(NULL);
}

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[] asm("_binary_index_html_end");

static void send_wol_packet(const char *mac, const char *board_address, int port)
{
    uint8_t wol_packet[102];
    uint8_t mac_bytes[6];
    struct sockaddr_in dest_addr;

    // 将 MAC 地址转换为字节数组
    if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) != 6)
    {
        ESP_LOGE(TAG, "Invalid MAC address format");
        return;
    }

    // 构造 WOL 数据包
    memset(wol_packet, 0xFF, 6); // 前 6 字节为 0xFF
    for (int i = 0; i < 16; i++)
    {
        memcpy(&wol_packet[6 + i * 6], mac_bytes, 6); // 后续 16 组 MAC 地址
    }

    // 设置目标地址
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (!inet_aton(board_address, &dest_addr.sin_addr))
    {
        ESP_LOGE(TAG, "Invalid board address");
        return;
    }

    // 创建 UDP 套接字
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Failed to create socket: errno %d", errno);
        return;
    }

    // 发送 WOL 数据包
    int err = sendto(sock, wol_packet, sizeof(wol_packet), 0,
                     (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0)
    {
        ESP_LOGE(TAG, "Failed to send WOL packet: errno %d", errno);
    }
    else
    {
        ESP_LOGI(TAG, "WOL packet sent to %s:%d", board_address, port);
    }

    close(sock);
}

static void ipv4_ipv6_server_task(void *pvParameters)
{
    static const char *TAG = "ipv4-ipv6-server";
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC}; // 支持 IPv4 和 IPv6
    struct addrinfo *address_info;
    int listen_sock = INVALID_SOCK;

    int res = getaddrinfo(SERVER_ADDRESS, server_port, &hints, &address_info);
    if (res != 0 || address_info == NULL)
    {
        ESP_LOGE(TAG, "Couldn't get hostname for `%s` getaddrinfo() returns %d, addrinfo=%p", SERVER_ADDRESS, res, address_info);
        goto error;
    }

    listen_sock = socket(address_info->ai_family, address_info->ai_socktype, address_info->ai_protocol);
    if (listen_sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        goto error;
    }
    ESP_LOGI(TAG, "Socket created");

    int flags = fcntl(listen_sock, F_GETFL);
    if (fcntl(listen_sock, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        ESP_LOGE(TAG, "Unable to set socket non-blocking: errno %d", errno);
        goto error;
    }

    if (bind(listen_sock, address_info->ai_addr, address_info->ai_addrlen) != 0)
    {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        goto error;
    }
    ESP_LOGI(TAG, "Socket bound, port %s", server_port);

    if (listen(listen_sock, 1) != 0)
    {
        ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
        goto error;
    }
    ESP_LOGI(TAG, "Socket listening");

    while (1)
    {
        struct sockaddr_storage source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);

        if (sock < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
            }
            vTaskDelay(pdMS_TO_TICKS(YIELD_TO_ALL_MS));
            continue;
        }

        char addr_str[128];
        if (source_addr.ss_family == AF_INET)
        {
            inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str));
        }
        else if (source_addr.ss_family == AF_INET6)
        {
            inet6_ntoa_r(((struct sockaddr_in6 *)&source_addr)->sin6_addr, addr_str, sizeof(addr_str));
        }
        ESP_LOGI(TAG, "Connection accepted from %s", addr_str);

        char rx_buffer[1024];
        int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len < 0)
        {
            ESP_LOGE(TAG, "recv failed: errno %d", errno);
            close(sock);
            continue;
        }
        // 重置 HTTP 请求看门狗计时器
        ESP_ERROR_CHECK(esp_timer_stop(http_request_watchdog_timer));
        ESP_ERROR_CHECK(esp_timer_start_periodic(http_request_watchdog_timer, 29 * 60 * 1000000));

        rx_buffer[len] = '\0';
        ESP_LOGI(TAG, "Received: %s", rx_buffer);

        if (strstr(rx_buffer, "GET /v6 HTTP/1.1") != NULL)
        {
            char ipv6_address[64];
            if (get_global_ipv6_address(ipv6_address, sizeof(ipv6_address)))
            {
                char response[256];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/plain\r\n"
                         "\r\n"
                         "%s",
                         ipv6_address);
                send(sock, response, strlen(response), 0);
            }
            else
            {
                const char *response =
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Failed to retrieve IPv6 address";
                send(sock, response, strlen(response), 0);
            }
        }
        else if (strstr(rx_buffer, "GET /sync_cloudflare HTTP/1.1") != NULL)
        {
            if (strstr(rx_buffer, token) != NULL || check_cookie(rx_buffer))

            {
                ESP_LOGI(TAG, "Token verified, starting https_request_task");

                // 启动 https_request_task
                xTaskCreate(&https_request_task, "https_request_task", 8192, NULL, 5, NULL);

                const char *response_template =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "%s\r\n"
                    "\r\n"
                    "Task started";

                char response[512];
                snprintf(response, sizeof(response), response_template, generate_cookie_header(cookie, sizeof(cookie)));
                send(sock, response, strlen(response), 0);
            }
            else
            {
                const char *response =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Invalid token";
                send(sock, response, strlen(response), 0);
            }
        }
        else if (strstr(rx_buffer, "GET /wol HTTP/1.1") != NULL)
        {
            if (strstr(rx_buffer, token) != NULL || check_cookie(rx_buffer))
            {
                // 提取请求头中的 mac、board_address 和 port 字段
                char mac[18] = {0};
                char board_address[16] = {0};
                int port = 0;

                char *mac_header = strstr(rx_buffer, "mac:");
                char *board_address_header = strstr(rx_buffer, "board_address:");
                char *port_header = strstr(rx_buffer, "port:");

                if (mac_header && board_address_header && port_header)
                {
                    sscanf(mac_header, "mac: %17s", mac);
                    sscanf(board_address_header, "board_address: %15s", board_address);
                    sscanf(port_header, "port: %d", &port);
                    // 创建包含 WOL 三条数据的 JSON 变量并保存到 NVS
                    cJSON *wol_json = cJSON_CreateObject();
                    if (wol_json)
                    {
                        cJSON_AddStringToObject(wol_json, "wol_mac", mac);
                        cJSON_AddStringToObject(wol_json, "wol_addr", board_address);
                        cJSON_AddNumberToObject(wol_json, "wol_port", port);

                        // 保存到 NVS
                        save_config_to_nvs(wol_json);

                        // 释放 JSON 对象
                        cJSON_Delete(wol_json);
                    }
                    ESP_LOGI(TAG, "Received WOL request: mac=%s, board_address=%s, port=%d", mac, board_address, port);

                    // 发送 WOL 数据包
                    send_wol_packet(mac, board_address, port);
                    const char *response_template =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n"
                        "%s\r\n"
                        "\r\n"
                        "WOL packet sent";
                    char response[512];
                    snprintf(response, sizeof(response), response_template, generate_cookie_header(cookie, sizeof(cookie)));
                    send(sock, response, strlen(response), 0);
                }
                else
                {
                    const char *response =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: text/plain\r\n"
                        "\r\n"
                        "Missing or invalid headers";
                    send(sock, response, strlen(response), 0);
                }
            }
            else
            {
                const char *response =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Invalid token";
                send(sock, response, strlen(response), 0);
            }
        }
        else if (strstr(rx_buffer, "GET / HTTP/1.1") != NULL)
        {
            char ipv6_address[64];
            if (!get_global_ipv6_address(ipv6_address, sizeof(ipv6_address)))
            {
                snprintf(ipv6_address, sizeof(ipv6_address), "Failed to retrieve IPv6 address");
            }

            // 使用嵌入式文件读取 HTML 内容
            const char *html_template = (const char *)index_html_start;
            size_t html_size = index_html_end - index_html_start;

            // 确保 response 的大小足够容纳 HTML 和 IPv6 地址
            char response[html_size + 128];
            int response_len = snprintf(response, sizeof(response), html_template, ipv6_address);

            if (response_len < 0 || response_len >= sizeof(response))
            {
                const char *error_response =
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Failed to generate response";
                send(sock, error_response, strlen(error_response), 0);
            }
            else
            {
                // 发送响应头
                char header[128];
                int header_len = snprintf(header, sizeof(header),
                                          "HTTP/1.1 200 OK\r\n"
                                          "Content-Type: text/html\r\n"
                                          "Content-Length: %d\r\n"
                                          "\r\n",
                                          response_len);
                send(sock, header, header_len, 0);

                // 发送 HTML 内容
                send(sock, response, response_len, 0);
            }
        }
        else if (strstr(rx_buffer, "POST /setconfig HTTP/1.1") != NULL)
        {
            if (strstr(rx_buffer, token) != NULL || check_cookie(rx_buffer))
            {
                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body)
                {
                    body += 4; // 跳过 "\r\n\r\n"
                    cJSON *json = cJSON_Parse(body);
                    if (json)
                    {
                        save_config_to_nvs(json);
                        cJSON_Delete(json);
                        const char *response_template =
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "%s\r\n"
                            "\r\n"
                            "Configuration saved";
                        char response[512];
                        snprintf(response, sizeof(response), response_template, generate_cookie_header(cookie, sizeof(cookie)));
                        send(sock, response, strlen(response), 0);
                    }
                    else
                    {
                        const char *response =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: text/plain\r\n"
                            "\r\n"
                            "Invalid JSON";
                        send(sock, response, strlen(response), 0);
                    }
                }
            }
            else
            {
                const char *response =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Invalid token";
                send(sock, response, strlen(response), 0);
            }
        }
        else if (strstr(rx_buffer, "GET /getconfig HTTP/1.1") != NULL)
        {
            if (strstr(rx_buffer, token) != NULL || check_cookie(rx_buffer))
            {
                nvs_handle_t nvs_handle;
                esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
                if (err != ESP_OK)
                {
                    ESP_LOGW(TAG, "Failed to open NVS, returning default configuration");
                    cJSON *json = cJSON_CreateObject();
                    cJSON_AddStringToObject(json, "domain_name", domain_name);
                    cJSON_AddStringToObject(json, "aaaa_name", aaaa_name);
                    cJSON_AddStringToObject(json, "cloudflare_token", cloudflare_token);
                    cJSON_AddStringToObject(json, "token", token);
                    cJSON_AddStringToObject(json, "server_port", server_port);
                    char *response_body = cJSON_Print(json);
                    cJSON_Delete(json);

                    const char *response_template =
                        "HTTP/1.1 200 OK\r\n"
                        "%s\r\n"
                        "Content-Type: application/json\r\n"
                        "\r\n"
                        "%s";
                    char response[1024];
                    snprintf(response, sizeof(response), response_template, generate_cookie_header(cookie, sizeof(cookie)), response_body);

                    send(sock, response, strlen(response), 0);
                    free(response_body);
                    goto end_res;
                }

                // If NVS is opened successfully, proceed to read data
                cJSON *json = cJSON_CreateObject();
                char value[128];
                size_t size;

                if (nvs_get_str(nvs_handle, "domain_name", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "domain_name", value, &size);
                    cJSON_AddStringToObject(json, "domain_name", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "domain_name", domain_name);
                }

                if (nvs_get_str(nvs_handle, "aaaa_name", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "aaaa_name", value, &size);
                    cJSON_AddStringToObject(json, "aaaa_name", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "aaaa_name", aaaa_name);
                }

                if (nvs_get_str(nvs_handle, "cf_token", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "cf_token", value, &size);
                    cJSON_AddStringToObject(json, "cloudflare_token", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "cloudflare_token", cloudflare_token);
                }

                if (nvs_get_str(nvs_handle, "token", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "token", value, &size);
                    cJSON_AddStringToObject(json, "token", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "token", token);
                }

                if (nvs_get_str(nvs_handle, "server_port", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "server_port", value, &size);
                    cJSON_AddStringToObject(json, "server_port", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "server_port", server_port);
                }
                if (nvs_get_str(nvs_handle, "wifi_ssid", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "wifi_ssid", value, &size);
                    cJSON_AddStringToObject(json, "wifi_ssid", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "wifi_ssid", wifi_ssid);
                }
                if (nvs_get_str(nvs_handle, "wifi_passwd", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "wifi_passwd", value, &size);
                    cJSON_AddStringToObject(json, "wifi_passwd", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "wifi_passwd", wifi_passwd);
                }
                if (nvs_get_str(nvs_handle, "wol_mac", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "wol_mac", value, &size);
                    cJSON_AddStringToObject(json, "wol_mac", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "wol_mac", wol_mac);
                }
                if (nvs_get_str(nvs_handle, "wol_addr", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "wol_addr", value, &size);
                    cJSON_AddStringToObject(json, "wol_addr", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "wol_addr", wol_addr);
                }
                if (nvs_get_str(nvs_handle, "wol_port", NULL, &size) == ESP_OK)
                {
                    nvs_get_str(nvs_handle, "wol_port", value, &size);
                    cJSON_AddStringToObject(json, "wol_port", value);
                }
                else
                {
                    cJSON_AddStringToObject(json, "wol_port", wol_port);
                }

                nvs_close(nvs_handle);

                char *response_body = cJSON_Print(json);
                cJSON_Delete(json);

                const char *response_template =
                    "HTTP/1.1 200 OK\r\n"
                    "%s\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "%s";
                char response[1024];
                snprintf(response, sizeof(response), response_template, generate_cookie_header(cookie, sizeof(cookie)), response_body);
                send(sock, response, strlen(response), 0);
                free(response_body);
            }
            else
            {
                const char *response =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Invalid token";
                send(sock, response, strlen(response), 0);
            }
        }
        else if (strstr(rx_buffer, "GET /reboot HTTP/1.1") != NULL)
        {
            if (strstr(rx_buffer, token) != NULL || check_cookie(rx_buffer))
            {
                const char *response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Rebooting...";
                send(sock, response, strlen(response), 0);
                close(sock);
                esp_restart();
            }
            else
            {
                const char *response =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Invalid token";
                send(sock, response, strlen(response), 0);
            }
        }
        else
        {
            const char *response =
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "\r\n"
                "Invalid request";
            send(sock, response, strlen(response), 0);
        }
    end_res:
        close(sock);
    }

error:
    if (listen_sock != INVALID_SOCK)
    {
        close(listen_sock);
    }
    if (address_info)
    {
        free(address_info);
    }
    vTaskDelete(NULL);
}

static void periodic_https_request_task(void *arg)
{
    ESP_LOGI(TAG, "Periodic HTTPS request task triggered");
    xTaskCreate(&https_request_task, "https_request_task", 8192, NULL, 5, NULL);
}

// 从 NVS 读取配置
static void load_config_from_nvs()
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "Failed to open NVS, using default configuration");
        nvs_handle_t nvs_handle;
        esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to open NVS for initialization: %s", esp_err_to_name(err));
            return;
        }

        // 写入默认值
        nvs_set_str(nvs_handle, "domain_name", DOMAIN_NAME);
        nvs_set_str(nvs_handle, "aaaa_name", AAAA_NAME);
        nvs_set_str(nvs_handle, "cloudflare_token", CLOUDFLARE_TOKEN);
        nvs_set_str(nvs_handle, "token", TOKEN);
        nvs_set_str(nvs_handle, "server_port", SERVER_PORT);
        nvs_set_str(nvs_handle, "wifi_ssid", WIFI_SSID);
        nvs_set_str(nvs_handle, "wifi_passwd", WIFI_PASSWD);
        nvs_set_str(nvs_handle, "wol_mac", WOL_MAC);
        nvs_set_str(nvs_handle, "wol_addr", WOL_ADDR);
        nvs_set_str(nvs_handle, "wol_port", WOL_PORT);
        generate_cookie_header(cookie, COOKIE_LENGTH);
        // 提交更改
        err = nvs_commit(nvs_handle);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to commit NVS defaults: %s", esp_err_to_name(err));
        }

        nvs_close(nvs_handle);
        return;
    }

    size_t size;

    // 动态加载 domain_name
    if (nvs_get_str(nvs_handle, "domain_name", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "domain_name", temp, &size);
            strncpy(domain_name, temp, sizeof(domain_name));
            free(temp);
            ESP_LOGI(TAG, "Loaded domain_name: %s", domain_name);
        }
    }

    // 动态加载 aaaa_name
    if (nvs_get_str(nvs_handle, "aaaa_name", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "aaaa_name", temp, &size);
            strncpy(aaaa_name, temp, sizeof(aaaa_name));
            free(temp);
            ESP_LOGI(TAG, "Loaded aaaa_name: %s", aaaa_name);
        }
    }

    // 动态加载 cloudflare_token
    if (nvs_get_str(nvs_handle, "cf_token", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "cf_token", temp, &size);
            strncpy(cloudflare_token, temp, sizeof(cloudflare_token));
            free(temp);
            ESP_LOGI(TAG, "Loaded cloudflare_token: %s", cloudflare_token);
        }
    }

    // 动态加载 token
    if (nvs_get_str(nvs_handle, "token", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "token", temp, &size);
            strncpy(token, temp, sizeof(token));
            free(temp);
            ESP_LOGI(TAG, "Loaded token: %s", token);
        }
    }

    // 动态加载 server_port
    if (nvs_get_str(nvs_handle, "server_port", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "server_port", temp, &size);
            strncpy(server_port, temp, sizeof(server_port));
            free(temp);
            ESP_LOGI(TAG, "Loaded server_port: %s", server_port);
        }
    }
    if (nvs_get_str(nvs_handle, "wifi_ssid", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "wifi_ssid", temp, &size);
            strncpy(wifi_ssid, temp, sizeof(wifi_ssid));
            free(temp);
            ESP_LOGI(TAG, "Loaded wifi_ssid: %s", wifi_ssid);
        }
    }
    if (nvs_get_str(nvs_handle, "wifi_passwd", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "wifi_passwd", temp, &size);
            strncpy(wifi_passwd, temp, sizeof(wifi_passwd));
            free(temp);
            ESP_LOGI(TAG, "Loaded wifi_passwd: %s", wifi_passwd);
        }
    }
    if (nvs_get_str(nvs_handle, "wol_mac", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "wol_mac", temp, &size);
            strncpy(wol_mac, temp, sizeof(wol_mac));
            free(temp);
            ESP_LOGI(TAG, "Loaded wol_mac: %s", wol_mac);
        }
    }
    if (nvs_get_str(nvs_handle, "wol_addr", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "wol_addr", temp, &size);
            strncpy(wol_addr, temp, sizeof(wol_addr));
            free(temp);
            ESP_LOGI(TAG, "Loaded wol_board_address: %s", wol_addr);
        }
    }
    if (nvs_get_str(nvs_handle, "wol_port", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "wol_port", temp, &size);
            strncpy(wol_port, temp, sizeof(wol_port));
            free(temp);
            ESP_LOGI(TAG, "Loaded wol_port: %s", wol_port);
        }
    }
    if (nvs_get_str(nvs_handle, "cookie", NULL, &size) == ESP_OK)
    {
        char *temp = malloc(size);
        if (temp)
        {
            nvs_get_str(nvs_handle, "cookie", temp, &size);
            strncpy(cookie, temp, sizeof(cookie));
            free(temp);
            ESP_LOGI(TAG, "Loaded cookie: %s", cookie);
        }
    }
    else
    {
        generate_cookie_header(cookie, COOKIE_LENGTH);
    }
    nvs_close(nvs_handle);
}
// 保存配置到 NVS
static void save_config_to_nvs(cJSON *json)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to open NVS for writing");
        return;
    }

    cJSON *item;
    if ((item = cJSON_GetObjectItem(json, "domain_name")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "domain_name", item->valuestring);
        ESP_LOGI(TAG, "Saved domain_name: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "aaaa_name")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "aaaa_name", item->valuestring);
        ESP_LOGI(TAG, "Saved aaaa_name: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "cloudflare_token")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "cf_token", item->valuestring);
        ESP_LOGI(TAG, "Saved cloudflare_token: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "token")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "token", item->valuestring);
        ESP_LOGI(TAG, "Saved token: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "server_port")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "server_port", item->valuestring);
        ESP_LOGI(TAG, "Saved server_port: %s", item->valuestring);
    }
    // 保存 WiFi SSID 和密码到 NVS
    if ((item = cJSON_GetObjectItem(json, "wifi_ssid")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "wifi_ssid", item->valuestring);
        ESP_LOGI(TAG, "Saved wifi_ssid: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "wifi_passwd")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "wifi_passwd", item->valuestring);
        ESP_LOGI(TAG, "Saved wifi_passwd: %s", item->valuestring);
    }
    // 保存 WOL 参数到 NVS
    if ((item = cJSON_GetObjectItem(json, "wol_mac")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "wol_mac", item->valuestring);
        ESP_LOGI(TAG, "Saved wol_mac: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "wol_addr")) && cJSON_IsString(item))
    {
        nvs_set_str(nvs_handle, "wol_addr", item->valuestring);
        ESP_LOGI(TAG, "Saved wol_board_address: %s", item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "wol_port")) && cJSON_IsNumber(item))
    {
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", item->valueint);
        nvs_set_str(nvs_handle, "wol_port", port_str);
        ESP_LOGI(TAG, "Saved wol_port: %s", port_str);
    }

    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
}
#define BOOT_BUTTON_GPIO GPIO_NUM_0 // BOOT 按钮通常连接到 GPIO0
// 按钮中断处理函数
static void IRAM_ATTR boot_button_isr_handler(void *arg)
{
    // 设置标志或直接触发任务
    ets_printf("BOOT button pressed, erasing NVS...\n");

    // 清除 NVS 数据
    esp_err_t err = nvs_flash_erase();
    if (err == ESP_OK)
    {
        ets_printf("NVS erased successfully!\n");
    }
    else
    {
        ets_printf("Failed to erase NVS: %s\n", esp_err_to_name(err));
    }

    // 重启设备
    esp_restart();
}
#include "driver/gpio.h"

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // 配置 BOOT 按钮 GPIO
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BOOT_BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_NEGEDGE, // 检测下降沿（按钮按下）
    };
    gpio_config(&io_conf);

    // 注册中断服务
    gpio_install_isr_service(0);
    gpio_isr_handler_add(BOOT_BUTTON_GPIO, boot_button_isr_handler, NULL);
    init_random_generator();
    // 从 NVS 加载配置
    load_config_from_nvs();

    ESP_ERROR_CHECK(example_connect(wifi_ssid, wifi_passwd));

    // 启动支持 IPv4 和 IPv6 的服务器任务
    xTaskCreate(&ipv4_ipv6_server_task, "ipv4_ipv6_server_task", 16384, NULL, 5, NULL);

    if (esp_reset_reason() == ESP_RST_POWERON)
    {
        ESP_LOGI(TAG, "Updating time from NVS");
        ESP_ERROR_CHECK(update_time_from_nvs());
    }

    const esp_timer_create_args_t nvs_update_timer_args = {
        .callback = (void *)&fetch_and_store_time_in_nvs,
    };

    esp_timer_handle_t nvs_update_timer;
    ESP_ERROR_CHECK(esp_timer_create(&nvs_update_timer_args, &nvs_update_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(nvs_update_timer, TIME_PERIOD));
    const esp_timer_create_args_t http_request_watchdog_timer_args = {
        .callback = &http_request_watchdog_callback,
    };

    ESP_ERROR_CHECK(esp_timer_create(&http_request_watchdog_timer_args, &http_request_watchdog_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(http_request_watchdog_timer, 29 * 60 * 1000000));

    // 检查 cloudflare_token 是否为空
    if (strlen(cloudflare_token) > 0)
    {
        ESP_LOGI(TAG, "cloudflare_token is not empty, starting periodic HTTPS request timer.");
        // 立刻运行一次
        xTaskCreate(&https_request_task, "https_request_task", 8192, NULL, 5, NULL);
        // 添加每 5 分钟运行一次的计时器
        const esp_timer_create_args_t periodic_https_request_timer_args = {
            .callback = &periodic_https_request_task,
        };

        esp_timer_handle_t periodic_https_request_timer;
        ESP_ERROR_CHECK(esp_timer_create(&periodic_https_request_timer_args, &periodic_https_request_timer));
        ESP_ERROR_CHECK(esp_timer_start_periodic(periodic_https_request_timer, 5 * 60 * 1000000)); // 5 分钟
    }
    else
    {
        ESP_LOGW(TAG, "cloudflare_token is empty, skipping periodic HTTPS request timer.");
    }
}
