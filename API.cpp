#include <stdio.h>
#include <string.h>

// FreeRTOS
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

// ESP System
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"

// Networking
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_client.h"

// JSON Parsing
#include "cJSON.h"

// --- Configuration ---
// Option 1: Configure via menuconfig (idf.py menuconfig) - Recommended
#define WIFI_SSID      CONFIG_WIFI_SSID
#define WIFI_PASS      CONFIG_WIFI_PASSWORD
#define API_URL        CONFIG_API_URL // e.g., "http://your.website.com/api/angles"

/* // Option 2: Hardcode here (Not Recommended for credentials)
#define WIFI_SSID      "your_wifi_ssid"
#define WIFI_PASS      "your_wifi_password"
#define API_URL        "http://your.website.com/api/angles"
*/

// Task Parameters
#define API_FETCH_TASK_PRIORITY   5
#define API_FETCH_TASK_STACK_SIZE 8192 // Needs sufficient stack for networking & JSON
#define API_FETCH_INTERVAL_MS     (5 * 60 * 1000) // Fetch every 5 minutes
#define HTTP_TIMEOUT_MS           10000 // 10 seconds timeout

// Wi-Fi Connection Retry Limit
#define WIFI_MAXIMUM_RETRY        5

// --- Global Variables ---
static const char *TAG = "API_FETCHER";

// Event group to signal Wi-Fi connection status
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;
const int WIFI_FAIL_BIT      = BIT1;
static int s_retry_num = 0; // Wi-Fi connection retry counter

// --- Function Prototypes ---
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
static void wifi_init_sta(void);
static esp_err_t _http_event_handler(esp_http_client_event_t *evt);
static void fetch_angles_from_api(void);
static void api_fetch_task(void *pvParameters);

// --- Wi-Fi Connection Functions ---

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        ESP_LOGI(TAG, "Wi-Fi station started, attempting to connect...");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry Wi-Fi connection (%d/%d)...", s_retry_num, WIFI_MAXIMUM_RETRY);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "Failed to connect to Wi-Fi after %d retries.", WIFI_MAXIMUM_RETRY);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0; // Reset retry counter on successful connection
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init()); // Initialize TCP/IP stack

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta(); // Create default Wi-Fi station

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Register event handlers
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    // Configure Wi-Fi
    wifi_config_t wifi_config = {
        .sta = {
            // Use configured SSID and Password
            // .threshold.authmode = WIFI_AUTH_WPA2_PSK, // Set auth mode if needed
            // .pmf_cfg = { // Enable PMF if needed
            //     .capable = true,
            //     .required = false
            // },
        },
    };
    // Copy SSID and Password from defines/config
    strncpy((char*)wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, WIFI_PASS, sizeof(wifi_config.sta.password) - 1);


    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    // --- Wait for connection result ---
    // This waits indefinitely blocks execution until either connection succeeds or fails after retries.
    // Consider making this non-blocking or adding a timeout if needed in a larger application.
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE, // Don't clear bits on exit
            pdFALSE, // Wait for EITHER bit
            portMAX_DELAY); // Wait forever

    // Check connection result
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to AP SSID: %s", WIFI_SSID);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect to SSID: %s", WIFI_SSID);
        // Handle connection failure (e.g., retry later, enter fallback mode)
    } else {
        ESP_LOGE(TAG, "UNEXPECTED WIFI EVENT during connection wait");
    }
    // Note: The event handlers remain registered to handle future disconnections.
}

// --- HTTP Client & API Fetching Functions ---

/**
 * @brief Event handler for HTTP client events.
 *
 * Handles receiving data and other HTTP events. Stores response data in the buffer
 * provided via evt->user_data.
 */
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    static int output_len; // Stores number of bytes read into the user buffer

    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            output_len = 0; // Reset buffer length counter for new connection
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Check if user_data buffer is valid and has space
            if (evt->user_data != NULL && (output_len + evt->data_len < evt->buffer_len)) {
                memcpy(evt->user_data + output_len, evt->data, evt->data_len);
                output_len += evt->data_len;
                // Null-terminate the buffer assuming it's string data
                 ((char*)evt->user_data)[output_len] = '\0';
            } else if (evt->user_data != NULL) {
                ESP_LOGW(TAG, "HTTP Response buffer overflow! Current len: %d, New data: %d, Buffer size: %d", output_len, evt->data_len, evt->buffer_len);
                // Handle overflow, maybe stop copying or return error
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            output_len = 0; // Reset buffer length counter
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
             int mbedtls_err = 0;
             esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
             if (err != 0) {
                 ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                 ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
             }
            output_len = 0; // Reset buffer length counter
            break;
        case HTTP_EVENT_REDIRECT:
             ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
             // Optional: Add headers if needed for redirection
             // esp_http_client_set_header(evt->client, "From", "user@example.com");
             // esp_http_client_set_header(evt->client, "Accept", "application/json");
             break;
    }
    return ESP_OK;
}


/**
 * @brief Fetches angle data from the configured API URL.
 *
 * Performs an HTTP GET request, parses the JSON response, and logs the angles.
 */
static void fetch_angles_from_api(void) {
    char response_buffer[512]; // Buffer to store HTTP response body
    memset(response_buffer, 0, sizeof(response_buffer)); // Clear the buffer initially

    esp_http_client_config_t config = {
        .url = API_URL,
        .event_handler = _http_event_handler,
        .user_data = response_buffer,        // Pass buffer to event handler
        .buffer_size = sizeof(response_buffer), // Inform handler of buffer size
        .timeout_ms = HTTP_TIMEOUT_MS,
        .disable_auto_redirect = false,      // Follow redirects if any
        .crt_bundle_attach = esp_crt_bundle_attach, // Enable HTTPS support if API URL is https
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // Perform GET request
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        int status_code = esp_http_client_get_status_code(client);
        ESP_LOGI(TAG, "HTTP GET Status = %d", status_code);

        if (status_code == 200 && strlen(response_buffer) > 0) {
            ESP_LOGD(TAG, "HTTP Response Body (first %d bytes): %s", (int)sizeof(response_buffer)-1, response_buffer);

            // Parse JSON response
            cJSON *root = cJSON_Parse(response_buffer);
            if (root != NULL) {
                cJSON *azimuth_json = cJSON_GetObjectItem(root, "azimuth");
                cJSON *tilt_json = cJSON_GetObjectItem(root, "tilt");

                if (cJSON_IsNumber(azimuth_json) && cJSON_IsNumber(tilt_json)) {
                    double azimuth = azimuth_json->valuedouble;
                    double tilt = tilt_json->valuedouble;

                    // --- Use the fetched angles ---
                    // In a real application, you would pass these values to the
                    // part of your code that needs them (e.g., motor control task).
                    ESP_LOGI(TAG, "Successfully fetched angles: Azimuth=%.2f, Tilt=%.2f", azimuth, tilt);
                    // Example: update_tracker_target(azimuth, tilt);
                    // -----------------------------

                } else {
                    ESP_LOGE(TAG, "JSON parsing error: Could not find 'azimuth' or 'tilt' numbers in response.");
                    ESP_LOGE(TAG, "Received JSON: %s", response_buffer); // Log received data on error
                }
                cJSON_Delete(root); // Free JSON object memory
            } else {
                ESP_LOGE(TAG, "Failed to parse JSON response. Error ptr: %s", cJSON_GetErrorPtr());
                ESP_LOGE(TAG, "Received Data: %s", response_buffer); // Log received data on error
            }
        } else if (status_code != 200) {
             ESP_LOGE(TAG, "HTTP request failed with status code: %d", status_code);
             ESP_LOGE(TAG, "Response body: %s", response_buffer); // Log body even on error status
        } else if (strlen(response_buffer) == 0) {
             ESP_LOGW(TAG, "HTTP request successful (Status %d), but response body was empty.", status_code);
        }

    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    // Cleanup
    esp_http_client_cleanup(client);
}

/**
 * @brief FreeRTOS task to periodically fetch angles from the API.
 */
static void api_fetch_task(void *pvParameters) {
    ESP_LOGI(TAG, "API fetch task started. Waiting for Wi-Fi connection...");

    // Wait indefinitely for the initial Wi-Fi connection
    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);

    ESP_LOGI(TAG, "Wi-Fi connected. Starting API fetch loop (Interval: %d ms).", API_FETCH_INTERVAL_MS);

    while(1) {
        // Check if Wi-Fi is still connected before attempting fetch
        EventBits_t bits = xEventGroupGetBits(wifi_event_group);
        if (bits & WIFI_CONNECTED_BIT) {
            ESP_LOGI(TAG, "Fetching angles from API: %s", API_URL);
            fetch_angles_from_api();
        } else {
            ESP_LOGW(TAG, "Wi-Fi disconnected. Skipping API fetch. Waiting for reconnect...");
            // Wait until Wi-Fi reconnects (or task gets deleted/system restarts)
            xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
            ESP_LOGI(TAG, "Wi-Fi reconnected. Resuming API fetch loop.");
            continue; // Skip the delay at the end and fetch immediately after reconnect
        }

        // Wait for the next fetch interval
        vTaskDelay(pdMS_TO_TICKS(API_FETCH_INTERVAL_MS));
    }
}

// --- Main Application Entry Point ---
void app_main(void) {
    ESP_LOGI(TAG, "Initializing API Angle Fetcher...");

    // Initialize NVS Flash (required for Wi-Fi persistence)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize Wi-Fi and connect
    wifi_init_sta(); // This function blocks until connected or failed

    // Check if Wi-Fi connection was successful before starting the task
    EventBits_t bits = xEventGroupGetBits(wifi_event_group);
    if (bits & WIFI_CONNECTED_BIT) {
        // Create the API fetching task
        xTaskCreate(api_fetch_task,             // Task function
                    "api_fetch_task",         // Task name
                    API_FETCH_TASK_STACK_SIZE,// Stack size
                    NULL,                     // Parameter
                    API_FETCH_TASK_PRIORITY,  // Priority
                    NULL);                    // Task handle (optional)
        ESP_LOGI(TAG, "API fetch task created.");
    } else {
         ESP_LOGE(TAG, "Wi-Fi connection failed. API fetch task will not start.");
         // Handle the failure case appropriately (e.g., retry connection, reboot, enter error state)
    }

    ESP_LOGI(TAG, "Initialization complete. Main task exiting (if fetch task created).");
    // app_main can exit; FreeRTOS scheduler keeps tasks running.
}
