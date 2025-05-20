#include "network_module.h"
#include <string.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_eth.h"
#include "esp_eth_mac.h"
#include "esp_eth_phy.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "driver/gpio.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

// Logging tag
static const char *TAG = "ETH_MODULE";

// Ethernet connection status
static EventGroupHandle_t eth_event_group;
#define ETH_CONNECTED_BIT BIT0
#define ETH_DISCONNECTED_BIT BIT1

// TCP Server parameters
#define TCP_SERVER_TASK_STACK_SIZE 4096
#define TCP_SERVER_TASK_PRIORITY 5
#define MAX_CONNECTIONS 5
#define BUFFER_SIZE 2048

// Ethernet connection parameters
static esp_eth_handle_t eth_handle = NULL;
static esp_netif_t *eth_netif = NULL;
static int server_socket = -1;
static int client_socket = -1;
static TaskHandle_t tcp_server_task_handle = NULL;

// Forward declarations for static functions
static void tcp_server_task(void *pvParameters);
static esp_err_t send_json_to_client(const cJSON *json_obj);
static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

// -- Ethernet Initialization --

esp_err_t ethernet_init(const uint8_t *mac_address) {
    ESP_LOGI(TAG, "Initializing Ethernet...");
    
    // Create event group for ethernet status
    eth_event_group = xEventGroupCreate();
    if (eth_event_group == NULL) {
        ESP_LOGE(TAG, "Failed to create ethernet event group");
        return ESP_FAIL;
    }
    
    // Initialize TCP/IP network interface
    ESP_ERROR_CHECK(esp_netif_init());
    
    // Create default event loop if not already created
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // Create ethernet network interface
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    eth_netif = esp_netif_new(&netif_cfg);
    
    // Configure ethernet MAC and PHY
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    
    // Set custom MAC address if provided
    if (mac_address != NULL) {
        memcpy(mac_config.mac, mac_address, 6);
    }
    
    // LAN8720 PHY configuration - update pins as needed for your hardware
    phy_config.phy_addr = 0;
    phy_config.reset_gpio_num = 5;  // GPIO number connected to PHY reset
    
    // ESP32 Ethernet pins configuration - update for your hardware
    eth_esp32_emac_config_t esp32_emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    esp32_emac_config.smi_mdc_gpio_num = 23;  // GPIO for MDC
    esp32_emac_config.smi_mdio_gpio_num = 18; // GPIO for MDIO
    esp32_emac_config.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN; // External crystal
    esp32_emac_config.clock_config.rmii.clock_gpio = 0;               // GPIO0 for 50MHz RMII clock input
    
    // Create MAC and PHY instances
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&esp32_emac_config, &mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan8720(&phy_config);
    
    // Create ethernet driver
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));
    
    // Attach ethernet driver to network interface
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    
    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL));
    
    // Start ethernet driver
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    
    ESP_LOGI(TAG, "Ethernet initialized successfully");
    return ESP_OK;
}

esp_err_t disable_wifi() {
    ESP_LOGI(TAG, "Disabling WiFi to save power...");
    
    // Stop WiFi if it's running
    esp_err_t err = esp_wifi_stop();
    if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_INIT) {
        ESP_LOGE(TAG, "Failed to stop WiFi: %s", esp_err_to_name(err));
        return err;
    }
    
    // Deinitialize WiFi driver
    err = esp_wifi_deinit();
    if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_INIT) {
        ESP_LOGE(TAG, "Failed to deinitialize WiFi: %s", esp_err_to_name(err));
        return err;
    }
    
    ESP_LOGI(TAG, "WiFi disabled successfully");
    return ESP_OK;
}

// -- Ethernet event handler --

static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == ETH_EVENT) {
        switch (event_id) {
            case ETHERNET_EVENT_CONNECTED:
                ESP_LOGI(TAG, "Ethernet Link Up");
                xEventGroupClearBits(eth_event_group, ETH_DISCONNECTED_BIT);
                xEventGroupSetBits(eth_event_group, ETH_CONNECTED_BIT);
                break;
                
            case ETHERNET_EVENT_DISCONNECTED:
                ESP_LOGI(TAG, "Ethernet Link Down");
                xEventGroupClearBits(eth_event_group, ETH_CONNECTED_BIT);
                xEventGroupSetBits(eth_event_group, ETH_DISCONNECTED_BIT);
                break;
                
            case ETHERNET_EVENT_START:
                ESP_LOGI(TAG, "Ethernet Started");
                break;
                
            case ETHERNET_EVENT_STOP:
                ESP_LOGI(TAG, "Ethernet Stopped");
                break;
                
            default:
                break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "Ethernet Got IP Address: "IPSTR, IP2STR(&event->ip_info.ip));
    }
}

// -- TCP Server Implementation --

esp_err_t ethernet_server_init(uint16_t port) {
    ESP_LOGI(TAG, "Starting TCP server on port %d", port);
    
    // Store the port as a parameter for the server task
    uint16_t *port_param = (uint16_t *)malloc(sizeof(uint16_t));
    if (port_param == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for port parameter");
        return ESP_ERR_NO_MEM;
    }
    *port_param = port;
    
    // Create TCP server task
    BaseType_t task_created = xTaskCreate(
        tcp_server_task,
        "tcp_server_task",
        TCP_SERVER_TASK_STACK_SIZE,
        port_param,
        TCP_SERVER_TASK_PRIORITY,
        &tcp_server_task_handle
    );
    
    if (task_created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create TCP server task");
        free(port_param);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "TCP server task created successfully");
    return ESP_OK;
}

static void tcp_server_task(void *pvParameters) {
    uint16_t port = *(uint16_t *)pvParameters;
    free(pvParameters); // Free the memory allocated for the port parameter
    
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char rx_buffer[BUFFER_SIZE];
    
    // Wait for ethernet to connect before starting server
    xEventGroupWaitBits(eth_event_group, ETH_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (server_socket < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind socket to port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        ESP_LOGE(TAG, "Socket bind failed: errno %d", errno);
        close(server_socket);
        vTaskDelete(NULL);
        return;
    }
    
    // Listen for connections
    if (listen(server_socket, MAX_CONNECTIONS) != 0) {
        ESP_LOGE(TAG, "Socket listen failed: errno %d", errno);
        close(server_socket);
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "TCP server listening on port %d", port);
    
    while (1) {
        // Handle connection loss and reconnection
        if (client_socket < 0) {
            ESP_LOGI(TAG, "Waiting for client connection...");
            client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
            if (client_socket < 0) {
                ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }
            ESP_LOGI(TAG, "Client connected: %s:%d", 
                     inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }
        
        // Receive data from client
        int bytes_received = recv(client_socket, rx_buffer, sizeof(rx_buffer) - 1, 0);
        
        if (bytes_received < 0) {
            ESP_LOGE(TAG, "Error receiving data: errno %d", errno);
            close(client_socket);
            client_socket = -1;
            continue;
        } else if (bytes_received == 0) {
            ESP_LOGI(TAG, "Client disconnected");
            close(client_socket);
            client_socket = -1;
            continue;
        } else {
            // Null-terminate the received data
            rx_buffer[bytes_received] = 0;
            ESP_LOGI(TAG, "Received %d bytes: %s", bytes_received, rx_buffer);
            
            // Parse and handle the command (implement command handling logic)
            // TODO: Implement command handling
            // parse_and_handle_command(rx_buffer);
            
            // For now, just send back an acknowledgment
            const char *response = "{\"status\":\"ok\",\"message\":\"Command received\"}";
            send(client_socket, response, strlen(response), 0);
        }
    }
    
    // This point should never be reached
    close(server_socket);
    vTaskDelete(NULL);
}

// -- Status Reporting Functions --

esp_err_t send_status_to_master(const tracker_status_t *status) {
    if (!ethernet_is_connected() || client_socket < 0) {
        ESP_LOGW(TAG, "Cannot send status: No client connected");
        return ESP_ERR_INVALID_STATE;
    }
    
    // Create JSON object
    cJSON *root = cJSON_CreateObject();
    
    // Add status information
    cJSON_AddStringToObject(root, "type", "status_update");
    cJSON_AddNumberToObject(root, "timestamp", (double)time(NULL));
    cJSON_AddNumberToObject(root, "current_azimuth", status->current_azimuth);
    cJSON_AddNumberToObject(root, "current_tilt", status->current_tilt);
    cJSON_AddNumberToObject(root, "target_azimuth", status->target_azimuth);
    cJSON_AddNumberToObject(root, "target_tilt", status->target_tilt);
    cJSON_AddBoolToObject(root, "azimuth_motor_active", status->azimuth_motor_active);
    cJSON_AddBoolToObject(root, "tilt_motor_active", status->tilt_motor_active);
    cJSON_AddBoolToObject(root, "emergency_brake_active", status->emergency_brake_active);
    cJSON_AddNumberToObject(root, "motor_load_azimuth", status->motor_load_azimuth);
    cJSON_AddNumberToObject(root, "motor_load_tilt", status->motor_load_tilt);
    cJSON_AddNumberToObject(root, "power_output", status->power_output);
    cJSON_AddNumberToObject(root, "panel_temperature", status->panel_temperature);
    cJSON_AddNumberToObject(root, "uptime", status->uptime);
    cJSON_AddStringToObject(root, "last_error", status->last_error);
    
    // Send JSON to client
    esp_err_t result = send_json_to_client(root);
    
    // Free JSON object
    cJSON_Delete(root);
    
    return result;
}

static esp_err_t send_json_to_client(const cJSON *json_obj) {
    esp_err_t result = ESP_OK;
    
    // Convert JSON to string
    char *json_str = cJSON_PrintUnformatted(json_obj);
    if (json_str == NULL) {
        ESP_LOGE(TAG, "Failed to convert JSON to string");
        return ESP_FAIL;
    }
    
    // Send JSON string to client
    int bytes_sent = send(client_socket, json_str, strlen(json_str), 0);
    if (bytes_sent < 0) {
        ESP_LOGE(TAG, "Error sending data: errno %d", errno);
        result = ESP_FAIL;
        
        // Close and reset the socket on error
        close(client_socket);
        client_socket = -1;
    } else {
        ESP_LOGD(TAG, "Sent %d bytes: %s", bytes_sent, json_str);
    }
    
    // Free the JSON string
    free(json_str);
    
    return result;
}

void process_master_commands() {
    // This function should be called regularly to process any pending commands
    // It's a placeholder for now - actual implementation will depend on your command structure
    
    // In a full implementation, this would check for commands in a queue or 
    // directly from the socket if non-blocking mode is set
}

bool ethernet_is_connected() {
    EventBits_t bits = xEventGroupGetBits(eth_event_group);
    return (bits & ETH_CONNECTED_BIT) != 0;
}

void remote_log(const char *format, ...) {
    // Format message locally
    char local_buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(local_buffer, sizeof(local_buffer), format, args);
    va_end(args);
    
    // Log locally
    ESP_LOGI(TAG, "%s", local_buffer);
    
    // Send to master if connected
    if (ethernet_is_connected() && client_socket >= 0) {
        // Create JSON log message
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "log");
        cJSON_AddStringToObject(root, "message", local_buffer);
        cJSON_AddNumberToObject(root, "timestamp", (double)time(NULL));
        
        // Send JSON to client
        send_json_to_client(root);
        
        // Free JSON object
        cJSON_Delete(root);
    }
}