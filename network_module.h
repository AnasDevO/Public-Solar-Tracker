#ifndef NETWORK_MODULE_H
#define NETWORK_MODULE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * @brief Defines the status of the solar tracker that can be reported
 */
typedef struct {
    float current_azimuth;      // Current azimuth angle in degrees
    float current_tilt;         // Current tilt angle in degrees
    float target_azimuth;       // Target azimuth angle in degrees
    float target_tilt;          // Target tilt angle in degrees
    bool azimuth_motor_active;  // True if azimuth motor is active
    bool tilt_motor_active;     // True if tilt motor is active
    bool emergency_brake_active; // True if emergency brake is active
    float motor_load_azimuth;   // Current load on azimuth motor (%)
    float motor_load_tilt;      // Current load on tilt motor (%)
    float power_output;         // Current power output in watts
    float panel_temperature;    // Panel temperature in degrees Celsius
    uint32_t uptime;            // System uptime in seconds
    char last_error[64];        // Last error message
} tracker_status_t;

/**
 * @brief Initialize the Ethernet (RJ45) connection
 * 
 * @param mac_address Optional MAC address to use (NULL for default)
 * @return esp_err_t ESP_OK on success, error otherwise
 */
esp_err_t ethernet_init(const uint8_t *mac_address);

/**
 * @brief Disable the WiFi module to save power and avoid interference
 * 
 * @return esp_err_t ESP_OK on success, error otherwise
 */
esp_err_t disable_wifi();

/**
 * @brief Initialize TCP/IP server on Ethernet
 * 
 * @param port TCP port to listen on
 * @return esp_err_t ESP_OK on success, error otherwise
 */
esp_err_t ethernet_server_init(uint16_t port);

/**
 * @brief Send tracker status data to the master system
 * 
 * @param status Pointer to status structure containing all tracker data
 * @return esp_err_t ESP_OK on success, error otherwise
 */
esp_err_t send_status_to_master(const tracker_status_t *status);

/**
 * @brief Process incoming commands from the master system
 * This function should be called regularly to handle incoming commands
 */
void process_master_commands();

/**
 * @brief Check if ethernet connection is active
 * 
 * @return true if connected, false otherwise
 */
bool ethernet_is_connected();

/**
 * @brief Log message to both local console and remote master if connected
 * 
 * @param format printf-style format string
 * @param ... Variable arguments
 */
void remote_log(const char *format, ...);

#endif // NETWORK_MODULE_H