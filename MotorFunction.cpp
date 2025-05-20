#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include "driver/gpio.h"
#include "driver/adc.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "esp_adc_cal.h"
#include "motorfunction.h"
#include "network_module.h"
#include <math.h>

// Tag for logging
static const char *TAG = "SOLAR_TRACKER";

// --- Configuration ---
// Motor control pins
#define AZIMUTH_MOTOR_PIN_A 25  // Direction pin A for Azimuth motor
#define AZIMUTH_MOTOR_PIN_B 26  // Direction pin B for Azimuth motor
#define AZIMUTH_MOTOR_PWM_PIN 27 // PWM speed control for Azimuth motor
#define AZIMUTH_MOTOR_EN_PIN 14  // Enable pin for Azimuth motor

#define TILT_MOTOR_PIN_A 32     // Direction pin A for Tilt motor
#define TILT_MOTOR_PIN_B 33     // Direction pin B for Tilt motor
#define TILT_MOTOR_PWM_PIN 15   // PWM speed control for Tilt motor
#define TILT_MOTOR_EN_PIN 13    // Enable pin for Tilt motor

#define AZIMUTH_BRAKE_PIN 18    // Emergency brake pin for Azimuth motor
#define TILT_BRAKE_PIN 19       // Emergency brake pin for Tilt motor

// Feedback pins (potentiometers or encoders)
#define AZIMUTH_FEEDBACK_PIN ADC1_CHANNEL_0  // ADC channel for Azimuth position feedback
#define TILT_FEEDBACK_PIN ADC1_CHANNEL_3     // ADC channel for Tilt position feedback

// Current sensing pins for overload detection
#define AZIMUTH_CURRENT_SENSE_PIN ADC1_CHANNEL_6  // ADC channel for Azimuth current sensing
#define TILT_CURRENT_SENSE_PIN ADC1_CHANNEL_7     // ADC channel for Tilt current sensing

// Power output monitoring
#define POWER_SENSOR_PIN ADC1_CHANNEL_4      // ADC channel for power output monitoring
#define TEMP_SENSOR_PIN ADC1_CHANNEL_5       // ADC channel for temperature sensor

// PWM Configuration for motor speed control
#define PWM_FREQUENCY 5000      // 5 kHz
#define PWM_RESOLUTION LEDC_TIMER_10_BIT  // 10-bit resolution (0-1023)
#define AZIMUTH_PWM_CHANNEL LEDC_CHANNEL_0
#define TILT_PWM_CHANNEL LEDC_CHANNEL_1

// Control parameters
#define MOTOR_CONTROL_TASK_PRIORITY 5
#define MOTOR_CONTROL_TASK_STACK_SIZE 4096
#define MOTOR_CONTROL_LOOP_DELAY_MS 50  // Shorter delay for more responsive control
#define ANGLE_TOLERANCE 0.5f     // Smaller tolerance for more precise positioning
#define RAMP_UP_INCREMENT 10     // How quickly to ramp up PWM (lower for gentler starts)
#define RAMP_DOWN_INCREMENT 5    // How quickly to ramp down PWM (lower for gentler stops)
#define SLOW_ZONE_DEGREES 5.0f   // Degrees from target to start slowing down
#define MAX_CURRENT_AZIMUTH 2.0f // Maximum current in amps before emergency brake
#define MAX_CURRENT_TILT 1.5f    // Maximum current in amps before emergency brake
#define STATUS_UPDATE_INTERVAL_MS 5000  // Send status update every 5 seconds

// Calibration values for sensors
// ADC readings for min/max positions (need to be calibrated for actual hardware)
#define AZIMUTH_MIN_ADC 100
#define AZIMUTH_MAX_ADC 4000
#define AZIMUTH_MIN_ANGLE 0.0f
#define AZIMUTH_MAX_ANGLE 360.0f

#define TILT_MIN_ADC 100
#define TILT_MAX_ADC 4000
#define TILT_MIN_ANGLE 0.0f
#define TILT_MAX_ANGLE 90.0f

// --- Global Variables ---
// Target angles
static volatile float g_target_azimuth = 0.0f;
static volatile float g_target_tilt = 0.0f;

// Current angles (updated from sensor readings)
static float g_current_azimuth = 0.0f;
static float g_current_tilt = 0.0f;

// Motor status variables
static bool g_azimuth_motor_active = false;
static bool g_tilt_motor_active = false;
static bool g_emergency_brake_active = false;
static int g_azimuth_pwm_duty = 0;  // Current PWM duty cycle (0-1023)
static int g_tilt_pwm_duty = 0;     // Current PWM duty cycle (0-1023)
static float g_motor_load_azimuth = 0.0f; // Current load as percentage
static float g_motor_load_tilt = 0.0f;    // Current load as percentage
static float g_power_output = 0.0f;       // Panel power output in watts
static float g_panel_temperature = 0.0f;  // Panel temperature in Celsius
static uint32_t g_uptime_seconds = 0;     // System uptime
static char g_last_error[64] = "None";    // Last error message

// Mutexes and timers
static SemaphoreHandle_t g_angle_mutex = NULL;
static TimerHandle_t g_status_timer = NULL;

// ADC calibration
static esp_adc_cal_characteristics_t g_adc_chars;

// --- Function Prototypes ---
static void setup_motors(void);
static void setup_adc(void);
static void setup_pwm(void);
static void move_azimuth_motor(int direction, int speed); // With speed control
static void move_tilt_motor(int direction, int speed);    // With speed control
static float read_current_azimuth(void);
static float read_current_tilt(void);
static float read_motor_current(adc1_channel_t channel);
static float read_power_output(void);
static float read_panel_temperature(void);
static void motor_control_task(void *pvParameters);
static void emergency_brake_azimuth(void);
static void emergency_brake_tilt(void);
static void release_brake_azimuth(void);
static void release_brake_tilt(void);
static void status_timer_callback(TimerHandle_t xTimer);
static void update_uptime(void);
static void send_status_update(void);

// --- Function Implementations ---

/**
 * @brief Configure hardware for motor control.
 */
static void setup_motors(void) {
    ESP_LOGI(TAG, "Setting up motor GPIOs...");

    // Configure Azimuth Motor Pins
    gpio_reset_pin(AZIMUTH_MOTOR_PIN_A);
    gpio_set_direction(AZIMUTH_MOTOR_PIN_A, GPIO_MODE_OUTPUT);
    gpio_reset_pin(AZIMUTH_MOTOR_PIN_B);
    gpio_set_direction(AZIMUTH_MOTOR_PIN_B, GPIO_MODE_OUTPUT);
    gpio_reset_pin(AZIMUTH_MOTOR_EN_PIN);
    gpio_set_direction(AZIMUTH_MOTOR_EN_PIN, GPIO_MODE_OUTPUT);
    gpio_reset_pin(AZIMUTH_BRAKE_PIN);
    gpio_set_direction(AZIMUTH_BRAKE_PIN, GPIO_MODE_OUTPUT);

    // Configure Tilt Motor Pins
    gpio_reset_pin(TILT_MOTOR_PIN_A);
    gpio_set_direction(TILT_MOTOR_PIN_A, GPIO_MODE_OUTPUT);
    gpio_reset_pin(TILT_MOTOR_PIN_B);
    gpio_set_direction(TILT_MOTOR_PIN_B, GPIO_MODE_OUTPUT);
    gpio_reset_pin(TILT_MOTOR_EN_PIN);
    gpio_set_direction(TILT_MOTOR_EN_PIN, GPIO_MODE_OUTPUT);
    gpio_reset_pin(TILT_BRAKE_PIN);
    gpio_set_direction(TILT_BRAKE_PIN, GPIO_MODE_OUTPUT);

    // Initialize brake pins to inactive state (assuming active low)
    gpio_set_level(AZIMUTH_BRAKE_PIN, 1); // Release brake
    gpio_set_level(TILT_BRAKE_PIN, 1);    // Release brake

    // Ensure motors are stopped and disabled initially
    gpio_set_level(AZIMUTH_MOTOR_EN_PIN, 0);
    gpio_set_level(TILT_MOTOR_EN_PIN, 0);
    move_azimuth_motor(0, 0);
    move_tilt_motor(0, 0);

    ESP_LOGI(TAG, "Motor GPIOs setup complete.");

    // Setup PWM for speed control
    setup_pwm();
}

/**
 * @brief Configure ADC for sensor readings
 */
static void setup_adc(void) {
    ESP_LOGI(TAG, "Setting up ADC for sensors...");

    // Configure ADC
    adc1_config_width(ADC_WIDTH_BIT_12);  // 12-bit resolution (0-4095)

    // Configure ADC channels
    adc1_config_channel_atten(AZIMUTH_FEEDBACK_PIN, ADC_ATTEN_DB_11);
    adc1_config_channel_atten(TILT_FEEDBACK_PIN, ADC_ATTEN_DB_11);
    adc1_config_channel_atten(AZIMUTH_CURRENT_SENSE_PIN, ADC_ATTEN_DB_11);
    adc1_config_channel_atten(TILT_CURRENT_SENSE_PIN, ADC_ATTEN_DB_11);
    adc1_config_channel_atten(POWER_SENSOR_PIN, ADC_ATTEN_DB_11);
    adc1_config_channel_atten(TEMP_SENSOR_PIN, ADC_ATTEN_DB_11);

    // Characterize ADC for more accurate readings
    esp_adc_cal_characterize(ADC_UNIT_1, ADC_ATTEN_DB_11, ADC_WIDTH_BIT_12, 1100, &g_adc_chars);

    ESP_LOGI(TAG, "ADC setup complete.");
}

/**
 * @brief Configure PWM for motor speed control
 */
static void setup_pwm(void) {
    ESP_LOGI(TAG, "Setting up PWM for motor speed control...");

    // Configure timer
    ledc_timer_config_t ledc_timer = {
        .speed_mode = LEDC_HIGH_SPEED_MODE,
        .duty_resolution = PWM_RESOLUTION,
        .timer_num = LEDC_TIMER_0,
        .freq_hz = PWM_FREQUENCY,
        .clk_cfg = LEDC_AUTO_CLK
    };
    ledc_timer_config(&ledc_timer);

    // Configure Azimuth PWM channel
    ledc_channel_config_t azimuth_pwm = {
        .gpio_num = AZIMUTH_MOTOR_PWM_PIN,
        .speed_mode = LEDC_HIGH_SPEED_MODE,
        .channel = AZIMUTH_PWM_CHANNEL,
        .intr_type = LEDC_INTR_DISABLE,
        .timer_sel = LEDC_TIMER_0,
        .duty = 0,
        .hpoint = 0
    };
    ledc_channel_config(&azimuth_pwm);

    // Configure Tilt PWM channel
    ledc_channel_config_t tilt_pwm = {
        .gpio_num = TILT_MOTOR_PWM_PIN,
        .speed_mode = LEDC_HIGH_SPEED_MODE,
        .channel = TILT_PWM_CHANNEL,
        .intr_type = LEDC_INTR_DISABLE,
        .timer_sel = LEDC_TIMER_0,
        .duty = 0,
        .hpoint = 0
    };
    ledc_channel_config(&tilt_pwm);

    ESP_LOGI(TAG, "PWM setup complete.");
}

/**
 * @brief Control the Azimuth motor direction and speed.
 * @param direction 1 for positive rotation, -1 for negative, 0 to stop.
 * @param speed Speed value from 0 (stopped) to 1023 (full speed).
 */
static void move_azimuth_motor(int direction, int speed) {
    // Constrain speed
    if (speed < 0) speed = 0;
    if (speed > 1023) speed = 1023;

    // Set PWM duty cycle
    ledc_set_duty(LEDC_HIGH_SPEED_MODE, AZIMUTH_PWM_CHANNEL, speed);
    ledc_update_duty(LEDC_HIGH_SPEED_MODE, AZIMUTH_PWM_CHANNEL);
    g_azimuth_pwm_duty = speed;

    if (direction > 0) { // Move clockwise
        gpio_set_level(AZIMUTH_MOTOR_PIN_A, 1);
        gpio_set_level(AZIMUTH_MOTOR_PIN_B, 0);
        g_azimuth_motor_active = (speed > 0);
    } else if (direction < 0) { // Move counter-clockwise
        gpio_set_level(AZIMUTH_MOTOR_PIN_A, 0);
        gpio_set_level(AZIMUTH_MOTOR_PIN_B, 1);
        g_azimuth_motor_active = (speed > 0);
    } else { // Stop
        gpio_set_level(AZIMUTH_MOTOR_PIN_A, 0);
        gpio_set_level(AZIMUTH_MOTOR_PIN_B, 0);
        g_azimuth_motor_active = false;
    }

    // Control enable pin
    gpio_set_level(AZIMUTH_MOTOR_EN_PIN, (speed > 0) ? 1 : 0);
}

/**
 * @brief Control the Tilt motor direction and speed.
 * @param direction 1 for positive rotation, -1 for negative, 0 to stop.
 * @param speed Speed value from 0 (stopped) to 1023 (full speed).
 */
static void move_tilt_motor(int direction, int speed) {
    // Constrain speed
    if (speed < 0) speed = 0;
    if (speed > 1023) speed = 1023;

    // Set PWM duty cycle
    ledc_set_duty(LEDC_HIGH_SPEED_MODE, TILT_PWM_CHANNEL, speed);
    ledc_update_duty(LEDC_HIGH_SPEED_MODE, TILT_PWM_CHANNEL);
    g_tilt_pwm_duty = speed;

    if (direction > 0) { // Move up
        gpio_set_level(TILT_MOTOR_PIN_A, 1);
        gpio_set_level(TILT_MOTOR_PIN_B, 0);
        g_tilt_motor_active = (speed > 0);
    } else if (direction < 0) { // Move down
        gpio_set_level(TILT_MOTOR_PIN_A, 0);
        gpio_set_level(TILT_MOTOR_PIN_B, 1);
        g_tilt_motor_active = (speed > 0);
    } else { // Stop
        gpio_set_level(TILT_MOTOR_PIN_A, 0);
        gpio_set_level(TILT_MOTOR_PIN_B, 0);
        g_tilt_motor_active = false;
    }

    // Control enable pin
    gpio_set_level(TILT_MOTOR_EN_PIN, (speed > 0) ? 1 : 0);
}

/**
 * @brief Apply emergency brake to azimuth motor
 */
static void emergency_brake_azimuth(void) {
    // Stop motor
    move_azimuth_motor(0, 0);

    // Activate brake
    gpio_set_level(AZIMUTH_BRAKE_PIN, 0); // Assuming active low

    // Log the event
    ESP_LOGW(TAG, "Emergency brake activated for azimuth motor!");
    snprintf(g_last_error, sizeof(g_last_error), "Azimuth motor overload detected");

    g_emergency_brake_active = true;
}

/**
 * @brief Apply emergency brake to tilt motor
 */
static void emergency_brake_tilt(void) {
    // Stop motor
    move_tilt_motor(0, 0);

    // Activate brake
    gpio_set_level(TILT_BRAKE_PIN, 0); // Assuming active low

    // Log the event
    ESP_LOGW(TAG, "Emergency brake activated for tilt motor!");
    snprintf(g_last_error, sizeof(g_last_error), "Tilt motor overload detected");

    g_emergency_brake_active = true;
}

/**
 * @brief Release emergency brake for azimuth motor
 */
static void release_brake_azimuth(void) {
    gpio_set_level(AZIMUTH_BRAKE_PIN, 1); // Assuming active low

    // Update brake status (only if tilt brake is also released)
    if (gpio_get_level(TILT_BRAKE_PIN) == 1) {
        g_emergency_brake_active = false;
    }

    ESP_LOGI(TAG, "Azimuth brake released");
}

/**
 * @brief Release emergency brake for tilt motor
 */
static void release_brake_tilt(void) {
    gpio_set_level(TILT_BRAKE_PIN, 1); // Assuming active low

    // Update brake status (only if azimuth brake is also released)
    if (gpio_get_level(AZIMUTH_BRAKE_PIN) == 1) {
        g_emergency_brake_active = false;
    }

    ESP_LOGI(TAG, "Tilt brake released");
}

/**
 * @brief Reads the current azimuth angle from the position sensor.
 * @return The current azimuth angle in degrees.
 */
static float read_current_azimuth(void) {
    // Read ADC value
    uint32_t adc_reading = adc1_get_raw(AZIMUTH_FEEDBACK_PIN);

    // Get voltage using characterized values (more accurate)
    uint32_t voltage = esp_adc_cal_raw_to_voltage(adc_reading, &g_adc_chars);

    // Map ADC value to angle range
    float angle = AZIMUTH_MIN_ANGLE + (AZIMUTH_MAX_ANGLE - AZIMUTH_MIN_ANGLE) *
                  (adc_reading - AZIMUTH_MIN_ADC) / (float)(AZIMUTH_MAX_ADC - AZIMUTH_MIN_ADC);

    // Constrain to valid range
    if (angle < AZIMUTH_MIN_ANGLE) angle = AZIMUTH_MIN_ANGLE;
    if (angle > AZIMUTH_MAX_ANGLE) angle = AZIMUTH_MAX_ANGLE;

    return angle;
}

/**
 * @brief Reads the current tilt angle from the position sensor.
 * @return The current tilt angle in degrees.
 */
static float read_current_tilt(void) {
    // Read ADC value
    uint32_t adc_reading = adc1_get_raw(TILT_FEEDBACK_PIN);

    // Get voltage using characterized values (more accurate)
    uint32_t voltage = esp_adc_cal_raw_to_voltage(adc_reading, &g_adc_chars);

    // Map ADC value to angle range
    float angle = TILT_MIN_ANGLE + (TILT_MAX_ANGLE - TILT_MIN_ANGLE) *
                  (adc_reading - TILT_MIN_ADC) / (float)(TILT_MAX_ADC - TILT_MIN_ADC);

    // Constrain to valid range
    if (angle < TILT_MIN_ANGLE) angle = TILT_MIN_ANGLE;
    if (angle > TILT_MAX_ANGLE) angle = TILT_MAX_ANGLE;

    return angle;
}

/**
 * @brief Read motor current from current sensor
 * @param channel ADC channel connected to current sensor
 * @return Current in amps
 */
static float read_motor_current(adc1_channel_t channel) {
    // Read ADC value
    uint32_t adc_reading = adc1_get_raw(channel);

    // Get voltage using characterized values
    uint32_t voltage_mv = esp_adc_cal_raw_to_voltage(adc_reading, &g_adc_chars);

    // Convert to current (this depends on your current sensor's characteristics)
    // Example: For ACS712 30A sensor, sensitivity is ~66mV/A
    float current = (voltage_mv - 2500) / 66.0f; // 2500mV is the zero-current voltage for example

    return fabs(current); // Return absolute value
}

/**
 * @brief Read power output from power sensor
 * @return Power in watts
 */
static float read_power_output(void) {
    // Read ADC value
    uint32_t adc_reading = adc1_get_raw(POWER_SENSOR_PIN);

    // Get voltage using characterized values
    uint32_t voltage_mv = esp_adc_cal_raw_to_voltage(adc_reading, &g_adc_chars);

    // Convert to power (this depends on your power sensor's characteristics)
    // Example: Simple linear mapping
    float power = voltage_mv * 0.1f; // Example scaling factor

    return power;
}

/**
 * @brief Read panel temperature from temperature sensor
 * @return Temperature in Celsius
 */
static float read_panel_temperature(void) {
    // Read ADC value
    uint32_t adc_reading = adc1_get_raw(TEMP_SENSOR_PIN);

    // Get voltage using characterized values
    uint32_t voltage_mv = esp_adc_cal_raw_to_voltage(adc_reading, &g_adc_chars);

    // Convert to temperature (this depends on your temp sensor's characteristics)
    // Example: For LM35, 10mV/°C
    float temperature = voltage_mv / 10.0f;

    return temperature;
}

/**
 * @brief Set system uptime (called periodically)
 */
static void update_uptime(void) {
    g_uptime_seconds = esp_timer_get_time() / 1000000;
}

/**
 * @brief Sets the target azimuth and tilt angles safely.
 * @param new_azimuth Target azimuth angle in degrees.
 * @param new_tilt Target tilt angle in degrees.
 */
void set_target_angles(float new_azimuth, float new_tilt) {
    // Constrain angles to valid ranges
    if (new_azimuth < AZIMUTH_MIN_ANGLE) new_azimuth = AZIMUTH_MIN_ANGLE;
    if (new_azimuth > AZIMUTH_MAX_ANGLE) new_azimuth = AZIMUTH_MAX_ANGLE;
    if (new_tilt < TILT_MIN_ANGLE) new_tilt = TILT_MIN_ANGLE;
    if (new_tilt > TILT_MAX_ANGLE) new_tilt = TILT_MAX_ANGLE;

    if (xSemaphoreTake(g_angle_mutex, portMAX_DELAY) == pdTRUE) {
        g_target_azimuth = new_azimuth;
        g_target_tilt = new_tilt;
        ESP_LOGI(TAG, "New target angles set: Azimuth=%.2f, Tilt=%.2f", g_target_azimuth, g_target_tilt);
        xSemaphoreGive(g_angle_mutex);

        // Send immediate status update when targets change
        send_status_update();
    }
}

/**
 * @brief Periodic timer callback to send status updates to master
 */
static void status_timer_callback(TimerHandle_t xTimer) {
    send_status_update();
}

/**
 * @brief Send current tracker status to master system
 */
static void send_status_update(void) {
    // Only send if Ethernet is connected
    if (!ethernet_is_connected()) {
        ESP_LOGD(TAG, "Ethernet not connected, skipping status update");
        return;
    }

    // Update the uptime
    update_uptime();

    // Create status structure
    tracker_status_t status = {
        .current_azimuth = g_current_azimuth,
        .current_tilt = g_current_tilt,
        .target_azimuth = g_target_azimuth,
        .target_tilt = g_target_tilt,
        .azimuth_motor_active = g_azimuth_motor_active,
        .tilt_motor_active = g_tilt_motor_active,
        .emergency_brake_active = g_emergency_brake_active,
        .motor_load_azimuth = g_motor_load_azimuth,
        .motor_load_tilt = g_motor_load_tilt,
        .power_output = g_power_output,
        .panel_temperature = g_panel_temperature,
        .uptime = g_uptime_seconds
    };

    // Copy last error
    strncpy(status.last_error, g_last_error, sizeof(status.last_error));

    // Send status to master
    esp_err_t result = send_status_to_master(&status);
    if (result != ESP_OK) {
        ESP_LOGW(TAG, "Failed to send status update to master");
    } else {
        ESP_LOGD(TAG, "Status update sent successfully");
    }
}

/**
 * @brief FreeRTOS task to continuously control motors to reach target angles.
 */
static void motor_control_task(void *pvParameters) {
    ESP_LOGI(TAG, "Motor control task started.");

    float local_target_azimuth;
    float local_target_tilt;
    float azimuth_current, tilt_current;

    // Previous duty cycles for smooth ramping
    int prev_azimuth_duty = 0;
    int prev_tilt_duty = 0;

    while (1) {
        // --- Read Current State ---
        // Read current angles from sensors
        g_current_azimuth = read_current_azimuth();
        g_current_tilt = read_current_tilt();

        // Read motor currents
        azimuth_current = read_motor_current(AZIMUTH_CURRENT_SENSE_PIN);
        tilt_current = read_motor_current(TILT_CURRENT_SENSE_PIN);

        // Update load percentages
        g_motor_load_azimuth = (azimuth_current / MAX_CURRENT_AZIMUTH) * 100.0f;
        g_motor_load_tilt = (tilt_current / MAX_CURRENT_TILT) * 100.0f;

        // Read other sensors
        g_power_output = read_power_output();
        g_panel_temperature = read_panel_temperature();

        // Check for overload conditions
        if (azimuth_current > MAX_CURRENT_AZIMUTH && !g_emergency_brake_active) {
            emergency_brake_azimuth();
        }

        if (tilt_current > MAX_CURRENT_TILT && !g_emergency_brake_active) {
            emergency_brake_tilt();
        }

        // Skip control logic if emergency brake is active
        if (g_emergency_brake_active) {
            vTaskDelay(pdMS_TO_TICKS(MOTOR_CONTROL_LOOP_DELAY_MS));
            continue;
        }

        // Safely get the target angles
        if (xSemaphoreTake(g_angle_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            local_target_azimuth = g_target_azimuth;
            local_target_tilt = g_target_tilt;
            xSemaphoreGive(g_angle_mutex);
        } else {
            ESP_LOGW(TAG, "Could not get angle mutex in control loop.");
            vTaskDelay(pdMS_TO_TICKS(MOTOR_CONTROL_LOOP_DELAY_MS));
            continue;
        }

        // --- Control Logic ---
        // Azimuth Control
        float azimuth_error = local_target_azimuth - g_current_azimuth;

        // Handle angle wrapping for azimuth (e.g., 359° to 1°)
        if (azimuth_error > 180.0f) {
            azimuth_error -= 360.0f;
        } else if (azimuth_error < -180.0f) {
            azimuth_error += 360.0f;
        }

        int azimuth_direction = 0;
        int azimuth_speed = 0;

        if (fabs(azimuth_error) > ANGLE_TOLERANCE) {
            // Determine direction
            azimuth_direction = (azimuth_error > 0) ? 1 : -1;

            // Calculate base speed based on error magnitude
            float error_ratio = fabs(azimuth_error) / SLOW_ZONE_DEGREES;
            if (error_ratio > 1.0f) error_ratio = 1.0f;

            // Base speed: 30% to 100% depending on distance from target
            azimuth_speed = 307 + (int)(error_ratio * 716); // 307 is ~30%, 1023 is 100%

            // Ramp up/down for smooth operation
            if (azimuth_speed > prev_azimuth_duty) {
                // Ramp up gradually
                azimuth_speed = prev_azimuth_duty + RAMP_UP_INCREMENT;
                if (azimuth_speed > 1023) azimuth_speed = 1023;
            } else if (azimuth_speed < prev_azimuth_duty) {
// Ramp down gradually
                azimuth_speed = prev_azimuth_duty - RAMP_DOWN_INCREMENT;
                if (azimuth_speed < 0) azimuth_speed = 0;
            }
        }

        // Save current duty for next iteration
        prev_azimuth_duty = azimuth_speed;

        // Tilt Control
        float tilt_error = local_target_tilt - g_current_tilt;
        int tilt_direction = 0;
        int tilt_speed = 0;

        if (fabs(tilt_error) > ANGLE_TOLERANCE) {
            // Determine direction
            tilt_direction = (tilt_error > 0) ? 1 : -1;

            // Calculate base speed based on error magnitude
            float error_ratio = fabs(tilt_error) / SLOW_ZONE_DEGREES;
            if (error_ratio > 1.0f) error_ratio = 1.0f;

            // Base speed: 30% to 100% depending on distance from target
            tilt_speed = 307 + (int)(error_ratio * 716); // 307 is ~30%, 1023 is 100%

            // Ramp up/down for smooth operation
            if (tilt_speed > prev_tilt_duty) {
                // Ramp up gradually
                tilt_speed = prev_tilt_duty + RAMP_UP_INCREMENT;
                if (tilt_speed > 1023) tilt_speed = 1023;
            } else if (tilt_speed < prev_tilt_duty) {
                // Ramp down gradually
                tilt_speed = prev_tilt_duty - RAMP_DOWN_INCREMENT;
                if (tilt_speed < 0) tilt_speed = 0;
            }
        }

        // Save current duty for next iteration
        prev_tilt_duty = tilt_speed;

        // Apply control signals to motors
        move_azimuth_motor(azimuth_direction, azimuth_speed);
        move_tilt_motor(tilt_direction, tilt_speed);

        // Log status periodically (every ~5 seconds)
        static int log_counter = 0;
        if (++log_counter >= 100) {
            ESP_LOGI(TAG, "Current: Az=%.2f°, Tilt=%.2f° | Target: Az=%.2f°, Tilt=%.2f° | Load: Az=%.1f%%, Tilt=%.1f%%",
                     g_current_azimuth, g_current_tilt, local_target_azimuth, local_target_tilt,
                     g_motor_load_azimuth, g_motor_load_tilt);
            log_counter = 0;
        }

        // Short delay for next control cycle
        vTaskDelay(pdMS_TO_TICKS(MOTOR_CONTROL_LOOP_DELAY_MS));
    }
}

/**
 * @brief Reset emergency brake state
 * @return True if brake was successfully reset
 */
bool reset_emergency_brake(void) {
    // Only attempt reset if brake is active
    if (!g_emergency_brake_active) {
        ESP_LOGI(TAG, "Emergency brake is not active, no need to reset");
        return true;
    }

    // Check if current is below threshold before resetting
    float azimuth_current = read_motor_current(AZIMUTH_CURRENT_SENSE_PIN);
    float tilt_current = read_motor_current(TILT_CURRENT_SENSE_PIN);

    if (azimuth_current >= MAX_CURRENT_AZIMUTH || tilt_current >= MAX_CURRENT_TILT) {
        ESP_LOGW(TAG, "Cannot reset emergency brake - current still too high");
        snprintf(g_last_error, sizeof(g_last_error), "Reset denied - motor current still high");
        return false;
    }

    // Release brakes
    release_brake_azimuth();
    release_brake_tilt();

    // Clear error message
    snprintf(g_last_error, sizeof(g_last_error), "None");

    ESP_LOGI(TAG, "Emergency brake reset successfully");
    return true;
}

/**
 * @brief Stop all motors immediately
 */
void emergency_stop(void) {
    // Stop both motors
    move_azimuth_motor(0, 0);
    move_tilt_motor(0, 0);

    // Activate brakes
    emergency_brake_azimuth();
    emergency_brake_tilt();

    // Update status
    snprintf(g_last_error, sizeof(g_last_error), "Emergency stop activated");
    ESP_LOGW(TAG, "Emergency stop activated!");

    // Send immediate status update
    send_status_update();
}

/**
 * @brief Get current status of tracker for external use
 * @param status Pointer to status structure to fill
 * @return ESP_OK if successful
 */
esp_err_t get_tracker_status(tracker_status_t *status) {
    if (status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Fill status structure
    status->current_azimuth = g_current_azimuth;
    status->current_tilt = g_current_tilt;
    status->target_azimuth = g_target_azimuth;
    status->target_tilt = g_target_tilt;
    status->azimuth_motor_active = g_azimuth_motor_active;
    status->tilt_motor_active = g_tilt_motor_active;
    status->emergency_brake_active = g_emergency_brake_active;
    status->motor_load_azimuth = g_motor_load_azimuth;
    status->motor_load_tilt = g_motor_load_tilt;
    status->power_output = g_power_output;
    status->panel_temperature = g_panel_temperature;
    status->uptime = g_uptime_seconds;
    strncpy(status->last_error, g_last_error, sizeof(status->last_error));

    return ESP_OK;
}

/**
 * @brief Initialize motor control module
 * @return ESP_OK if successful
 */
esp_err_t motor_control_init(void) {
    ESP_LOGI(TAG, "Initializing motor control module...");

    // Setup hardware
    setup_motors();
    setup_adc();

    // Create mutex for thread-safe angle updates
    g_angle_mutex = xSemaphoreCreateMutex();
    if (g_angle_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return ESP_FAIL;
    }

    // Create timer for periodic status updates
    g_status_timer = xTimerCreate(
        "status_timer",
        pdMS_TO_TICKS(STATUS_UPDATE_INTERVAL_MS),
        pdTRUE,  // Auto-reload
        NULL,    // Timer ID
        status_timer_callback
    );

    if (g_status_timer == NULL) {
        ESP_LOGE(TAG, "Failed to create status timer");
        vSemaphoreDelete(g_angle_mutex);
        return ESP_FAIL;
    }

    // Start status timer
    if (xTimerStart(g_status_timer, 0) != pdPASS) {
        ESP_LOGE(TAG, "Failed to start status timer");
        vTimerDelete(g_status_timer);
        vSemaphoreDelete(g_angle_mutex);
        return ESP_FAIL;
    }

    // Create motor control task
    BaseType_t task_created = xTaskCreate(
        motor_control_task,
        "motor_control",
        MOTOR_CONTROL_TASK_STACK_SIZE,
        NULL,
        MOTOR_CONTROL_TASK_PRIORITY,
        NULL
    );

    if (task_created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create motor control task");
        xTimerStop(g_status_timer, 0);
        vTimerDelete(g_status_timer);
        vSemaphoreDelete(g_angle_mutex);
        return ESP_FAIL;
    }

    // Set initial values to safe defaults
    g_target_azimuth = g_current_azimuth = 0.0f;
    g_target_tilt = g_current_tilt = 0.0f;

    // Reset error state
    snprintf(g_last_error, sizeof(g_last_error), "None");

    ESP_LOGI(TAG, "Motor control module initialized successfully");
    return ESP_OK;
}

/**
 * @brief Deinitialize motor control module
 */
void motor_control_deinit(void) {
    // Stop motors
    move_azimuth_motor(0, 0);
    move_tilt_motor(0, 0);

    // Release brakes
    release_brake_azimuth();
    release_brake_tilt();

    // Stop timer
    if (g_status_timer != NULL) {
        xTimerStop(g_status_timer, 0);
        vTimerDelete(g_status_timer);
    }

    // Delete mutex
    if (g_angle_mutex != NULL) {
        vSemaphoreDelete(g_angle_mutex);
    }

    ESP_LOGI(TAG, "Motor control module deinitialized");
}

/**
 * @brief Process command received from master system
 * @param command JSON command object
 * @return ESP_OK if command was processed successfully
 */
esp_err_t process_motor_command(const cJSON *command) {
    if (command == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Get command type
    cJSON *cmd_type = cJSON_GetObjectItem(command, "cmd");
    if (!cJSON_IsString(cmd_type)) {
        ESP_LOGW(TAG, "Invalid command format - missing 'cmd' field");
        return ESP_ERR_INVALID_ARG;
    }

    const char *cmd_str = cmd_type->valuestring;

    if (strcmp(cmd_str, "set_position") == 0) {
        // Handle position setting command
        cJSON *azimuth = cJSON_GetObjectItem(command, "azimuth");
        cJSON *tilt = cJSON_GetObjectItem(command, "tilt");

        if (!cJSON_IsNumber(azimuth) || !cJSON_IsNumber(tilt)) {
            ESP_LOGW(TAG, "Invalid set_position command - missing angle values");
            return ESP_ERR_INVALID_ARG;
        }

        // Set new target angles
        set_target_angles((float)azimuth->valuedouble, (float)tilt->valuedouble);

        remote_log("New position command received: Az=%.2f, Tilt=%.2f",
                  (float)azimuth->valuedouble, (float)tilt->valuedouble);

        return ESP_OK;
    }
    else if (strcmp(cmd_str, "emergency_stop") == 0) {
        // Handle emergency stop command
        emergency_stop();
        remote_log("Emergency stop command received from master");
        return ESP_OK;
    }
    else if (strcmp(cmd_str, "reset_brake") == 0) {
        // Handle brake reset command
        bool result = reset_emergency_brake();
        remote_log("Brake reset command received, result: %s", result ? "success" : "failed");
        return result ? ESP_OK : ESP_FAIL;
    }
    else if (strcmp(cmd_str, "request_status") == 0) {
        // Handle status request
        send_status_update();
        return ESP_OK;
    }
    else {
        ESP_LOGW(TAG, "Unknown command: %s", cmd_str);
        return ESP_ERR_NOT_SUPPORTED;
    }
}