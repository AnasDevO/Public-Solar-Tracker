#ifndef MOTOR_CONTROL_H
#define MOTOR_CONTROL_H

#include <stdbool.h>
#include "esp_err.h"

/**
 * @brief Motor control configuration structure
 */
typedef struct {
    // Motor GPIO pins
    int motor_pin_a;         // Direction pin A
    int motor_pin_b;         // Direction pin B
    int pwm_pin;             // PWM control pin
    int enable_pin;          // Enable pin (optional)
    int brake_pin;           // Emergency brake pin
    int current_sense_pin;   // Current sensing pin (for overload detection)

    // Motor parameters
    int pwm_channel;         // LEDC channel to use for PWM
    int pwm_freq_hz;         // PWM frequency in Hz
    int pwm_resolution_bits; // PWM resolution in bits

    // Motor control parameters
    float acceleration;      // Acceleration rate (degrees/sec²)
    float max_speed;         // Maximum speed (degrees/sec)
    int min_duty;            // Minimum duty cycle (0-100%)
    int max_duty;            // Maximum duty cycle (0-100%)

    // Protection parameters
    float max_current;       // Maximum current in amps
    float current_threshold; // Current threshold for overload warning
    int overload_time_ms;    // Time in ms before triggering emergency brake

    // Feedback parameters
    int feedback_pin;        // ADC pin for position feedback
    float min_angle;         // Minimum angle (degrees)
    float max_angle;         // Maximum angle (degrees)
    int min_adc;             // ADC value at min angle
    int max_adc;             // ADC value at max angle
} motor_config_t;

/**
 * @brief Motor status information
 */
typedef struct {
    float current_position;  // Current position in degrees
    float target_position;   // Target position in degrees
    bool is_moving;          // Whether motor is currently moving
    float current_speed;     // Current speed in degrees/sec
    float load_percentage;   // Current load as percentage of max load
    bool overload_warning;   // Overload warning flag
    bool emergency_brake;    // Emergency brake status
    float motor_current;     // Motor current in amps
} motor_status_t;

/**
 * @brief Initialize a motor with the given configuration
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @param config Motor configuration structure
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_init(int motor_id, const motor_config_t *config);

/**
 * @brief Set the target position for a motor
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @param position Target position in degrees
 * @param speed Maximum speed for the movement (degrees/sec), 0 for default
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_set_position(int motor_id, float position, float speed);

/**
 * @brief Stop a motor smoothly
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_stop(int motor_id);

/**
 * @brief Engage emergency brake for a motor
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_emergency_brake(int motor_id);

/**
 * @brief Release emergency brake for a motor
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_release_brake(int motor_id);

/**
 * @brief Get the current status of a motor
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @param status Pointer to status structure to fill
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_get_status(int motor_id, motor_status_t *status);

/**
 * @brief Read current position from feedback sensor
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @return float Current position in degrees
 */
float motor_read_position(int motor_id);

/**
 * @brief Calibrate motor position feedback
 * Runs the motor to min and max positions and records ADC values
 *
 * @param motor_id Motor identifier (0 for azimuth, 1 for tilt)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_calibrate(int motor_id);

/**
 * @brief Start the motor control task
 * This function starts the task that handles motor control and monitoring
 *
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t motor_control_start();

/**
 * @brief Check if both motors have reached their target positions
 *
 * @return true if both motors have reached their targets, false otherwise
 */
bool motors_at_target_position();

#endif // MOTOR_CONTROL_H
