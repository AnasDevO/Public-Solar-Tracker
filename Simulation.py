
import pvlib
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt



def cell_temperature(poa_global, temp_air, wind_speed):
    cell_temp = pvlib.temperature.pvsyst_cell(
        poa_global=poa_global,
        temp_air=temp_air,
        wind_speed=wind_speed,
        u_c=36,
        u_v=0
    )
    return cell_temp

def transposition(dni, ghi, dhi, datetime, lat, lon, altitude, environment_surface_type, surface_tilt, surface_azimuth, temp):
    # Get solar position using SPA algorithm
    solar_pos = pvlib.solarposition.spa_python(datetime, lat, lon, altitude)
    solar_zenith = solar_pos['zenith'].values[0]
    solar_azimuth = solar_pos['azimuth'].values[0]
    # Create a location object
    location = pvlib.location.Location(latitude, longitude, tz=tz, altitude=altitude)

    # Standard POA calculation at sun's position
    airmass = pvlib.atmosphere.get_relative_airmass(solar_zenith)

    # Begin method
    diffuse_array = pvlib.irradiance.perez_driesse(
        surface_tilt,
        surface_azimuth,
        dhi,
        dni,
        pvlib.irradiance.get_extra_radiation(datetime),
        solar_zenith,
        solar_azimuth,
        airmass,
        return_components=True
    )
    diffuse=diffuse_array['sky_diffuse'][0]
    ground_diffuse = pvlib.irradiance.get_ground_diffuse(
        surface_tilt,
        ghi,
        0.2,
        environment_surface_type
    )
    # Compute Angle of Incidence (AOI)
    aoi = pvlib.irradiance.aoi(surface_tilt, surface_azimuth, solar_zenith, solar_azimuth)

    # Compute direct irradiance using AOI
    direct_irradiance = dni * np.cos(np.radians(aoi))
    direct_irradiance = max(direct_irradiance, 0)

    total_irradiance = direct_irradiance + diffuse + ground_diffuse
    cell_temper= cell_temperature(total_irradiance, temp, 5)
    effetive_irradiance = total_irradiance* (1- (cell_temper-25)*0.0045)
    return total_irradiance, effetive_irradiance


def calculate_optimal_poa(dni, ghi, dhi, time, lat, lon, altitude=0, temp=25):
    solar_pos = pvlib.solarposition.spa_python(time, lat, lon, 470)
    zenith = solar_pos['zenith'].values[0]
    azimuth = solar_pos['azimuth'].values[0]

    poa_sun_value=transposition(
            dni, ghi, dhi, time, lat, lon, altitude, 'urban', zenith, azimuth, temp
        )

    # Finding the optimal tilt
    tilts = np.arange(0, 90, 1)  # tilt angles from 0 to 90 degrees
    azimuth_range = np.arange(azimuth-45, azimuth+45, 1)
    optimal_poa = 0
    optimal_tilt = 0
    optimal_azimuth=0
    optimal_temp = 250
    unfiltered_poa=0


    for tilt in tilts:
            for azimuth_selected in azimuth_range:
                angle_irradiance = transposition(
                    dni ,ghi ,dhi ,time, lat, lon, altitude, 'urban', tilt, azimuth_selected, temp
                )
                if angle_irradiance[1] > optimal_poa:
                    optimal_temp = cell_temperature(angle_irradiance[1], temp, 5)
                    optimal_poa = angle_irradiance[1]
                    unfiltered_poa=angle_irradiance[0]
                    optimal_azimuth = azimuth_selected
                    optimal_tilt = tilt

    # # Convert lists to arrays for easier manipulation
    # cell_temperatures = np.array(cell_temperatures).flatten()
    # effective_poa_values = np.array(effective_poa_values).flatten()
    #
    # tilt_angles = np.arange(0, 90, 1)
    # # Create the dual-axis plot
    # fig, ax1 = plt.subplots(figsize=(10, 6))
    #
    # # Plot cell temperature on the first y-axis
    # color1 = 'tab:red'
    # ax1.set_xlabel('Tilt Angle (degrees)')
    # ax1.set_ylabel('Cell Temperature (°C)', color=color1)
    # temperature_line = ax1.plot(tilt_angles, cell_temperatures, color=color1,
    #                             marker='o', linestyle='-', label='Cell Temperature')
    # ax1.tick_params(axis='y', labelcolor=color1)
    # ax1.set_ylim(20, 80)  # Adjust as needed
    #
    # # Create a second y-axis for effective POA
    # ax2 = ax1.twinx()
    # color2 = 'tab:blue'
    # ax2.set_ylabel('Effective POA (W/m²)', color=color2)
    # poa_line = ax2.plot(tilt_angles, effective_poa_values, color=color2,
    #                     marker='s', linestyle='--', label='Effective POA')
    # ax2.tick_params(axis='y', labelcolor=color2)
    #
    # # Create a combined legend
    # lines1, labels1 = ax1.get_legend_handles_labels()
    # lines2, labels2 = ax2.get_legend_handles_labels()
    # ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper center')
    #
    # plt.title('Cell Temperature and Effective POA vs. Tilt Angle')
    # plt.grid(True, alpha=0.3)
    # plt.tight_layout()
    #
    # # Show the plot
    # plt.show()
    # Print results
    print(f"Sun's Position - Zenith: {zenith:.2f}, Azimuth: {azimuth:.2f}")
    print(f"POA at Sun's Position: {poa_sun_value[1]:.2f} W/m^2")
    print(f"Optimal Tilt: {optimal_tilt}°")
    print(f"Optimal Azimuth: {optimal_azimuth}°")
    print(f"POA at Optimal Tilt: {optimal_poa:.2f} W/m^2")


# Example Usage
latitude = 32.239464
longitude = -7.958947
altitude = 470
tz = 'Africa/Casablanca'
dni = 0
ghi = 13
dhi = 125

# Create timestamp: localize to Africa/Casablanca then convert to UTC and wrap in a DatetimeIndex
time_local = pd.Timestamp("2025-01-24 10:00:00").tz_localize(tz)
time_utc = time_local.tz_convert("UTC")
time = pd.DatetimeIndex([time_local])
calculate_optimal_poa(dni,ghi,dhi,time, latitude, longitude, altitude, 20)