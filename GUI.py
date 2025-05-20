import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pickle
from PIL import Image
import joblib
import folium
from streamlit_folium import st_folium


# Page config et styles
st.set_page_config(page_title="β Predict - Solar Optimizer", page_icon="☀️", layout="wide")

st.markdown("""
<style>
   .main { background: linear-gradient(135deg, #e6f7ff 0%, #ffffff 100%); }
   .welcome-text { font-size: 2.8em; text-align: center; margin: 20px 0; color: #1a5f7a; }
   .greek-beta { font-family: 'Symbol', serif; font-size: 1.2em; }
   .info-box {
       background: white;
       padding: 25px;
       border-radius: 15px;
       box-shadow: 0 4px 15px rgba(0,0,0,0.1);
       margin: 20px 0;
   }
   .metric-card {
       background: white;
       padding: 15px;
       border-radius: 10px;
       box-shadow: 0 2px 8px rgba(0,0,0,0.1);
       text-align: center;
   }
   .footer {
       background: linear-gradient(90deg, rgba(26,95,122,0.1) 0%, rgba(76,175,80,0.1) 100%);
       padding: 30px;
       border-radius: 15px;
       margin-top: 40px;
       text-align: center;
   }
   .contact-button {
       background: linear-gradient(135deg, #1a5f7a 0%, #4CAF50 100%);
       color: white;
       padding: 12px 25px;
       border-radius: 25px;
       text-decoration: none;
       display: inline-block;
       margin-top: 15px;
       transition: transform 0.3s;
   }
   .contact-button:hover {
       transform: translateY(-2px);
   }
   .chart-container {
       background: white;
       border-radius: 15px;
       padding: 20px;
       margin: 20px 0;
       box-shadow: 0 4px 15px rgba(0,0,0,0.1);
   }
</style>
""", unsafe_allow_html=True)

# En-tête
header_col1, header_col2 = st.columns([1, 4])
with header_col1:
   try:
       st.image('innovx-ttp.png', width=300)
   except:
       st.write("Logo non trouvé")

with header_col2:
   st.markdown("<h1 class='welcome-text'>β Predict<br><span style='font-size:0.6em;'>Optimisation Intelligente des Panneaux Solaires</span></h1>", unsafe_allow_html=True)

# Section d'information
info_col1, info_col2 = st.columns([3, 2])
with info_col1:
   st.markdown("""
   <div class='info-box'>
       <h3>L'angle d'inclinaison β (Beta)</h3>
       <p style='font-size: 1.1em; line-height: 1.6;'>
       L'angle β représente l'inclinaison optimale des panneaux solaires par rapport à l'horizontale. 
       Cette inclinaison est un paramètre crucial qui détermine l'efficacité de la capture d'énergie solaire.
       Notre système d'intelligence artificielle calcule en temps réel l'angle optimal en prenant en compte :
       <ul>
           <li>La position du soleil (azimut et zénith)</li>
           <li>Les conditions météorologiques</li>
           <li>L'irradiance solaire (GHI, DNI, DHI)</li>
           <li>Les paramètres environnementaux</li>
       </ul>
       </p>
   </div>
   """, unsafe_allow_html=True)
with info_col2:
   st.image("angle_beta2.png", caption="Illustration de l'angle β")

@st.cache_resource
def load_model():
   return joblib.load(r'C:\Users\MSI\Documents\work\PFE\Programfiles\drive\rf_model.pkl')

def prepare_features(df):
   df = df.copy()
   return pd.DataFrame({
       'GHI': df['GHI'],
       'Year': df['Datetime'].dt.year,
       'Month': df['Month'],
       'Solar Azimuth': df['Solar Azimuth'],
       'Solar Zenith': df['Solar Zenith'],
       'Hour_sin': df['Hour_sin'],
       'Hour_cos': df['Hour_cos'],
       'Day_of_Year_sin': df['Day_of_Year_sin'],
       'Day_of_Year_cos': df['Day_of_Year_cos'],
       'DHI': df['DHI'],
       'DNI': df['DNI'],
       'Relative Humidity': df['Relative Humidity'],
       'Temperature': df['Temperature'],
       'Surface Albedo': df['Surface Albedo'],
       'Precipitable Water': df['Precipitable Water']
   })

def create_chart(df, date):
   daily = df[df['Datetime'].dt.date == date]
   
   fig = make_subplots(
       rows=3, cols=1,
       subplot_titles=(
           'Irradiance Solaire (W/m²)',
           'Position Solaire (degrés)',
           'Angle β Optimal (degrés)'
       ),
       specs=[[{"type": "xy"}], [{"type": "xy"}], [{"type": "xy"}]],
       vertical_spacing=0.12
   )
   
   # Courbes d'irradiance
   for param, color, name in [
       ('GHI', '#FFA500', 'Irradiance Globale'),
       ('DNI', '#FF4500', 'Irradiance Directe'),
       ('DHI', '#FFD700', 'Irradiance Diffuse')
   ]:
       fig.add_trace(go.Scatter(
           x=daily['Datetime'], 
           y=daily[param],
           name=name,
           line=dict(color=color, width=2)
       ), row=1, col=1)
   
   # Paramètres solaires
   fig.add_trace(go.Scatter(
       x=daily['Datetime'],
       y=daily['Solar Zenith'],
       name='Angle Zénithal',
       line=dict(color='#4682B4', width=2)
   ), row=2, col=1)
   fig.add_trace(go.Scatter(
       x=daily['Datetime'],
       y=daily['Solar Azimuth'],
       name='Angle Azimutal',
       line=dict(color='#20B2AA', width=2)
   ), row=2, col=1)
   
   # Beta optimal
   fig.add_trace(go.Scatter(
       x=daily['Datetime'],
       y=daily['Beta_Optimal'],
       name='Angle β Optimal',
       line=dict(color='#32CD32', width=3)
   ), row=3, col=1)
   
   fig.update_layout(
       height=1000,
       showlegend=True,
       template='seaborn',
       font=dict(size=12)
   )
   
   return fig

def main():
   try:
       # Carte de sélection de localisation
       st.markdown("### 📍 Sélection de la localisation")
       def create_map():
           m = folium.Map(location=[36.19, 5.41], zoom_start=4)
           folium.TileLayer('cartodbpositron').add_to(m)
           folium.CircleMarker(
               location=[32.25, -7.98],
               radius=8,
               popup='Setif',
               color='#1a5f7a',
               fill=True
           ).add_to(m)
           return m
           
       m = create_map()
       map_data = st_folium(m, height=400, width=None)
       
       if map_data["last_clicked"]:
           latitude = map_data["last_clicked"]["lat"]
           longitude = map_data["last_clicked"]["lng"]
           st.success(f"📍 Position sélectionnée: {latitude:.4f}°N, {longitude:.4f}°E")
       
       # Chargement et préparation des données
       df = pd.read_excel('forecasts (1).xlsx')
       df['Datetime'] = pd.to_datetime(df['Datetime'])
       features = prepare_features(df)
       model = load_model()
       df['Beta_Optimal'] = model.predict(features)
       
       # Sélection de la période
       st.markdown("### 📅 Sélection de la période d'analyse")
       dates = pd.to_datetime(df['Datetime']).dt.date.unique()
       selected = st.date_input("", 
           min_value=min(dates),
           max_value=max(dates),
           value=min(dates)
       )
       
       daily = df[pd.to_datetime(df['Datetime']).dt.date == selected]
       
       # Métriques clés
       st.markdown("### 📊 Indicateurs clés de performance")
       cols = st.columns(6)
       metrics = {
           "☀️ GHI": (daily['GHI'].max(), daily['GHI'].mean(), "W/m²"),
           "🌞 DNI": (daily['DNI'].max(), daily['DNI'].mean(), "W/m²"),
           "🌡️ Temp.": (daily['Temperature'].max(), daily['Temperature'].mean(), "°C"),
           "☁️ Albedo": (daily['Surface Albedo'].mean(), daily['Surface Albedo'].std(), ""),
           "🧭 Azimuth": (daily['Solar Azimuth'].mean(), daily['Solar Azimuth'].std(), "°"),
           "📐 Beta": (daily['Beta_Optimal'].mean(), daily['Beta_Optimal'].std(), "°")
       }
       
       for col, (name, (val, delta, unit)) in zip(cols, metrics.items()):
           with col:
               st.metric(name, f"{val:.1f}{unit}", f"{delta:.1f}{unit}")
       
       # Visualisations
       st.markdown("### 📈 Analyse graphique")
       st.plotly_chart(create_chart(df, selected), use_container_width=True)
       
       # Données détaillées
       st.markdown("### 📋 Données détaillées")
       st.dataframe(
           daily[['Datetime', 'GHI', 'DNI', 'DHI', 'Temperature', 'Beta_Optimal']]
           .sort_values('Datetime'),
           use_container_width=True
       )

   except Exception as e:
       st.error(f"❌ Erreur: {str(e)}")
       st.write("Détails:", e)

   # Footer
   st.markdown("""
   <div class='footer'>
       <h3>Développé par Jaafar SELLAKH</h3>
       <p>Data Engineering Student</p>
       <a href='mailto:jaafar.sellakh@gmail.com' class='contact-button'>
           📧 Contact
       </a>
   </div>
   """, unsafe_allow_html=True)

if __name__ == "__main__":
   main()