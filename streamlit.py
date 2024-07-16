import streamlit as st
from pymongo import MongoClient
import pandas as pd
import plotly.express as px

# Koneksi ke MongoDB
client = MongoClient('mongodb://localhost:27017/')  # Sesuaikan dengan URI MongoDB Anda
db = client['object_counter_db']  # Ganti dengan nama database Anda
predictions_collection = db['detections']  # Ganti dengan nama koleksi predictions Anda

# Fungsi untuk mengambil data dari MongoDB
def fetch_data():
    cursor = predictions_collection.find({})
    data = []
    for doc in cursor:
        doc.pop('_id', None)
        data.append(doc)
    return data

# Fungsi untuk memproses data
def process_data(data):
    df = pd.DataFrame(data)
    # Ubah kolom tanggal ke tipe datetime dengan penanganan kesalahan
    if 'date' in df.columns:
        try:
            df['date'] = pd.to_datetime(df['date'], format='%Y-%m-%d')
        except Exception as e:
            st.error(f"Kesalahan saat mengubah kolom 'date' ke tipe datetime: {e}")
    else:
        st.error("Kolom 'date' tidak ditemukan dalam data.")
    return df

def main():
    st.title('Data Hasil Deteksi')

    data = fetch_data()
    if data:
        df = process_data(data)

        # Tampilkan data sebagai tabel jika diinginkan
        if st.checkbox('Tampilkan Data'):
            st.table(df)

        # Grafik 1: Jumlah tiap kendaraan berdasarkan tempat (label dan location)
        st.header("Diagram")
        if 'kecamatan' in df.columns and 'date' in df.columns:
            count_by_kecamatan = df.groupby(['kecamatan', 'date']).size().reset_index(name='counts')

            # Membuat diagram pie dengan pengaturan lebih menarik
            fig1 = px.pie(
                count_by_kecamatan,
                names='kecamatan',
                values='counts',
                labels={'kecamatan': 'Tempat', 'counts': 'Jumlah'},
                color_discrete_sequence=px.colors.sequential.RdBu,
                hover_data=['counts']
            )

            # Menambahkan layout yang lebih menarik dan menyesuaikan posisi judul
            fig1.update_traces(
                textinfo='percent+label',
                pull=[0.1 for _ in range(len(count_by_kecamatan['kecamatan'].unique()))]  # Menarik semua segmen sedikit ke luar
            )

            fig1.update_layout(
                annotations=[dict(
                    text="Distribusi Jumlah Signal Berdasarkan Tempat",
                    x=0.5,  # Posisikan judul di tengah (x=0 untuk kiri, x=1 untuk kanan)
                    y=1.15,  # Mengatur posisi vertikal judul (y=1 adalah di atas plot, lebih tinggi untuk di atas plot)
                    font_size=24,
                    showarrow=False
                )],
                legend_title_text='Kecamatan',  # Judul untuk legenda
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5
                )  # Legenda di bawah grafik
            )

            # Menampilkan diagram di Streamlit
            st.plotly_chart(fig1)
        else:
            st.error("Kolom 'kecamatan' atau 'date' tidak ditemukan dalam data.")
        
        # Grafik 2: Jumlah deteksi per hari
        st.header("Jumlah Deteksi per Hari")
        if 'date' in df.columns:
            count_by_date = df['date'].value_counts().reset_index()
            count_by_date.columns = ['date', 'counts']
            count_by_date = count_by_date.sort_values('date')

            fig2 = px.bar(
                count_by_date,
                x='date',
                y='counts',
                labels={'date': 'Tanggal', 'counts': 'Jumlah'},
                title='Jumlah Deteksi per Hari'
            )

            # Menampilkan grafik di Streamlit
            st.plotly_chart(fig2)
        else:
            st.error("Kolom 'date' tidak ditemukan dalam data.")

        # Grafik 3: Deteksi terbanyak dan terendah per hari
        st.header("Deteksi Terbanyak dan Terendah per Hari")
        if 'date' in df.columns:
            max_detection = count_by_date[count_by_date['counts'] == count_by_date['counts'].max()]
            min_detection = count_by_date[count_by_date['counts'] == count_by_date['counts'].min()]

            max_min_df = pd.concat([max_detection, min_detection])

            fig3 = px.bar(
                max_min_df,
                x='date',
                y='counts',
                labels={'date': 'Tanggal', 'counts': 'Jumlah'},
                title='Deteksi Terbanyak dan Terendah per Hari',
                color='counts',
                color_continuous_scale=px.colors.sequential.RdBu
            )

            # Menampilkan grafik di Streamlit
            st.plotly_chart(fig3)
        else:
            st.error("Kolom 'date' tidak ditemukan dalam data.")

        # Grafik 4: Kecamatan dengan deteksi terbanyak dan terendah
        st.header("Kecamatan dengan Deteksi Terbanyak dan Terendah")
        if 'kecamatan' in df.columns:
            count_by_kecamatan_total = df['kecamatan'].value_counts().reset_index()
            count_by_kecamatan_total.columns = ['kecamatan', 'counts']

            max_kecamatan = count_by_kecamatan_total[count_by_kecamatan_total['counts'] == count_by_kecamatan_total['counts'].max()]
            min_kecamatan = count_by_kecamatan_total[count_by_kecamatan_total['counts'] == count_by_kecamatan_total['counts'].min()]

            max_min_kecamatan_df = pd.concat([max_kecamatan, min_kecamatan])

            fig4 = px.bar(
                max_min_kecamatan_df,
                x='kecamatan',
                y='counts',
                labels={'kecamatan': 'Kecamatan', 'counts': 'Jumlah'},
                title='Kecamatan dengan Deteksi Terbanyak dan Terendah',
                color='counts',
                color_continuous_scale=px.colors.sequential.RdBu
            )

            # Menampilkan grafik di Streamlit
            st.plotly_chart(fig4)
        else:
            st.error("Kolom 'kecamatan' tidak ditemukan dalam data.")
    else:
        st.write("Tidak ada data yang tersedia.")

if __name__ == '__main__':
    main()
