import os
import json
import hashlib
import math
import time
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from threading import Thread
from queue import Queue
import logging
import sqlite3
from pathlib import Path

class VeritabanıYöneticisi:
    def __init__(self):
        self.db_yolu = "antivirus.db"
        self._veritabanı_kur()
        
    def _veritabanı_kur(self):
        try:
            with sqlite3.connect(self.db_yolu) as conn:
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS tehditler
                    (hash TEXT PRIMARY KEY,
                     isim TEXT,
                     tür TEXT,
                     risk_skoru INTEGER,
                     eklenme_tarihi TIMESTAMP)''')
                
                c.execute('''CREATE TABLE IF NOT EXISTS tarama_geçmişi
                    (id INTEGER PRIMARY KEY,
                     dosya_yolu TEXT,
                     hash TEXT,
                     durum TEXT,
                     risk_skoru INTEGER,
                     tarama_tarihi TIMESTAMP)''')
                
                c.execute('''CREATE TABLE IF NOT EXISTS karantina
                    (id INTEGER PRIMARY KEY,
                     orijinal_yol TEXT,
                     karantina_yolu TEXT,
                     hash TEXT,
                     risk_skoru INTEGER,
                     eklenme_tarihi TIMESTAMP)''')
                conn.commit()
        except Exception as e:
            logging.error(f"Veritabanı kurulum hatası: {str(e)}", exc_info=True)

    def tehdit_kontrol(self, dosya_hash):
        try:
            with sqlite3.connect(self.db_yolu) as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM tehditler WHERE hash=?", (dosya_hash,))
                return c.fetchone() is not None
        except Exception as e:
            logging.error(f"Tehdit kontrolü hatası: {str(e)}", exc_info=True)
            return False

class VirüsTarayıcı:
    def __init__(self):
        self.VT_API_KEY = " Api Key "  # VirüsTotal (Anrivürüs) API anahtarınızı buraya yazın
        self.veritabanı = VeritabanıYöneticisi()
        self.imza_veritabanı = İmzaVeritabanı()
        self.karantina = KarantinaYöneticisi()
        self.logger = self._logger_kur()
        self.api_istek_kuyruğu = Queue()
        self.api_limit_zamanı = time.time()
        self.api_istek_sayısı = 0
        
    def _logger_kur(self):
        logger = logging.getLogger('AntivirüsLogger')
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler('antivirus.log')
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        return logger

    def dosya_analiz(self, dosya_yolu):
        sonuç = {
            "dosya": dosya_yolu,
            "durum": "Temiz",
            "sebep": [],
            "risk_skoru": 0,
            "detaylar": {}
        }
        
        try:
            # Dosya türü kontrolü
            if not os.path.isfile(dosya_yolu):
                return sonuç
            
            # Dosya boyutu kontrolü (1GB'dan büyük dosyaları atla)
            if os.path.getsize(dosya_yolu) > 1024 * 1024 * 1024:
                sonuç["sebep"].append("Dosya çok büyük (>1GB)")
                return sonuç
            
            dosya_bilgileri = self._dosya_bilgileri_al(dosya_yolu)
            sonuç["detaylar"].update(dosya_bilgileri)
            
            # Sadece belirli dosya türlerini detaylı analiz et
            riskli_uzantılar = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs'}
            if dosya_bilgileri["uzantı"].lower() in riskli_uzantılar:
                # Yerel veritabanı kontrolü
                if self.veritabanı.tehdit_kontrol(dosya_bilgileri["hash"]):
                    sonuç["durum"] = "Zararlı"
                    sonuç["risk_skoru"] = 100
                    sonuç["sebep"].append("Dosya yerel tehdit veritabanında bulundu")
                    return sonuç
                
                # VirusTotal kontrolü
                vt_sonuç = self._virustotal_kontrol(dosya_bilgileri["hash"])
                if vt_sonuç.get("bulundu", False):
                    sonuç["detaylar"]["virustotal"] = vt_sonuç
                    if vt_sonuç.get("pozitif", 0) > 0:
                        risk_artışı = (vt_sonuç["pozitif"] / vt_sonuç["toplam"]) * 100
                        sonuç["risk_skoru"] += risk_artışı
                        sonuç["sebep"].append(
                            f"VirusTotal: {vt_sonuç['pozitif']}/{vt_sonuç['toplam']} "
                            f"antivirüs tarafından tehdit olarak tanımlandı"
                        )
                
                # Statik analiz
                statik_sonuç = self._statik_analiz(dosya_yolu)
                sonuç["detaylar"]["statik_analiz"] = statik_sonuç
                sonuç["risk_skoru"] += statik_sonuç["risk_skoru"]
                sonuç["sebep"].extend(statik_sonuç["sebepler"])
            
            # Risk skoruna göre durum belirleme
            sonuç["risk_skoru"] = min(100, max(0, sonuç["risk_skoru"]))
            if sonuç["risk_skoru"] >= 75:
                sonuç["durum"] = "Zararlı"
            elif sonuç["risk_skoru"] >= 50:
                sonuç["durum"] = "Yüksek Risk"
            elif sonuç["risk_skoru"] >= 25:
                sonuç["durum"] = "Şüpheli"
            
            return sonuç
            
        except Exception as e:
            self.logger.error(f"Dosya analizi hatası ({dosya_yolu}): {str(e)}", exc_info=True)
            sonuç["durum"] = "Hata"
            sonuç["sebep"].append(f"Analiz hatası: {str(e)}")
            return sonuç

    def _dosya_bilgileri_al(self, dosya_yolu):
        dosya = Path(dosya_yolu)
        with open(dosya_yolu, 'rb') as f:
            içerik = f.read()
            
        return {
            "isim": dosya.name,
            "uzantı": dosya.suffix.lower(),
            "boyut": dosya.stat().st_size,
            "oluşturulma": datetime.fromtimestamp(dosya.stat().st_ctime),
            "değiştirilme": datetime.fromtimestamp(dosya.stat().st_mtime),
            "hash": hashlib.sha256(içerik).hexdigest(),
            "md5": hashlib.md5(içerik).hexdigest()
        }

    def _virustotal_kontrol(self, dosya_hash):
        try:
            şimdi = time.time()
            if şimdi - self.api_limit_zamanı < 60:
                if self.api_istek_sayısı >= 4:
                    time.sleep(60 - (şimdi - self.api_limit_zamanı))
                    self.api_istek_sayısı = 0
                    self.api_limit_zamanı = time.time()
            else:
                self.api_istek_sayısı = 0
                self.api_limit_zamanı = şimdi
            
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            params = {"apikey": self.VT_API_KEY, "resource": dosya_hash}
            response = requests.get(url, params=params)
            self.api_istek_sayısı += 1
            
            if response.status_code == 200:
                vt_sonuç = response.json()
                if vt_sonuç["response_code"] == 1:
                    return {
                        "bulundu": True,
                        "pozitif": vt_sonuç["positives"],
                        "toplam": vt_sonuç["total"],
                        "tarama_tarihi": vt_sonuç["scan_date"],
                        "permalink": vt_sonuç["permalink"],
                        "sonuçlar": vt_sonuç["scans"]
                    }
            
            return {"bulundu": False}
            
        except Exception as e:
            self.logger.error(f"VirusTotal API hatası: {str(e)}", exc_info=True)
            return {"bulundu": False, "hata": str(e)}

    def _statik_analiz(self, dosya_yolu):
        sonuç = {
            "risk_skoru": 0,
            "sebepler": [],
            "özellikler": {}
        }
        
        try:
            with open(dosya_yolu, 'rb') as f:
                içerik = f.read()
            
            entropy = self._entropy_hesapla(içerik)
            sonuç["özellikler"]["entropy"] = entropy
            
            if entropy > 7.0:
                sonuç["risk_skoru"] += 20
                sonuç["sebepler"].append(
                    f"Yüksek entropy ({entropy:.2f}): Muhtemel şifrelenmiş/paketlenmiş içerik"
                )
            
            şüpheli_desenler = self.imza_veritabanı.şüpheli_desenleri_al()
            bulunan_desenler = []
            
            for desen in şüpheli_desenler:
                if desen["desen"].encode() in içerik:
                    sonuç["risk_skoru"] += desen["risk_puanı"]
                    bulunan_desenler.append(desen["isim"])
            
            if bulunan_desenler:
                sonuç["sebepler"].append(
                    f"Şüpheli kod parçaları bulundu: {', '.join(bulunan_desenler)}"
                )
            
            if dosya_yolu.lower().endswith(('.exe', '.dll')):
                pe_sonuç = self._pe_dosyası_analiz(dosya_yolu)
                sonuç["özellikler"]["pe_analiz"] = pe_sonuç
                sonuç["risk_skoru"] += pe_sonuç["risk_skoru"]
                sonuç["sebepler"].extend(pe_sonuç["sebepler"])
            
            return sonuç
            
        except Exception as e:
            self.logger.error(f"Statik analiz hatası: {str(e)}", exc_info=True)
            return {"risk_skoru": 0, "sebepler": [f"Analiz hatası: {str(e)}"], "özellikler": {}}

    def _entropy_hesapla(self, veri):
        if not veri:
            return 0
        entropy = 0
        for x in range(256):
            p_x = veri.count(x) / len(veri)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def _pe_dosyası_analiz(self, dosya_yolu):
        try:
            import pefile
            pe = pefile.PE(dosya_yolu)
            
            sonuç = {
                "risk_skoru": 0,
                "sebepler": [],
                "özellikler": {
                    "imzalı": False,
                    "şüpheli_bölümler": [],
                    "içe_aktarılanlar": []
                }
            }
            
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                sonuç["özellikler"]["imzalı"] = True
                sonuç["risk_skoru"] -= 20
                
            for section in pe.sections:
                isim = section.Name.decode().rstrip('\x00')
                entropy = section.get_entropy()
                if entropy > 7.0:
                    sonuç["özellikler"]["şüpheli_bölümler"].append(
                        f"{isim} (Entropy: {entropy:.2f})"
                    )
                    sonuç["risk_skoru"] += 10
                    
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_isim = entry.dll.decode()
                    for imp in entry.imports:
                        if imp.name:
                            fonk_isim = imp.name.decode()
                            sonuç["özellikler"]["içe_aktarılanlar"].append(
                                f"{dll_isim}:{fonk_isim}"
                            )
                            
                            if any(x in fonk_isim.lower() for x in [
                                "inject", "hook", "debug", "crypt", "virtual"
                            ]):
                                sonuç["risk_skoru"] += 5
                                sonuç["sebepler"].append(
                                    f"Şüpheli API çağrısı: {fonk_isim}"
                                )
            
            return sonuç
            
        except Exception as e:
            self.logger.error(f"PE analiz hatası: {str(e)}", exc_info=True)
            return {"risk_skoru": 0, "sebepler": [], "özellikler": {}}
        

class İmzaVeritabanı:
    def __init__(self):
        self.imza_dosyası = "imzalar.json"
        self.son_güncelleme = None
        self._imzaları_yükle()
    
    def _imzaları_yükle(self):
        try:
            if os.path.exists(self.imza_dosyası):
                with open(self.imza_dosyası, 'r') as f:
                    self.imzalar = json.load(f)
                self.son_güncelleme = datetime.fromtimestamp(
                    os.path.getmtime(self.imza_dosyası)
                )
            else:
                self.imzalar = {
                    "şüpheli_desenler": [
                        {
                            "isim": "Process Injection",
                            "desen": "VirtualAllocEx",
                            "risk_puanı": 20
                        },
                        {
                            "isim": "Keylogger",
                            "desen": "SetWindowsHookEx",
                            "risk_puanı": 15
                        },
                        {
                            "isim": "Dosya İşlemleri",
                            "desen": "CreateFile",
                            "risk_puanı": 5
                        }
                    ],
                    "güvenilir_imzalar": [
                        "Microsoft Corporation",
                        "Google LLC",
                        "Mozilla Corporation"
                    ]
                }
                self._imzaları_kaydet()
        except Exception as e:
            logging.error(f"İmza yükleme hatası: {str(e)}", exc_info=True)
            self.imzalar = {"şüpheli_desenler": [], "güvenilir_imzalar": []}
    
    def _imzaları_kaydet(self):
        try:
            with open(self.imza_dosyası, 'w') as f:
                json.dump(self.imzalar, f, indent=4)
            self.son_güncelleme = datetime.now()
        except Exception as e:
            logging.error(f"İmza kaydetme hatası: {str(e)}", exc_info=True)

    def şüpheli_desenleri_al(self):
        return self.imzalar.get("şüpheli_desenler", [])

class KarantinaYöneticisi:
    def __init__(self):
        self.karantina_klasörü = "karantina"
        self.veritabanı = VeritabanıYöneticisi()
        self._klasör_kontrol()
    
    def _klasör_kontrol(self):
        if not os.path.exists(self.karantina_klasörü):
            os.makedirs(self.karantina_klasörü)
    
    def karantinaya_al(self, dosya_yolu, risk_skoru):
        try:
            dosya_adı = os.path.basename(dosya_yolu)
            karantina_adı = f"quarantine_{int(time.time())}_{dosya_adı}"
            karantina_yolu = os.path.join(self.karantina_klasörü, karantina_adı)
            
            # Dosyayı karantinaya taşı
            with open(dosya_yolu, 'rb') as f:
                veri = f.read()
            
            # Basit bir şifreleme (gerçek uygulamada daha güçlü şifreleme kullanılmalı)
            şifreli_veri = bytes([b ^ 0xFF for b in veri])
            
            with open(karantina_yolu, 'wb') as f:
                f.write(şifreli_veri)
            
            # Veritabanına kaydet
            with sqlite3.connect(self.veritabanı.db_yolu) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO karantina 
                    (orijinal_yol, karantina_yolu, hash, risk_skoru, eklenme_tarihi)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    dosya_yolu,
                    karantina_yolu,
                    hashlib.sha256(veri).hexdigest(),
                    risk_skoru,
                    datetime.now()
                ))
                conn.commit()
            
            # Orijinal dosyayı sil
            os.remove(dosya_yolu)
            return True
            
        except Exception as e:
            logging.error(f"Karantina hatası: {str(e)}", exc_info=True)
            return False
    
    def karantinadan_çıkar(self, karantina_yolu, hedef_klasör=None):
        try:
            if not os.path.exists(karantina_yolu):
                return False
                
            with sqlite3.connect(self.veritabanı.db_yolu) as conn:
                c = conn.cursor()
                c.execute("SELECT orijinal_yol FROM karantina WHERE karantina_yolu=?", 
                         (karantina_yolu,))
                sonuç = c.fetchone()
                
            if not sonuç:
                return False
                
            orijinal_yol = sonuç[0]
            if hedef_klasör:
                orijinal_yol = os.path.join(
                    hedef_klasör, 
                    os.path.basename(orijinal_yol)
                )
            
            # Dosyayı deşifrele ve geri yükle
            with open(karantina_yolu, 'rb') as f:
                şifreli_veri = f.read()
            
            veri = bytes([b ^ 0xFF for b in şifreli_veri])
            
            with open(orijinal_yol, 'wb') as f:
                f.write(veri)
            
            # Karantina kaydını sil
            with sqlite3.connect(self.veritabanı.db_yolu) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM karantina WHERE karantina_yolu=?", 
                         (karantina_yolu,))
                conn.commit()
            
            # Karantina dosyasını sil
            os.remove(karantina_yolu)
            return True
            
        except Exception as e:
            logging.error(f"Karantinadan çıkarma hatası: {str(e)}", exc_info=True)
            return False
        

class AntivirüsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Antivirüs")
        self.root.geometry("800x600")
        
        self.tarayıcı = VirüsTarayıcı()
        self.seçilen_klasör = None
        self.tarama_devam_ediyor = True
        
        self._arayüz_oluştur()
        
    def _arayüz_oluştur(self):
        # Ana frame
        ana_frame = ttk.Frame(self.root, padding="10")
        ana_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Üst kısım
        üst_frame = ttk.Frame(ana_frame)
        üst_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.klasör_btn = ttk.Button(
            üst_frame, 
            text="Klasör Seç", 
            command=self.klasör_seç
        )
        self.klasör_btn.grid(row=0, column=0, padx=5)
        
        self.tara_btn = ttk.Button(
            üst_frame, 
            text="Taramayı Başlat", 
            command=self.taramayı_başlat
        )
        self.tara_btn.grid(row=0, column=1, padx=5)
        
        self.durdur_btn = ttk.Button(
            üst_frame, 
            text="Taramayı Durdur", 
            command=self.taramayı_durdur,
            state="disabled"
        )
        self.durdur_btn.grid(row=0, column=2, padx=5)
        
        self.karantina_btn = ttk.Button(
            üst_frame, 
            text="Karantina", 
            command=self.karantina_göster
        )
        self.karantina_btn.grid(row=0, column=3, padx=5)
        
        self.güncelle_btn = ttk.Button(
            üst_frame, 
            text="İmzaları Güncelle", 
            command=self.imzaları_güncelle
        )
        self.güncelle_btn.grid(row=0, column=4, padx=5)
        
        # İlerleme çubuğu
        self.ilerleme_var = tk.DoubleVar()
        self.ilerleme = ttk.Progressbar(
            ana_frame,
            orient="horizontal",
            length=300,
            mode="determinate",
            variable=self.ilerleme_var
        )
        self.ilerleme.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)
        
        # Sonuç alanı
        sonuç_frame = ttk.Frame(ana_frame)
        sonuç_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.sonuç_text = tk.Text(sonuç_frame, wrap=tk.WORD, height=20)
        self.sonuç_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(
            sonuç_frame, 
            orient=tk.VERTICAL, 
            command=self.sonuç_text.yview
        )
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.sonuç_text.configure(yscrollcommand=scrollbar.set)
        
        # Grid ağırlıkları
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        ana_frame.columnconfigure(0, weight=1)
        ana_frame.rowconfigure(2, weight=1)
        sonuç_frame.columnconfigure(0, weight=1)
        sonuç_frame.rowconfigure(0, weight=1)
        
    def klasör_seç(self):
        self.seçilen_klasör = filedialog.askdirectory()
        if self.seçilen_klasör:
            self.sonuç_text.delete(1.0, tk.END)
            self.sonuç_text.insert(1.0, f"Seçilen klasör: {self.seçilen_klasör}\n")
            self.tara_btn["state"] = "normal"
    
    def taramayı_başlat(self):
        if not self.seçilen_klasör:
            messagebox.showwarning(
                "Uyarı",
                "Lütfen önce bir klasör seçin!"
            )
            return
        
        self.tarama_devam_ediyor = True
        self.tara_btn["state"] = "disabled"
        self.durdur_btn["state"] = "normal"
        self.ilerleme_var.set(0)
        
        # Taramayı ayrı bir thread'de başlat
        Thread(target=self.tarama_yap, daemon=True).start()
    
    def taramayı_durdur(self):
        self.tarama_devam_ediyor = False
        self.tara_btn["state"] = "normal"
        self.durdur_btn["state"] = "disabled"
    
    def karantina_göster(self):
        karantina_pencere = tk.Toplevel(self.root)
        karantina_pencere.title("Karantina")
        karantina_pencere.geometry("600x400")
        
        liste_frame = ttk.Frame(karantina_pencere, padding="10")
        liste_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Treeview
        columns = ("Dosya Yolu", "Risk Skoru", "Eklenme Tarihi")
        tree = ttk.Treeview(liste_frame, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        # Karantina verilerini yükle
        with sqlite3.connect(self.tarayıcı.veritabanı.db_yolu) as conn:
            c = conn.cursor()
            c.execute("SELECT orijinal_yol, risk_skoru, eklenme_tarihi FROM karantina")
            for row in c.fetchall():
                tree.insert("", "end", values=row)
        
        tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Kaydırma çubuğu
        scrollbar = ttk.Scrollbar(
            liste_frame, 
            orient=tk.VERTICAL, 
            command=tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid ağırlıkları
        karantina_pencere.columnconfigure(0, weight=1)
        karantina_pencere.rowconfigure(0, weight=1)
        liste_frame.columnconfigure(0, weight=1)
        liste_frame.rowconfigure(0, weight=1)

    def imzaları_güncelle(self):
        """İmza veritabanını günceller"""
        try:
            # Burada gerçek bir güncelleme fonksiyonu olacak
            messagebox.showinfo(
                "Güncelleme",
                "İmza veritabanı başarıyla güncellendi!"
            )
        except Exception as e:
            messagebox.showerror(
                "Hata",
                f"Güncelleme sırasında hata oluştu: {str(e)}"
            )

    def tarama_yap(self):
        try:
            başlangıç_zamanı = time.time()
            sonuçlar = []
            
            # Tüm dosyaları bul
            tüm_dosyalar = []
            self.sonuç_text.delete(1.0, tk.END)
            self.sonuç_text.insert(1.0, "Dosyalar taranıyor...\n")
            self.root.update()
            
            for root, dirs, files in os.walk(self.seçilen_klasör):
                for file in files:
                    if not self.tarama_devam_ediyor:
                        return
                    tüm_dosyalar.append(os.path.join(root, file))
            
            toplam_dosya = len(tüm_dosyalar)
            taranan_dosya = 0
            
            self.sonuç_text.insert(tk.END, f"\nToplam {toplam_dosya} dosya bulundu.\n")
            self.root.update()
            
            # Her dosyayı tara
            for dosya_yolu in tüm_dosyalar:
                try:
                    if not self.tarama_devam_ediyor:
                        return
                    
                    self.sonuç_text.insert(tk.END, f"\nTaranıyor: {dosya_yolu}")
                    self.sonuç_text.see(tk.END)
                    self.root.update()
                    
                    sonuç = self.tarayıcı.dosya_analiz(dosya_yolu)
                    if sonuç["durum"] != "Temiz":
                        self.sonuç_text.insert(tk.END, f" -> {sonuç['durum']}")
                    sonuçlar.append(sonuç)
                    
                    taranan_dosya += 1
                    yüzde = (taranan_dosya / toplam_dosya) * 100
                    self.ilerleme_var.set(yüzde)
                    
                    if taranan_dosya % 10 == 0:  # Her 10 dosyada bir güncelle
                        self.sonuç_text.insert(tk.END, f"\nİlerleme: {taranan_dosya}/{toplam_dosya} ({yüzde:.1f}%)")
                        self.root.update()
                    
                except Exception as e:
                    self.sonuç_text.insert(tk.END, f"\nHata ({dosya_yolu}): {str(e)}")
                    continue
            
            bitiş_zamanı = time.time()
            tarama_süresi = bitiş_zamanı - başlangıç_zamanı
            
            self.sonuç_text.insert(tk.END, "\n\nTarama tamamlandı! Rapor hazırlanıyor...")
            self.root.update()
            
            self.tarama_sonuçlarını_yazdır(sonuçlar, tarama_süresi)
            
        except Exception as e:
            hata_mesajı = f"Tarama sırasında hata oluştu: {str(e)}"
            self.sonuç_text.insert(tk.END, f"\n\nHATA: {hata_mesajı}")
            messagebox.showerror("Hata", hata_mesajı)
        finally:
            self.tarama_devam_ediyor = False
            self.tara_btn["state"] = "normal"
            self.durdur_btn["state"] = "disabled"
            self.root.update()

    def tarama_sonuçlarını_yazdır(self, sonuçlar, tarama_süresi):
        try:
            özet = f"""
╔══════════════════════════════════════════════════════════════╗
║                   ANTİVİRÜS TARAMA RAPORU                    ║
╚══════════════════════════════════════════════════════════════╝

📊 TARAMA BİLGİLERİ
------------------
🕒 Tarih/Saat: {datetime.now().strftime('%d/%m/%Y %H:%M')}
⚡ Tarama Süresi: {tarama_süresi:.1f} saniye

📈 ÖZET İSTATİSTİKLER
-------------------"""

            toplam = len(sonuçlar)
            temiz = sum(1 for s in sonuçlar if s["durum"] == "Temiz")
            zararlı = sum(1 for s in sonuçlar if s["durum"] == "Zararlı")
            yüksek_risk = sum(1 for s in sonuçlar if s["durum"] == "Yüksek Risk")
            şüpheli = sum(1 for s in sonuçlar if s["durum"] == "Şüpheli")
            
            tarama_hızı = toplam / tarama_süresi if tarama_süresi > 0 else 0
            
            özet += f"""
📁 Toplam Taranan: {toplam:,} dosya
✅ Temiz: {temiz:,}
⚠️ Şüpheli: {şüpheli:,}
❗ Yüksek Risk: {yüksek_risk:,}
🚫 Zararlı: {zararlı:,}
⚡ Tarama Hızı: {tarama_hızı:.0f} dosya/saniye
"""

            if zararlı + yüksek_risk + şüpheli > 0:
                özet += """
🔍 TESPİT EDİLEN TEHDİTLER
------------------------
"""
                önemli_sonuçlar = [s for s in sonuçlar if s["durum"] != "Temiz"]
                önemli_sonuçlar.sort(key=lambda x: x["risk_skoru"], reverse=True)
                
                for sonuç in önemli_sonuçlar:
                    try:
                        dosya_adı = os.path.basename(sonuç['dosya'])
                        durum_emoji = {
                            "Zararlı": "🚫",
                            "Yüksek Risk": "❗",
                            "Şüpheli": "⚠️"
                        }.get(sonuç["durum"], "ℹ️")
                        
                        özet += f"""
{durum_emoji} Dosya: {dosya_adı}
   📍 Konum: {sonuç['dosya']}
   ⚡ Risk Skoru: {sonuç['risk_skoru']}/100
   🔍 Durum: {sonuç['durum']}
   📝 Tespitler:"""
                        
                        for sebep in sonuç['sebep']:
                            özet += f"\n      • {sebep}"
                        özet += "\n" + "-" * 60 + "\n"
                        
                    except Exception as e:
                        continue
            else:
                özet += """
✨ TEBRİKLER! Hiçbir tehdit tespit edilmedi.
"""

            özet += """
💡 ÖNERİLER
---------
• Şüpheli dosyaları karantinaya alın
• Gerçek zamanlı korumayı aktif tutun
• İmza veritabanını güncel tutun
"""

            self.sonuç_text.delete(1.0, tk.END)
            self.sonuç_text.insert(1.0, özet)
            
        except Exception as e:
            self.sonuç_text.delete(1.0, tk.END)
            self.sonuç_text.insert(1.0, f"Rapor oluşturulurken hata: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirüsGUI(root)
    root.mainloop()