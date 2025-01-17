import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import hashlib
import time
from datetime import datetime
import math
import yara
import requests
import magic
import json
import sys
from colorama import init, Fore, Back, Style
init()  # Windows'ta renkleri kullanabilmek için

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)

class DosyaAnalizci:
    def __init__(self):
        # Kaynak dosyaları yükle
        self.zararlı_hashler = self.zararlı_hash_listesi_yükle()
        self.şüpheli_desenler = self.şüpheli_desen_listesi_yükle()
        self.güvenilir_üreticiler = self.güvenilir_üretici_listesi_yükle()
        self.imza_güncelleme_tarihi = self.imza_tarihini_al()
        self.gerçek_zamanlı_koruma_aktif = False
        self.son_tarama_tarihi = None
        self.karantina_klasörü = os.path.join(os.path.expanduser("~"), "AntivirusQuarantine")
        
        # Şüpheli kod desenleri
        self.şüpheli_desenler = [
            # Sistem manipülasyonu
            b"CreateRemoteThread",
            b"WriteProcessMemory",
            b"VirtualAllocEx",
            b"SetWindowsHookEx",
            b"GetAsyncKeyState",  # Keylogger belirtisi
            
            # Ağ aktivitesi
            b"URLDownloadToFile",
            b"InternetOpenUrl",
            b"WSAStartup",
            b"connect(",
            
            # Dosya sistemi
            b"CreateFile",
            b"WriteFile",
            b"MoveFile",
            b"RegCreateKey",
            
            # Şifreleme belirtileri
            b"CryptoAPI",
            b"AES_encrypt",
            b"RSA_encrypt",
            
            # Zararlı yazılım belirtileri
            b"cmd.exe /c",
            b"powershell.exe -enc",
            b"mshta.exe",
            b".vbs",
            b"wscript.shell",
            
            # Antivirüs atlatma
            b"IsDebuggerPresent",
            b"Sleep(",
            b"GetTickCount",
        ]
        
        # Şüpheli dosya uzantıları
        self.şüpheli_uzantılar = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', 
            '.js', '.wsf', '.hta', '.scr', '.pif', '.reg'
        }

        self.güvenilir_üreticiler = {
            'Microsoft': {'indirim': -30, 'isim_içerir': ['microsoft', 'windows', 'msvc'], 
                         'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
            'Python': {'indirim': -40, 'isim_içerir': ['python', 'py'], 
                      'güvenilir_kodlar': [b'CreateFile', b'WriteFile']},
            'Chrome': {'indirim': -35, 'isim_içerir': ['chrome', 'google'], 
                      'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
            'Firefox': {'indirim': -35, 'isim_içerir': ['firefox', 'mozilla'], 
                       'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
            'Qt': {'indirim': -30, 'isim_içerir': ['qt5', 'qt6'], 
                  'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'connect(']}
        }

        self.toplam_dosya = 0
        self.zararlı_sayısı = 0
        self.yüksek_riskli_sayısı = 0
        self.şüpheli_sayısı = 0

        if not os.path.exists(self.karantina_klasörü):
            os.makedirs(self.karantina_klasörü)

    def dosya_analiz(self, dosya_yolu):
        sonuç = {
            "dosya": dosya_yolu,
            "durum": "Temiz",
            "sebep": [],
            "risk_skoru": 0,
            "şüpheli_kodlar": []
        }
        
        try:
            # Dosya yolunu normalize et
            dosya_yolu = os.path.normpath(dosya_yolu)
            dosya_adı = os.path.basename(dosya_yolu).lower()
            dosya_uzantısı = os.path.splitext(dosya_adı)[1].lower()
            
            # Türkçe karakter içeren dosya yollarını handle et
            try:
                dosya_yolu = dosya_yolu.encode('utf-8').decode('utf-8')
            except UnicodeError:
                dosya_yolu = dosya_yolu.encode('ascii', 'ignore').decode('ascii')
            
            # Resim ve medya dosyaları kontrolü
            güvenli_uzantılar = {
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4', 
                '.wav', '.avi', '.webp', '.tiff', '.ico', '.svg', '.raw'
            }
            
            # Resim veya Mac OS dosyası kontrolü
            if dosya_uzantısı in güvenli_uzantılar or dosya_adı.startswith('._') or '__macosx' in dosya_yolu.lower():
                sonuç["durum"] = "Temiz"
                sonuç["sebep"].append("Güvenli medya/sistem dosyası")
                return sonuç
            
            # Güvenilir yazılım kontrolü - genişletilmiş liste
            güvenilir_yazılımlar = {
                'vc_redist': {'indirim': -50, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'MoveFile', b'RegCreateKey', b'IsDebuggerPresent']},
                'vcredist': {'indirim': -50, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'MoveFile', b'RegCreateKey', b'IsDebuggerPresent']},
                'microsoft visual c++': {'indirim': -50, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'MoveFile', b'RegCreateKey']},
                'qt5': {'indirim': -30, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'connect(', b'RegCreateKey']},
                'opengl': {'indirim': -30, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'SetWindowsHookEx']},
                'python': {'indirim': -40, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile']},
                'anaconda': {'indirim': -40, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'MoveFile']},
                'chrome': {'indirim': -35, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
                'firefox': {'indirim': -35, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
                'microsoft': {'indirim': -35, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
                'windows': {'indirim': -35, 'güvenilir_kodlar': [b'CreateFile', b'WriteFile', b'RegCreateKey']},
            }
            
            # Dosya yolunda güvenilir klasörler kontrolü
            güvenilir_klasörler = ['windows', 'program files', 'microsoft', 'common files']
            if any(klasör.lower() in dosya_yolu.lower() for klasör in güvenilir_klasörler):
                sonuç["risk_skoru"] -= 25
                sonuç["sebep"].append("Güvenilir sistem klasöründe")
            
            güvenilir_yazılım_bulundu = False
            güvenilir_kodlar = set()
            
            # Güvenilir yazılım kontrolü
            for yazılım, bilgi in güvenilir_yazılımlar.items():
                if yazılım in dosya_adı:
                    sonuç["risk_skoru"] += bilgi['indirim']
                    sonuç["sebep"].append(f"Güvenilir yazılım: {yazılım}")
                    güvenilir_yazılım_bulundu = True
                    güvenilir_kodlar.update(bilgi['güvenilir_kodlar'])
                    break  # İlk eşleşmede dur
            
            try:
                with open(dosya_yolu, 'rb') as f:
                    içerik = f.read()
                    
                    # Şüpheli desen kontrolü
                    for desen in self.şüpheli_desenler:
                        if desen in içerik:
                            if güvenilir_yazılım_bulundu and desen in güvenilir_kodlar:
                                continue
                                
                            puan = {
                                b"CreateRemoteThread": 20,
                                b"WriteProcessMemory": 20,
                                b"VirtualAllocEx": 15,
                                b"SetWindowsHookEx": 12,
                                b"GetAsyncKeyState": 10,
                                b"CreateFile": 5,
                                b"WriteFile": 5,
                                b"MoveFile": 5,
                                b"RegCreateKey": 8,
                                b"IsDebuggerPresent": 5,
                                b"GetTickCount": 3,
                            }.get(desen, 8)
                            
                            if güvenilir_yazılım_bulundu:
                                puan = int(puan * 0.6)  # %40 indirim
                            
                            sonuç["risk_skoru"] += puan
                            sonuç["sebep"].append(f"Şüpheli kod bulundu: {desen.decode()}")
                    
                    # Entropy analizi
                    entropy = self.hesapla_entropy(içerik)
                    if entropy > 7.0:
                        entropy_puanı = 25
                        if güvenilir_yazılım_bulundu:
                            entropy_puanı = 12
                        sonuç["risk_skoru"] += entropy_puanı
                        sonuç["sebep"].append("Yüksek entropy: Muhtemel şifrelenmiş/paketlenmiş içerik")
            
            except UnicodeEncodeError:
                if dosya_uzantısı in güvenli_uzantılar:
                    sonuç["durum"] = "Temiz"
                return sonuç
                
            except Exception as e:
                if dosya_uzantısı in güvenli_uzantılar or dosya_adı.startswith('._'):
                    sonuç["durum"] = "Temiz"
                    sonuç["sebep"].append("Güvenli dosya")
                else:
                    sonuç["durum"] = "Hata"
                    sonuç["sebep"].append(f"Beklenmeyen hata: {str(e)}")
                return sonuç
            
            # Risk skorunu 0-100 arasında sınırla
            sonuç["risk_skoru"] = max(0, min(sonuç["risk_skoru"], 100))
            
            # Durum belirleme
            if sonuç["risk_skoru"] >= 75:
                sonuç["durum"] = "Zararlı"
            elif sonuç["risk_skoru"] >= 55:
                sonuç["durum"] = "Yüksek Risk"
            elif sonuç["risk_skoru"] >= 35:
                sonuç["durum"] = "Şüpheli"
            
        except Exception as e:
            if dosya_uzantısı in güvenli_uzantılar or dosya_adı.startswith('._'):
                sonuç["durum"] = "Temiz"
                sonuç["sebep"].append("Güvenli dosya")
            else:
                sonuç["durum"] = "Hata"
                sonuç["sebep"].append(f"Beklenmeyen hata: {str(e)}")
        
        return sonuç

    def hesapla_entropy(self, data):
        """Shannon entropy hesaplama"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def virustotal_kontrol(self, dosya_yolu):
        """VirusTotal API ile dosya kontrolü"""
        try:
            API_KEY = "30c9c41059c25999f395f72470cd6e1a78c925234542fafe550343a869ec0bbf"  # VirusTotal API anahtarı
            dosya_hash = hashlib.sha256(open(dosya_yolu, 'rb').read()).hexdigest()
            
            headers = {
                "x-apikey": API_KEY
            }
            
            url = f"https://www.virustotal.com/api/v3/files/{dosya_hash}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                sonuç = response.json()
                return sonuç.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
        except Exception as e:
            print(f"VirusTotal API hatası: {e}")
        return None

    def dosya_raporu_oluştur(self, dosya_yolu, sonuçlar):
        try:
            dosya_bilgisi = os.stat(dosya_yolu)
            dosya_boyutu = dosya_bilgisi.st_size / 1024  # KB cinsinden
            hash_md5 = hashlib.md5(open(dosya_yolu, 'rb').read()).hexdigest()
            hash_sha256 = hashlib.sha256(open(dosya_yolu, 'rb').read()).hexdigest()
            
            risk_seviyesi = "Düşük" if sonuçlar['risk_skoru'] < 30 else \
                           "Orta" if sonuçlar['risk_skoru'] < 60 else \
                           "Yüksek" if sonuçlar['risk_skoru'] < 85 else "Kritik"

            rapor = f"""
╔══════════════════════════════════════════════════════════════════════════════
║ DETAYLI GÜVENLİK ANALİZ RAPORU
╠══════════════════════════════════════════════════════════════════════════════
║ DOSYA BİLGİLERİ
║ • Dosya Adı: {os.path.basename(dosya_yolu)}
║ • Konum: {dosya_yolu}
║ • Boyut: {dosya_boyutu:.2f} KB
║ • Oluşturulma: {time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(dosya_bilgisi.st_ctime))}
║ • Son Değişiklik: {time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(dosya_bilgisi.st_mtime))}
╠══════════════════════════════════════════════════════════════════════════════
║ GÜVENLİK ANALİZİ
║ • Risk Skoru: {sonuçlar['risk_skoru']}/100
║ • Risk Seviyesi: {risk_seviyesi}
║ • Durum: {sonuçlar['durum']}
╠══════════════════════════════════════════════════════════════════════════════
║ TESPİT EDİLEN ŞÜPHELİ KODLAR:"""

            if sonuçlar['şüpheli_kodlar']:
                for kod in sonuçlar['şüpheli_kodlar']:
                    rapor += f"\n║ • {kod.decode('utf-8', errors='ignore')}"
            else:
                rapor += "\n║ • Şüpheli kod tespit edilmedi"

            rapor += f"""
╠══════════════════════════════════════════════════════════════════════════════
║ HASH DEĞERLERİ
║ • MD5: {hash_md5}
║ • SHA256: {hash_sha256}
╠══════════════════════════════════════════════════════════════════════════════
║ ÖNERİLER"""

            if sonuçlar['risk_skoru'] >= 85:
                rapor += """
║ ! DİKKAT: Bu dosya yüksek risk taşıyor!
║ • Dosyayı AÇMAYIN
║ • Sisteminizden kaldırmanız önerilir
║ • Güvenlik yazılımınızla tam tarama yapın"""
            elif sonuçlar['risk_skoru'] >= 60:
                rapor += """
║ ! UYARI: Bu dosya potansiyel risk taşıyor
║ • Dosyayı güvenli ortamda test edin
║ • Kaynağını doğrulayın"""
            else:
                rapor += """
║ • Dosya düşük risk taşıyor
║ • Normal kullanıma devam edebilirsiniz"""

            rapor += "\n╚═════════════════════════════════���════════════════════════════════════════════"
            
            return rapor
            
        except Exception as e:
            return f"Rapor oluşturulurken hata: {str(e)}"

    def şüpheli_desenleri_güncelle(self):
        self.şüpheli_desenler.extend([
            # Sistem Gizleme
            b"SetFileAttributes",
            b"NtUnmapViewOfSection",
            b"NtProtectVirtualMemory",
            
            # Ağ Güvenliği
            b"WinExec",
            b"ShellExecute",
            b"socket.connect",
            b"http://",
            b"https://",
            
            # Klavye/Fare Takibi
            b"SetWindowsHookEx",
            b"GetKeyState",
            b"GetKeyboardState",
            
            # Ekran Kaydı
            b"BitBlt",
            b"GetDC",
            b"CreateCompatibleDC",
            
            # Bellek Manipülasyonu
            b"VirtualProtect",
            b"HeapCreate",
            b"RtlMoveMemory",
            
            # Persistence
            b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            b"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            b"Schedule Task",
        ])

    def risk_skoru_hesapla(self, dosya_yolu, şüpheli_kodlar):
        skor = 0
        dosya_adı = os.path.basename(dosya_yolu).lower()
        
        # Dijital imza kontrolü ekle
        if self.dijital_imza_kontrol(dosya_yolu):
            skor -= 40  # İmzalı dosyalar için büyük indirim
        
        # Güvenilir üretici kontrolü - genişletilmiş liste
        güvenilir_üreticiler = {
            'Microsoft': {'desenler': ['microsoft', 'windows', 'office'], 'indirim': -60},
            'Anaconda': {'desenler': ['anaconda', 'conda'], 'indirim': -70},
            'Python': {'desenler': ['python', 'pip'], 'indirim': -70},
            'Google': {'desenler': ['chrome', 'google'], 'indirim': -60},
            'Adobe': {'desenler': ['adobe', 'acrobat'], 'indirim': -50},
            'Oracle': {'desenler': ['java', 'jre', 'jdk'], 'indirim': -50},
            'Mozilla': {'desenler': ['firefox', 'mozilla'], 'indirim': -50},
        }
        
        # Güvenilir üretici kontrolü
        for üretici, bilgi in güvenilir_üreticiler.items():
            if any(desen in dosya_adı for desen in bilgi['desenler']):
                skor += bilgi['indirim']
                break
        
        # Şüpheli kod ağırlıkları
        kod_ağırlıkları = {
            b"CreateRemoteThread": 15,
            b"WriteProcessMemory": 15,
            b"VirtualAllocEx": 12,
            b"SetWindowsHookEx": 10,
            b"GetAsyncKeyState": 8,
            b"cmd.exe": 10,
            b"powershell.exe": 12,
        }
        
        for kod in şüpheli_kodlar:
            for şüpheli_kod, ağırlık in kod_ağırlıkları.items():
                if şüpheli_kod in kod:
                    skor += ağırlık
                    break
            else:
                skor += 5  # Diğer şüpheli kodlar için
        
        # Dosya türü kontrolü
        dosya_uzantısı = os.path.splitext(dosya_adı)[1].lower()
        yüksek_riskli_uzantılar = {'.exe': 15, '.dll': 12, '.bat': 10, '.ps1': 10}
        skor += yüksek_riskli_uzantılar.get(dosya_uzantısı, 0)
        
        return max(0, min(skor, 100))  # 0-100 arası sınırla

    def durum_belirle(self, risk_skoru):
        if risk_skoru >= 80:
            return "Zararlı"
        elif risk_skoru >= 60:
            return "Yüksek Risk"
        elif risk_skoru >= 40:
            return "Şüpheli"
        elif risk_skoru >= 20:
            return "Düşük Risk"
        else:
            return "Güvenli"

    def toplu_tarama(self, klasör_yolu):
        tarama_sonuçları = []
        toplam_dosya = 0
        taranan_dosya = 0
        
        for root, dirs, files in os.walk(klasör_yolu):
            toplam_dosya += len(files)
            for dosya in files:
                dosya_yolu = os.path.join(root, dosya)
                try:
                    sonuç = self.dosya_analiz(dosya_yolu)
                    tarama_sonuçları.append({
                        'dosya': dosya_yolu,
                        'sonuç': sonuç
                    })
                    taranan_dosya += 1
                    
                    # İlerleme durumunu güncelle
                    ilerleme = (taranan_dosya / toplam_dosya) * 100
                    self.ilerleme_güncelle(ilerleme)
                    
                except Exception as e:
                    tarama_sonuçları.append({
                        'dosya': dosya_yolu,
                        'hata': str(e)
                    })
        
        return self.toplu_rapor_oluştur(tarama_sonuçları)

    def toplu_rapor_oluştur(self, sonuçlar):
        özet = f"""
{Fore.CYAN}╔══ TARAMA SONUÇ ÖZETİ ══════════════════════════════════════════════════
{Fore.CYAN}║ {Fore.WHITE}Toplam Taranan Dosya: {self.toplam_dosya}
{Fore.CYAN}║ {Fore.RED}Zararlı Dosya: {self.zararlı_sayısı}
{Fore.CYAN}║ {Fore.YELLOW}Yüksek Riskli Dosya: {self.yüksek_riskli_sayısı}
{Fore.CYAN}║ {Fore.YELLOW}Şüpheli Dosya: {self.şüpheli_sayısı}
{Fore.CYAN}╚════════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
"""
        return özet + "\n".join(self.dosya_raporu_oluştur(sonuç) for sonuç in sonuçlar)

    def karantinaya_al(self, dosya_yolu):
        """Dosyayı karantinaya al"""
        try:
            if not os.path.exists(self.karantina_klasörü):
                os.makedirs(self.karantina_klasörü)
                
            dosya_adı = os.path.basename(dosya_yolu)
            karantina_yolu = os.path.join(self.karantina_klasörü, 
                f"quarantine_{int(time.time())}_{dosya_adı}")
            
            # Dosyayı şifrele ve taşı
            with open(dosya_yolu, 'rb') as f:
                veri = f.read()
            
            # Basit XOR şifreleme
            şifreli_veri = bytes([b ^ 0xFF for b in veri])
            
            with open(karantina_yolu, 'wb') as f:
                f.write(şifreli_veri)
                
            os.remove(dosya_yolu)  # Orijinal dosyayı sil
            return True, "Dosya karantinaya alındı"
            
        except Exception as e:
            return False, f"Karantina hatası: {str(e)}"

    def karantinadan_çıkar(self, karantina_dosyası, hedef_yol):
        """Dosyayı karantinadan çıkar"""
        try:
            with open(karantina_dosyası, 'rb') as f:
                şifreli_veri = f.read()
            
            # XOR şifre çözme
            veri = bytes([b ^ 0xFF for b in şifreli_veri])
            
            with open(hedef_yol, 'wb') as f:
                f.write(veri)
                
            os.remove(karantina_dosyası)
            return True, "Dosya karantinadan çıkarıldı"
            
        except Exception as e:
            return False, f"Karantinadan çıkarma hatası: {str(e)}"
            
            return True, karantina_yolu
            
        except Exception as e:
            return False, str(e)

class GerçekZamanlıKoruma:
    def __init__(self, analizci):
        self.analizci = analizci
        self.izlenen_klasörler = set()
        self.observer = None
    
    def klasör_izlemeye_başla(self, klasör_yolu):
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        
        class DosyaOlayİzleyici(FileSystemEventHandler):
            def __init__(self, analizci):
                self.analizci = analizci
            
            def on_created(self, event):
                if not event.is_directory:
                    sonuç = self.analizci.dosya_analiz(event.src_path)
                    if sonuç["risk_skoru"] >= 80:
                        self.analizci.karantinaya_al(event.src_path)
        
        self.observer = Observer()
        self.observer.schedule(DosyaOlayİzleyici(self.analizci), 
                             klasör_yolu, recursive=True)
        self.observer.start()
        self.izlenen_klasörler.add(klasör_yolu)

class GelişmişAntivirüs:
    def __init__(self):
        self.analizci = DosyaAnalizci()
        self.taranan_dosya_sayısı = 0
    
    def klasör_tara(self, tarama_yolu):
        """Belirtilen klasörü ve alt klasörlerini tarar"""
        sonuçlar = []
        self.taranan_dosya_sayısı = 0
        
        try:
            # Alt klasörler dahil tüm dosyaları tara
            for root, dirs, files in os.walk(tarama_yolu):
                for dosya in files:
                    try:
                        dosya_yolu = os.path.join(root, dosya)
                        print(f"Taranan dosya: {dosya_yolu}")  # Debug için
                        
                        # Dosya uzantısı kontrolü
                        _, uzantı = os.path.splitext(dosya)
                        if uzantı.lower() in self.analizci.şüpheli_uzantılar:
                            analiz_sonucu = self.analizci.dosya_analiz(dosya_yolu)
                        else:
                            analiz_sonucu = {
                                "dosya": dosya_yolu,
                                "durum": "Temiz",
                                "sebep": ["Güvenli dosya uzantısı"],
                                "risk_skoru": 0
                            }
                        
                        sonuçlar.append(analiz_sonucu)
                        self.taranan_dosya_sayısı += 1
                        
                    except (PermissionError, FileNotFoundError) as e:
                        sonuçlar.append({
                            "dosya": dosya_yolu,
                            "durum": "Erişim Hatası",
                            "sebep": [f"Dosyaya erişilemedi: {str(e)}"],
                            "risk_skoru": 0
                        })
                    except Exception as e:
                        sonuçlar.append({
                            "dosya": dosya_yolu,
                            "durum": "Hata",
                            "sebep": [f"Beklenmeyen hata: {str(e)}"],
                            "risk_skoru": 0
                        })
                        
        except Exception as e:
            print(f"Klasör tarama hatası: {e}")
        
        return sonuçlar

class AntivirüsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Gelişmiş Antivirüs")
        self.root.geometry("800x600")
        self.antivirüs = GelişmişAntivirüs()
        
        # Ana frame
        self.ana_frame = ttk.Frame(self.root, padding="10")
        self.ana_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Başlık
        ttk.Label(self.ana_frame, text="Antivirüs Tarama Merkezi", 
                 font=('Helvetica', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # Klasör seçme
        self.klasör_frame = ttk.Frame(self.ana_frame)
        self.klasör_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.klasör_yolu = tk.StringVar()
        self.klasör_entry = ttk.Entry(self.klasör_frame, textvariable=self.klasör_yolu, width=60)
        self.klasör_entry.grid(row=0, column=0, padx=5)
        
        self.gözat_btn = ttk.Button(self.klasör_frame, text="Klasör Seç", command=self.klasör_seç)
        self.gözat_btn.grid(row=0, column=1, padx=5)
        
        # Tarama butonu
        self.tara_btn = ttk.Button(self.ana_frame, text="Taramayı Başlat", command=self.tarama_başlat)
        self.tara_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # İlerleme çubuğu
        self.ilerleme = ttk.Progressbar(self.ana_frame, length=600, mode='indeterminate')
        self.ilerleme.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Durum etiketi
        self.durum_label = ttk.Label(self.ana_frame, text="Hazır", font=('Helvetica', 10))
        self.durum_label.grid(row=4, column=0, columnspan=2, pady=5)
        
        # Sonuçlar için metin kutusu
        self.sonuç_text = tk.Text(self.ana_frame, height=20, width=80)
        self.sonuç_text.grid(row=5, column=0, columnspan=2, pady=10)
        
        # Karantina butonu
        self.karantina_btn = ttk.Button(self.ana_frame, text="Karantina Yönetimi", 
                                      command=self.karantina_yönetimi_göster)
        self.karantina_btn.grid(row=6, column=0, pady=5)
        
        # Gerçek zamanlı koruma switch'i
        self.gerçek_zamanlı = tk.BooleanVar()
        self.gerçek_zamanlı_switch = ttk.Checkbutton(self.ana_frame, 
                                                    text="Gerçek Zamanlı Koruma",
                                                    variable=self.gerçek_zamanlı,
                                                    command=self.gerçek_zamanlı_değişti)
        self.gerçek_zamanlı_switch.grid(row=6, column=1, pady=5)
    
    def klasör_seç(self):
        klasör = filedialog.askdirectory()
        if klasör:
            self.klasör_yolu.set(klasör)
    
    def tarama_başlat(self):
        klasör = self.klasör_yolu.get()
        if not klasör:
            messagebox.showerror("Hata", "Lütfen bir klasör seçin!")
            return
        
        if not os.path.exists(klasör):
            messagebox.showerror("Hata", "Seçilen klasör bulunamadı!")
            return
        
        self.ilerleme.start()
        self.durum_label.config(text="Tarama devam ediyor...")
        self.tara_btn.config(state='disabled')
        self.sonuç_text.delete(1.0, tk.END)
        self.sonuç_text.insert(1.0, "Tarama başladı...\n")
        
        def tarama_thread():
            try:
                sonuçlar = self.antivirüs.klasör_tara(klasör)
                self.root.after(0, self.tarama_tamamlandı, sonuçlar)
            except Exception as e:
                self.root.after(0, self.tarama_hatası, str(e))
        
        threading.Thread(target=tarama_thread, daemon=True).start()
    
    def tarama_tamamlandı(self, sonuçlar):
        self.ilerleme.stop()
        self.tara_btn.config(state='normal')
        
        if not sonuçlar:
            self.durum_label.config(text="Tarama tamamlandı - Dosya bulunamadı")
            self.sonuç_text.insert(tk.END, "\nTarama tamamlandı fakat hiç dosya bulunamadı.")
            return
        
        self.durum_label.config(text=f"Tarama tamamlandı - {len(sonuçlar)} dosya tarandı")
        self.sonuçları_göster(sonuçlar)
    
    def tarama_hatası(self, hata_mesajı):
        self.ilerleme.stop()
        self.tara_btn.config(state='normal')
        self.durum_label.config(text="Tarama hatası!")
        messagebox.showerror("Tarama Hatası", f"Tarama sırasında bir hata oluştu:\n{hata_mesajı}")
    
    def sonuçları_göster(self, sonuçlar):
        self.sonuç_text.delete(1.0, tk.END)
        
        if not sonuçlar:
            self.sonuç_text.insert(1.0, "Hiç dosya taranmadı veya taranan klasörlere erişilemedi.")
            return
        
        zararlı_sayısı = len([s for s in sonuçlar if s["durum"] == "Zararlı"])
        yüksek_risk_sayısı = len([s for s in sonuçlar if s["durum"] == "Yüksek Risk"])
        şüpheli_sayısı = len([s for s in sonuçlar if s["durum"] == "Şüpheli"])
        
        özet = f"Tarama Sonuçları\n"
        özet += "=" * 50 + "\n\n"
        özet += f"Toplam taranan dosya: {len(sonuçlar)}\n"
        özet += f"Zararlı dosya: {zararlı_sayısı}\n"
        özet += f"Yüksek riskli dosya: {yüksek_risk_sayısı}\n"
        özet += f"Şüpheli dosya: {şüpheli_sayısı}\n"
        özet += "-" * 50 + "\n\n"
        
        # Tehlikeli dosyaları listele
        for sonuç in sonuçlar:
            if sonuç["durum"] != "Temiz":
                özet += f"Dosya: {sonuç['dosya']}\n"
                özet += f"Durum: {sonuç['durum']}\n"
                özet += f"Risk Skoru: {sonuç['risk_skoru']}\n"
                özet += "Sebepler:\n"
                for sebep in sonuç['sebep']:
                    özet += f"  - {sebep}\n"
                özet += "-" * 30 + "\n"
        
        self.sonuç_text.insert(1.0, özet)

    def karantina_yönetimi_göster(self):
        """Karantina yönetimi penceresini göster"""
        karantina_pencere = tk.Toplevel(self.root)
        karantina_pencere.title("Karantina Yönetimi")
        karantina_pencere.geometry("600x400")
        
        # Karantina listesi
        liste_frame = ttk.Frame(karantina_pencere, padding="10")
        liste_frame.pack(fill=tk.BOTH, expand=True)
        
        # Karantina dosyaları listesi
        self.karantina_liste = tk.Listbox(liste_frame, width=70, height=15)
        self.karantina_liste.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Kaydırma çubuğu
        scrollbar = ttk.Scrollbar(liste_frame, orient=tk.VERTICAL, 
                                command=self.karantina_liste.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.karantina_liste.configure(yscrollcommand=scrollbar.set)
        
        # Butonlar
        buton_frame = ttk.Frame(karantina_pencere, padding="10")
        buton_frame.pack(fill=tk.X)
        
        ttk.Button(buton_frame, text="Geri Yükle", 
                  command=self.karantina_geri_yükle).pack(side=tk.LEFT, padx=5)
        ttk.Button(buton_frame, text="Kalıcı Sil", 
                  command=self.karantina_sil).pack(side=tk.LEFT, padx=5)
        
        # Karantina listesini güncelle
        self.karantina_listesi_güncelle()

    def karantina_listesi_güncelle(self):
        """Karantina dosyaları listesini güncelle"""
        self.karantina_liste.delete(0, tk.END)
        karantina_klasörü = self.antivirüs.analizci.karantina_klasörü
        
        if os.path.exists(karantina_klasörü):
            for dosya in os.listdir(karantina_klasörü):
                self.karantina_liste.insert(tk.END, dosya)

    def karantina_geri_yükle(self):
        """Seçili dosyayı karantinadan geri yükle"""
        seçili = self.karantina_liste.curselection()
        if not seçili:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return
            
        dosya_adı = self.karantina_liste.get(seçili[0])
        karantina_yolu = os.path.join(self.antivirüs.analizci.karantina_klasörü, dosya_adı)
        
        hedef_yol = filedialog.asksaveasfilename(
            defaultextension=".*",
            initialfile=dosya_adı.split("_", 2)[-1],  # Orijinal dosya adı
            title="Dosyayı Nereye Geri Yüklemek İstersiniz?"
        )
        
        if hedef_yol:
            try:
                # Dosyayı deşifrele ve geri yükle
                with open(karantina_yolu, 'rb') as f:
                    şifreli_veri = f.read()
                
                veri = bytes([b ^ 0xFF for b in şifreli_veri])  # XOR şifre çözme
                
                with open(hedef_yol, 'wb') as f:
                    f.write(veri)
                
                os.remove(karantina_yolu)  # Karantinadan kaldır
                self.karantina_listesi_güncelle()
                messagebox.showinfo("Başarılı", "Dosya başarıyla geri yüklendi!")
                
            except Exception as e:
                messagebox.showerror("Hata", f"Geri yükleme hatası: {str(e)}")

    def karantina_sil(self):
        """Seçili dosyayı kalıcı olarak sil"""
        seçili = self.karantina_liste.curselection()
        if not seçili:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return
            
        if messagebox.askyesno("Onay", "Dosya kalıcı olarak silinecek. Emin misiniz?"):
            dosya_adı = self.karantina_liste.get(seçili[0])
            karantina_yolu = os.path.join(self.antivirüs.analizci.karantina_klasörü, dosya_adı)
            
            try:
                os.remove(karantina_yolu)
                self.karantina_listesi_güncelle()
                messagebox.showinfo("Başarılı", "Dosya kalıcı olarak silindi!")
            except Exception as e:
                messagebox.showerror("Hata", f"Silme hatası: {str(e)}")

    def gerçek_zamanlı_değişti(self):
        """Gerçek zamanlı koruma durumu değiştiğinde çağrılır"""
        if self.gerçek_zamanlı.get():
            klasör = filedialog.askdirectory(title="İzlenecek Klasörü Seçin")
            if klasör:
                try:
                    self.antivirüs.gerçek_zamanlı_koruma_başlat(klasör)
                    messagebox.showinfo("Bilgi", f"{klasör} klasörü izlenmeye başlandı!")
                except Exception as e:
                    messagebox.showerror("Hata", f"Gerçek zamanlı koruma başlatılamadı: {str(e)}")
                    self.gerçek_zamanlı.set(False)
        else:
            self.antivirüs.gerçek_zamanlı_koruma_durdur()

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
🔄 İmza Veritabanı: {self.imza_güncelleme_tarihi}
👁️ Gerçek Zamanlı Koruma: {'Aktif' if self.gerçek_zamanlı_koruma_aktif else 'Pasif'}

📈 ÖZET İSTATİSTİKLER
-------------------"""

            # İstatistikler
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
                # Tehditleri önem sırasına göre sırala
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
                        
                    except UnicodeEncodeError:
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
