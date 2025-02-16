# DKIM Analyzer Tool

![GitHub](https://img.shields.io/badge/Python-3.6%2B-blue) ![GitHub](https://img.shields.io/badge/DNS-DKIM-orange) ![GitHub license](https://img.shields.io/badge/license-MIT-green)

Uno strumento Python per analizzare i record DKIM dei domini e verificare le firme DKIM nelle email.  
Supporta sia la **CLI (Command Line Interface)** che una **GUI (Graphical User Interface)**.

---

## 🚀 Funzionalità
- 🔍 **Analisi automatizzata dei record DKIM**  
- 📡 **Query DNS per identificare i selettori DKIM**  
- ✅ **Verifica della struttura dei record DKIM**  
- 📄 **Analisi di email `.eml` per verificare firme DKIM**  
- 🖥️ **Modalità CLI & GUI disponibili**  

---

## 📦 Installazione

### **1️⃣ Requisiti**
Assicurati di avere **Python 3.6 o superiore** installato.

Installa le dipendenze necessarie con:
```bash
pip install dnspython
```

### **2️⃣ Clonare la Repository**
Clona la repository GitHub:
```bash
git clone https://github.com/OlinadEpep/dkim-analyzer.git
cd dkim-analyzer
```

---

## 🛠️ Utilizzo

### **CLI**
Per utilizzare la modalità CLI, esegui:
```bash
python dkimn.py
```
Segui le istruzioni per analizzare un dominio o un'email.

### **GUI**
Per utilizzare la modalità GUI, esegui:
```bash
python dkimn.py
```
Seleziona l'opzione GUI quando richiesto.

---

## 📜 Licenza
Questo progetto è distribuito sotto la licenza MIT. Vedi il file [LICENSE](LICENSE) per maggiori dettagli.

---

## 🤝 Contributi
Contributi, issue e richieste di funzionalità sono benvenuti! Sentiti libero di controllare la pagina delle [issue](https://github.com/tuo-username/dkim-analyzer/issues) se vuoi contribuire.

1. Fork il progetto
2. Crea il tuo branch (`git checkout -b feature/AmazingFeature`)
3. Commit i tuoi cambiamenti (`git commit -m 'Add some AmazingFeature'`)
4. Push il branch (`git push origin feature/AmazingFeature`)
5. Apri una Pull Request

---

Grazie per il tuo supporto!
