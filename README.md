# 🥚 EggScan - Monitor Your LAN Devices Easily

![Download EggScan](https://img.shields.io/badge/Download%20EggScan-Here-blue)

## 🚀 Getting Started

EggScan is a self-hosted LAN device monitor. It helps you see important information about devices on your local network. You can view the IP address, MAC address, vendor, and online status through a simple web dashboard. This gives you control and visibility over your network.

## 📦 System Requirements

To run EggScan, you will need:

- A computer or Raspberry Pi running Linux.
- Python 3.x installed.
- Access to your local network.

## 💻 Download & Install

To download EggScan, visit this page to download: [EggScan Releases](https://github.com/tob-denn/EggScan/releases).

1. Go to the EggScan Releases page.
2. Choose the latest release.
3. Download the appropriate file for your system.
4. Follow the installation instructions below to set it up.

## ⚙️ Installation Instructions

### Step 1: Extract the Files

After downloading the zip file, extract it to a folder on your machine.

### Step 2: Open a Terminal

On your machine, open the terminal. This is where you will enter commands.

### Step 3: Navigate to the Directory

Use the `cd` command to change to the directory where you extracted EggScan. For example:

```bash
cd path/to/your/eggsan-folder
```

### Step 4: Install Dependencies

Before running EggScan, you need to install required dependencies. Use the following command:

```bash
pip install -r requirements.txt
```

### Step 5: Start the Application

Run the application with this command:

```bash
python app.py
```

### Step 6: Access the Dashboard

Open your web browser and enter the following URL:

```
http://localhost:5000
```

You should see the EggScan dashboard, where you can monitor your LAN devices.

## 🔍 Features

- **Device Monitoring**: See devices connected to your local network.
- **Online Status**: Check if a device is active.
- **Vendor Information**: Identify device manufacturers.
- **Easy Setup**: Simple installation process for anyone to follow.
  
## 🌐 Help & Support

If you encounter any issues or need assistance, feel free to open an issue on the EggScan GitHub page. Our community is here to help.

## 📄 License

EggScan is open-source and available under the MIT License. You can freely use and modify the software as long as you provide attribution.

## 🛠️ Contributing

If you want to contribute to EggScan, we welcome your suggestions and code. Please check the CONTRIBUTING.md file for guidelines.

For more information and updates, remember to visit the releases page: [EggScan Releases](https://github.com/tob-denn/EggScan/releases).