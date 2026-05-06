# Cafe_Firmware
Complete Official Firmware Archive for the Nintendo Wii U (`Cafe OS` & `vWii`)

# Difference

* **`Firmware.x.x.xX.zip`** = Raw encrypted Nintendo Update Server (NUS / WUP) files, containing verified `title.tmd`, `title.tik`, `title.cert`, `.app`, and `.h3` files
---
* **`Extracted.Firmware.x.x.xX.zip`** = Decrypted system files extracted directly into the native **Cemu**/**NAND** partition layout (`slc01/sys/title/...`, `mlc01/sys/title/...`, `slccmpt01/sys/title/...`), ready for direct use in Cemu or for inspecting system binaries (like `fw.img`, `kernel.img`, `.rpx`, `.rpl`, etc) on PC.


# Required keys (GitHub secrets or environment variables)

No key is stored in this repository. Provide them as repository secrets (Settings -> Secrets and variables -> Actions) or as environment variables when running locally:

* `WIIU_COMMON_KEY` = Wii U common key, 32 hexadecimal characters (alternatively pass `--otp` with an `otp.bin`).
* `VWII_COMMON_KEY` = vWii common key, 32 hexadecimal characters (required for every vWii title).
* `WII_COMMON_KEY` = Wii common key, 32 hexadecimal characters (!!optional!!).
* `WII_KOREAN_KEY` = Wii Korean key, 32 hexadecimal characters (!!optional!!).

Each key is checked against its SHA-1 fingerprint before use.

# CLI Usage (`firmware_downloader.py`)

```bash

# Download and package the latest Wii U firmware wave (5.5.6U):
python3 firmware_downloader.py

# Latest firmware of every region without naming a version (5.5.5 first, then 5.5.6 last),
# checked against the latest TMD of every title on the Nintendo servers:
python3 firmware_downloader.py --latest --extract-data --logs

# Download a specific firmware wave across all available regions (e.g. 5.5.5 -> 5.5.5E, 5.5.5U, 5.5.5J) and extract Cemu/NAND folders:
python3 firmware_downloader.py 5.5.5 --extract-data --logs

# Download and archive all 51 firmware waves (145 regional builds) and generate the Logiqx XML DATfile:
python3 firmware_downloader.py --allversion --extract-data --datfile --logs

# Rebuild the Logiqx XML DATfile from local Firmware.*.zip archives:
python3 firmware_downloader.py --dat-from-zips --logs

```
