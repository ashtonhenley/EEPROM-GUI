import tkinter as tk
from tkinter import messagebox
from i2c_handler import I2CHandler, parse_data
from tkinter import filedialog
import binascii
class EEPROMGUI:
    def __init__(self, i2c, master):
        self.dark_theme = {
            "BG": "#23272e",
            "PANEL": "#2c313c",
            "ENTRY": "#23272e",
            "LABEL": "#bfc7d5",
            "BUTTON": "#3b82f6",
            "BUTTON_ACTIVE": "#2563eb",
            "BUTTON_TEXT": "#ffffff",
            "HIGHLIGHT": "#3b4252"
        }
        self.light_theme = {
            "BG": "#f0f0f0",
            "PANEL": "#f8f8ff",
            "ENTRY": "#ffffff",
            "LABEL": "#23272e",
            "BUTTON": "#1976d2",
            "BUTTON_ACTIVE": "#1565c0",
            "BUTTON_TEXT": "#ffffff",
            "HIGHLIGHT": "#90caf9"
        }
        self.current_theme = self.dark_theme

        self.i2c = i2c
        self.master = master
        master.title("Bison Configuration Tool")
        master.geometry("700x750")
        master.configure(bg=self.current_theme["BG"])

        font_label = ("Segoe UI", 11)
        font_entry = ("Segoe UI", 11)
        font_button = ("Segoe UI", 11, "bold")


        self.param_labels = [
            "Product", "Version", "Speed", "Ramp", "PID KP", "PID KI", "KPD IV", "KID IV",
            "KPD IV Log", "KID IV Log", "Hall Phase", "Speed Command", "Enable", "Rotation", "Open Loop", "OL Voltage Factor", "CRC Checksum"
        ]
        self.param_vars = {}

        param_frame = tk.LabelFrame(
            master, text="EEPROM Parameters", padx=15, pady=15,
            font=("Segoe UI", 12, "bold"),
            bg=self.current_theme["PANEL"], fg=self.current_theme["LABEL"], bd=2, relief="groove"
        )
        param_frame.pack(pady=20, padx=20, fill="x")

        for i, label in enumerate(self.param_labels):
            tk.Label(param_frame, text=label, font=font_label, bg=self.current_theme["PANEL"], fg=self.current_theme["LABEL"]).grid(
                row=i, column=0, sticky="e", padx=8, pady=4
            )
            var = tk.StringVar()
            entry = tk.Entry(param_frame, textvariable=var, width=22, font=font_entry,
                            bg=self.current_theme["ENTRY"], fg=self.current_theme["LABEL"], insertbackground=self.current_theme["LABEL"],
                            highlightbackground=self.current_theme["HIGHLIGHT"], highlightcolor=self.current_theme["HIGHLIGHT"], relief="flat")
            # Ensure CRC is read only for the user
            if label == "CRC Checksum":
                entry.configure(state="readonly")
            entry.grid(row=i, column=1, padx=8, pady=4)
            self.param_vars[label] = var

        button_frame = tk.Frame(master, bg=self.current_theme["BG"])
        button_frame.pack(pady=15)

        button_style = dict(
            font=font_button, bg=self.current_theme["BUTTON"], fg=self.current_theme["BUTTON_TEXT"],
            activebackground=self.current_theme["BUTTON_ACTIVE"], activeforeground=self.current_theme["BUTTON_TEXT"],
            relief="flat", bd=1, padx=12, pady=6, cursor="hand2"
        )

        self.read_button = tk.Button(button_frame, text="Read EEPROM", command=self.read_eeprom, **button_style)
        self.read_button.pack(side="left", padx=8)

        self.write_button = tk.Button(button_frame, text="Write EEPROM", command=self.write_eeprom, **button_style)
        self.write_button.pack(side="left", padx=8)

        self.save_button = tk.Button(button_frame, text="Save to File", command=self.save_to_file, **button_style)
        self.save_button.pack(side="left", padx=8)

        self.load_button = tk.Button(button_frame, text="Load from File", command=self.load_from_file, **button_style)
        self.load_button.pack(side="left", padx=8)

        self.param_frame = param_frame
        self.button_frame = button_frame

        output_frame = tk.LabelFrame(
            master, text="EEPROM Raw Data", padx=10, pady=10,
            font=("Segoe UI", 11, "bold"), bg=self.current_theme["PANEL"], fg=self.current_theme["LABEL"], bd=2, relief="groove"
        )
        output_frame.pack(pady=10, padx=20, fill="both", expand=True)
        self.output_frame = output_frame

        self.theme_button = tk.Button(self.button_frame, text="Toggle Dark/Light Mode", command=self.toggle_theme, **button_style)
        self.theme_button.pack(side="left", padx=8)

        self.output_text = tk.Text(
            output_frame, height=8, width=60, font=("Consolas", 10),
            bg=self.current_theme["ENTRY"], fg=self.current_theme["LABEL"], insertbackground=self.current_theme["LABEL"],
            highlightbackground=self.current_theme["HIGHLIGHT"], highlightcolor=self.current_theme["HIGHLIGHT"], relief="flat"
        )
        self.output_text.pack(fill="both", expand=True)
        self.apply_theme()

    # If the "read" button is selected, we get a read event
    def read_eeprom(self):
        try:
            print("Read button clicked")
            total_bytes = 52  # 48 data + 4 CRC
            chunk_size = 10
            addr = 64
            end_addr = addr + total_bytes
            all_data = []
            while addr < end_addr:
                to_read = min(chunk_size, end_addr - addr)
                print(f"Reading from addr={addr}, length={to_read}")
                data = self.i2c.read_data(addr, to_read)
                print(f"Data received: {data}")
                all_data.extend(data)
                addr += to_read

            # Pad with zeros if not enough data
            if len(all_data) < 52:
                all_data.extend([0] * (52 - len(all_data)))

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, ', '.join(str(b) for b in all_data))

            parsed_data = parse_data(all_data)
            segments = parsed_data.split()

            # Fill in fields, using blanks or zeros if missing
            # Product (12 bytes, ASCII)
            product_bytes = segments.get('block1_12', [0]*12)
            product_str = ''.join(chr(b) for b in product_bytes).rstrip('\x00')
            self.param_vars["Product"].set(product_str)

            # Version (10 bytes, ASCII)
            version_bytes = segments.get('block2_10', [0]*10)
            version_str = ''.join(chr(b) for b in version_bytes).rstrip('\x00')
            self.param_vars["Version"].set(version_str)

            # 2-byte fields (speed, ramp, pid_kp, pid_ki, kpdiv, kidiv, kpdiv_log, kidiv_log, hall phase)
            block3_2s = segments.get('block3_2s', [[0, 0]]*9)
            for i, label in enumerate(["Speed", "Ramp", "PID KP", "PID KI", "KPD IV", "KID IV", "KPD IV Log", "KID IV Log", "Hall Phase"]):
                val = int.from_bytes(block3_2s[i], byteorder='little', signed=False)
                self.param_vars[label].set(val)

            block4_4 = segments.get('block4_4', [0]*4)
            speed_command_val = int.from_bytes(block4_4, byteorder='little', signed=False)
            self.param_vars["Speed Command"].set(speed_command_val)

            # Enable, Rotation, Open Loop: 1 byte each (from block5_1s)
            block5_1s = segments.get('block5_1s', [0]*3)
            for i, label in enumerate(["Enable", "Rotation", "Open Loop"]):
                self.param_vars[label].set(block5_1s[i])

            # OL Voltage Factor: 1 byte (last byte)
            ol_voltage_factor = segments.get('ol_voltage_factor', 0)
            self.param_vars["OL Voltage Factor"].set(ol_voltage_factor)
            print("READING:")
            print(f"Data for CRC (first 10): {[hex(b) for b in all_data[:10]]}")
            print(f"Data for CRC (last 10): {[hex(b) for b in all_data[38:48]]}")
            crc_calc = binascii.crc32(bytes(all_data[:48]), 0xFFFFFFFF) & 0xFFFFFFFF
            print(f"Calculated CRC: 0x{crc_calc:08X}")
            # CRC Checksum: 4 bytes 
            crc_bytes = all_data[48:52]
            crc_stored = int.from_bytes(crc_bytes, byteorder='little')  # No reverse!
            self.param_vars["CRC Checksum"].set(f"0x{crc_stored:08X}")

            # Optionally, check CRC and display in output_text
            crc_calc = binascii.crc32(bytes(all_data[:48]), 0xFFFFFFFF) & 0xFFFFFFFF
            self.output_text.insert(tk.END, f"\nStored CRC32: 0x{crc_stored:08X}")
            self.output_text.insert(tk.END, f"\nCalc'd CRC32: 0x{crc_calc:08X}")
            if crc_stored == crc_calc:
                self.output_text.insert(tk.END, "\nCRC OK")
            else:
                self.output_text.insert(tk.END, "\nCRC MISMATCH")

        except Exception as e:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Read Error", f"{e}")
    # If the "write" button is selected, we get a write event
    def write_eeprom(self):
        try:
            values = []
            # Product: 12 bytes, ASCII
            product = self.param_vars["Product"].get().encode("ascii", errors="replace")[:12]
            product += b'\x00' * (12 - len(product))
            values.extend(product)

            # Version: 10 bytes, ASCII
            version = self.param_vars["Version"].get().encode("ascii", errors="replace")[:10]
            version += b'\x00' * (10 - len(version))
            values.extend(version)

            # 9 fields, 2 bytes each
            for label in ["Speed", "Ramp", "PID KP", "PID KI", "KPD IV", "KID IV", "KPD IV Log", "KID IV Log", "Hall Phase"]:
                val_str = self.param_vars[label].get()
                try:
                    val = int(val_str)
                except (ValueError, TypeError):
                    val = 0
                values.extend(val.to_bytes(2, byteorder='little', signed=False))

            # Speed Command: 4 bytes
            val_str = self.param_vars["Speed Command"].get()
            try:
                val = int(val_str)
            except (ValueError, TypeError):
                val = 0
            values.extend(val.to_bytes(4, byteorder='little', signed=False))

            # Enable, Rotation, Open Loop: 1 byte each
            for label in ["Enable", "Rotation", "Open Loop"]:
                val_str = self.param_vars[label].get()
                try:
                    val = int(val_str)
                except (ValueError, TypeError):
                    val = 0
                values.append(val & 0xFF)

            # OL Voltage Factor: 1 byte (new field at the end)
            val_str = self.param_vars["OL Voltage Factor"].get()
            try:
                val = int(val_str)
            except (ValueError, TypeError):
                val = 0
            values.append(val & 0xFF)

            # Ensure the total length is 48 bytes
            if len(values) != 48:
                raise ValueError(f"Data length is {len(values)}, expected 48 bytes.")

            # Calculate CRC32 (STM32 style)
            crc_val = binascii.crc32(bytes(values), 0xFFFFFFFF) & 0xFFFFFFFF
            crc_bytes = crc_val.to_bytes(4, byteorder='little')
            values.extend(crc_bytes)  # No reverse!

            self.i2c.write_data(values, 64)
           
            messagebox.showinfo("Write Success", "Data written successfully.")
        except Exception as e:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Write Error", str(e))

    def stm32_crc32(self, data_bytes):
        """
        Calculate CRC32 as STM32 hardware CRC peripheral does (default settings).
        :param data_bytes: bytes or bytearray
        :return: 32-bit CRC as unsigned int
        """
        # STM32 starts with 0xFFFFFFFF and does NOT invert the result
        crc = binascii.crc32(data_bytes, 0xFFFFFFFF)
        return crc & 0xFFFFFFFF

    def save_to_file(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not file_path:
                return  # User cancelled

            with open(file_path, "w") as f:
                for label in self.param_labels:
                    value = self.param_vars[label].get()
                    f.write(f"{label}: {value}\n")
            messagebox.showinfo("Save Success", f"Parameters saved to {file_path}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Save Error", str(e))

    def toggle_theme(self):
        self.current_theme = self.light_theme if self.current_theme == self.dark_theme else self.dark_theme
        self.apply_theme()

    def apply_theme(self):
        theme = self.current_theme
        self.master.configure(bg=theme["BG"])
        self.param_frame.configure(bg=theme["PANEL"], fg=theme["LABEL"])
        for child in self.param_frame.winfo_children():
            if isinstance(child, tk.Label):
                child.configure(bg=theme["PANEL"], fg=theme["LABEL"])
            elif isinstance(child, tk.Entry):
                child.configure(
                    bg=theme["ENTRY"], fg=theme["LABEL"], insertbackground=theme["LABEL"],
                    highlightbackground=theme["HIGHLIGHT"], highlightcolor=theme["HIGHLIGHT"]
                )
        self.button_frame.configure(bg=theme["BG"])
        for btn in [self.read_button, self.write_button, self.save_button, self.load_button, self.theme_button]:
            btn.configure(
                bg=theme["BUTTON"], fg=theme["BUTTON_TEXT"],
                activebackground=theme["BUTTON_ACTIVE"], activeforeground=theme["BUTTON_TEXT"]
            )
        self.output_frame.configure(bg=theme["PANEL"], fg=theme["LABEL"])
        self.output_text.configure(
            bg=theme["ENTRY"], fg=theme["LABEL"], insertbackground=theme["LABEL"],
            highlightbackground=theme["HIGHLIGHT"], highlightcolor=theme["HIGHLIGHT"]
        )

    def load_from_file(self):
        try:
            file_path = filedialog.askopenfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not file_path:
                return  # User cancelled

            with open(file_path, "r") as f:
                for line in f:
                    if ':' not in line:
                        continue
                    label, value = line.strip().split(':', 1)
                    label = label.strip()
                    value = value.strip()
                    if label in self.param_vars:
                        self.param_vars[label].set(value)
            messagebox.showinfo("Load Success", f"Parameters loaded from {file_path}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Load Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    device_url = 'ftdi://ftdi:0x6014:FTUDGLGE/1'
    eeprom_address = 0x50
    print("About to initialize I2CHandler")
    try:
        i2c = I2CHandler(device_url, eeprom_address)
        print("I2CHandler initialized")
    except Exception as e:
        tk.messagebox.showerror("I2C Error", f"Failed to initialize I2CHandler:\n{e}")
        root.destroy()
        raise
    app = EEPROMGUI(i2c, root)
    root.mainloop()
