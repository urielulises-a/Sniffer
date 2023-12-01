import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, Ether
import socket

class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.geometry("800x600")
        self.root.title("Packet Sniffer")

        self.create_widgets()

    def create_widgets(self):
        self.frame = ttk.Frame(self.root)
        self.frame.grid(row=0, column=0, padx=10, pady=10)

        ttk.Label(self.frame, text="Número de Paquetes:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.packet_count_entry = ttk.Entry(self.frame)
        self.packet_count_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

        ttk.Label(self.frame, text="Número de Paquete Específico:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.specific_packet_entry = ttk.Entry(self.frame)
        self.specific_packet_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)

        self.result_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, width=50, height=20)
        self.result_text.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)

        self.specific_packet_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, width=50, height=20)
        self.specific_packet_text.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)

        ttk.Button(self.frame, text="Iniciar Sniffer", command=self.start_sniffing).grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Label(self.frame, text="Todas las IPs").grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
        self.all_ips_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, width=50, height=10)
        self.all_ips_text.grid(row=5, column=0, padx=10, pady=10, sticky=tk.W, columnspan=2)

    def start_sniffing(self):
        try:
            packet_count = int(self.packet_count_entry.get())
            specific_packet = int(self.specific_packet_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Por favor, ingrese números válidos.")
            return

        if packet_count <= 0 or specific_packet < -1:
            messagebox.showerror("Error", "Por favor, ingrese valores válidos para el número de paquetes y el número de paquete específico.")
            return

        all_packets = []
        all_ips = set()

        def packet_callback(packet):
            nonlocal all_packets, all_ips

            try:
                # Mostrar información detallada en la interfaz principal
                packet_info = ""
                if packet.haslayer(IP):
                    packet_info += f"\n\n********Capa de Red********\n\n{packet[IP].show(dump=True)}"
                    all_ips.add(packet[IP].src)
                    all_ips.add(packet[IP].dst)

                    # Obtener y mostrar el nombre de host asociado a la dirección IP
                    try:
                        src_host = socket.gethostbyaddr(packet[IP].src)
                        dst_host = socket.gethostbyaddr(packet[IP].dst)
                        packet_info += f"\n\n********Nombre de Host********\n\nSource: {src_host[0]}, Destination: {dst_host[0]}\n\n"
                    except socket.herror:
                        pass

                if packet.haslayer(TCP): packet_info += f"\n\n********Capa de Transporte********\n\n{packet[TCP].show(dump=True)}\n\n"
                if packet.haslayer(UDP): packet_info += f"\n\n********Capa de Transporte********\n\n{packet[UDP].show(dump=True)}\n\n"
                if packet.haslayer(Ether): packet_info += f"\n\n********Capa de Enlace de Datos********\n\n{packet[Ether].show(dump=True)}\n\n"

                self.result_text.insert(tk.END, packet_info)
                self.result_text.see(tk.END)

                # Almacenar información para secciones adicionales
                all_packets.append(packet.summary())
            except Exception as e:
                messagebox.showerror("Error", f"Error al procesar el paquete: {e}")

        try:
            packets = sniff(count=packet_count)
        except Exception as e:
            messagebox.showerror("Error", f"Error al iniciar el sniffer: {e}")
            return

        for i, packet in enumerate(packets, start=1):
            try:
                packet_callback(packet)

                # Mostrar el paquete específico en la sección correspondiente
                if i == specific_packet:
                    specific_packet_info = f"{packet.summary()}\n\n"
                    if packet.haslayer(IP): specific_packet_info += f"\n\n********Capa de Red********\n\n{packet[IP].show(dump=True)}"
                    if packet.haslayer(TCP): specific_packet_info += f"\n\n********Capa de Transporte********\n\n{packet[TCP].show(dump=True)}\n\n"
                    if packet.haslayer(UDP): specific_packet_info += f"\n\n********Capa de Transporte********\n\n{packet[UDP].show(dump=True)}\n\n"
                    if packet.haslayer(Ether): specific_packet_info += f"\n\n********Capa de Enlace de Datos********\n\n{packet[Ether].show(dump=True)}\n\n"

                    self.specific_packet_text.insert(tk.END, specific_packet_info)
                    self.specific_packet_text.see(tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Error al procesar el paquete {i}: {e}")

        # Mostrar todos los paquetes en la sección correspondiente
        self.all_ips_text.insert(tk.END, "\n".join(all_ips))
        self.all_ips_text.see(tk.END)

def main():
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()

if __name__ == '__main__':
    main()
