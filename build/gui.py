from pathlib import Path
from tkinter import *
from tkinter import ttk, filedialog
from mac_vendor_lookup import MacLookup # type: ignore
from scapy.all import sniff, wrpcap, ARP
import threading
from datetime import datetime

class PlaceholderEntry(Entry):
    def __init__(self, master=None, placeholder="PLACEHOLDER", color="grey", *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = self["fg"]
        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._add_placeholder)
        self._add_placeholder()

    def _clear_placeholder(self, event=None):
        if self["fg"] == self.placeholder_color:
            self.delete(0, "end")
            self["fg"] = self.default_fg_color

    def _add_placeholder(self, event=None):
        if not self.get():
            self.insert(0, self.placeholder)
            self["fg"] = self.placeholder_color

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"/home/kali/Desktop/packet-sniffer-and-network-analyzer/build/assets/frame0")


def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)

def get_vendor_from_mac(mac_address):
    try:
        vendor = MacLookup().lookup(mac_address)
        return vendor
    except Exception as e:
        return ""


window = Tk()
window.title("Packet Sniffer And Traffic Analyzer")

window.geometry("1200x800")
window.configure(bg = "#FFFFFF")

interface_options = ["eth0"]
selected_interface_option = StringVar()
selected_interface_option.set(interface_options[0])
captured_packets = []
stop_tracker = True
ip_mac = {}
font_style = "Georgia"
font_size = 10


canvas = Canvas(window,bg = "#FFFFFF",height = 800,width = 1200,bd = 0,highlightthickness = 0,relief = "ridge")
canvas.place(x = 0, y = 0)
canvas.create_rectangle(0.0,0.0,218.0,800.0,fill="#D9D9D9",outline="")
canvas.create_text(44.0,36.0,anchor="nw",text="Packet Sniffer\nAnd Traffic Analyzer",fill="#000000",font=(font_style, font_size, "bold"))

canvas.create_text(20.0,98.0,anchor="nw",text="Interface",fill="#000000",font=(font_style, font_size))
interface = OptionMenu(window,selected_interface_option,*interface_options  )
interface.config(bd=0,bg="#D9D9D9",fg="#000716",highlightthickness=0, font=(font_style, font_size))
interface.place(x=83.0,y=99.0,width=108.0,height=20.0)
entry_image_1 = PhotoImage(file=relative_to_assets("entry_1.png"))
entry_bg_1 = canvas.create_image(137.0,110.0,image=entry_image_1)



canvas.create_text(20.0,138.0,anchor="nw",text="Count",fill="#000000",font=(font_style, font_size))
count = Entry(bd=0,bg="#D9D9D9",fg="#000716",highlightthickness=0)
count.place(x=83.0,y=139.0,width=108.0,height=20.0)
entry_image_2 = PhotoImage(file=relative_to_assets("entry_2.png"))
entry_bg_2 = canvas.create_image(137.0,150.0,image=entry_image_2)

filter = PlaceholderEntry(bd=0,bg="#D9D9D9",fg="#000716",highlightthickness=0, placeholder="Enter BPF Filter (Optional)..")
filter.place(x=231.0,y=25.0,width=942.0,height=25.0)



# Packet Summary Display

def on_frame_configure(event):
    packet_summary_canvas.configure(scrollregion=packet_summary_canvas.bbox("all"))

canvas.create_rectangle(231.0,65.0,783.0,365.0,fill="#D9D9D9",outline="")
packet_summary_frame = Frame(window, bg="#D9D9D9")
packet_summary_frame.place(x=231.0,y=65.0,width=942.0,height=400.0)
packet_summary_scrollbar = Scrollbar(packet_summary_frame, orient="vertical")
packet_summary_scrollbar.pack(side="right", fill="y")
packet_summary_canvas = Canvas(packet_summary_frame, bg="#D9D9D9", yscrollcommand=packet_summary_scrollbar.set)
packet_summary_canvas.pack(side="left", fill="both", expand=True)
packet_summary_scrollbar.config(command=packet_summary_canvas.yview)
packet_summary_inner_frame = Frame(packet_summary_canvas, bg="#D9D9D9")
packet_summary_canvas.create_window((0, 0), window=packet_summary_inner_frame, anchor="nw")
packet_summary_inner_frame.bind("<Configure>", on_frame_configure)
packet_summary_frame = packet_summary_inner_frame

# Packet Details
canvas.create_rectangle(231.0,484.0,692.0,788.0,fill="#D9D9D9",outline="")
frame3 = Frame(window)
frame3.place(x=231.0,y=484.0,width=461.0,height=304.0)
detailed_packet_view = Text(frame3, wrap="word", height=5, width=30, font=(font_style, font_size))
detailed_packet_view.pack(side="left", fill="both", expand=True)
scrollbar3 = Scrollbar(frame3, command=detailed_packet_view.yview)
scrollbar3.pack(side="right", fill="y")
detailed_packet_view.insert(END, "Click on packet to view details")
detailed_packet_view.tag_add("place_holder_msg", "1.0", "1.end")
detailed_packet_view.tag_config("place_holder_msg", font=(font_style, font_size, "bold"), foreground="black")
detailed_packet_view.config(yscrollcommand=scrollbar3.set)
detailed_packet_view.config(state="disabled")

# IP_MAC mapping
canvas.create_rectangle(711.0,484.0,1172.0,788.0,fill="#D9D9D9",outline="")
frame1 = Frame(window)
frame1.place(x=711.0,y=484.0,width=461.0,height=304.0)
ip_mac_mapping = Text(frame1, wrap="word", height=5, width=30, font=(font_style, font_size))
ip_mac_mapping.pack(side="left", fill="both", expand=True)
scrollbar1 = Scrollbar(frame1, command=ip_mac_mapping.yview)
scrollbar1.pack(side="right", fill="y")
ip_mac_mapping.config(yscrollcommand=scrollbar1.set)
ip_mac_mapping.insert(END,  "Start sniffer to detect attacks" + "\n\n")
ip_mac_mapping.tag_add("status", "1.0", "1.end")
ip_mac_mapping.tag_config("status", font=(font_style, font_size, "bold"), foreground="black")
ip_mac_mapping.config(yscrollcommand=scrollbar1.set)
ip_mac_mapping.config(state="disabled")


def update_ip_mac_mapping():

    # Clear the Text widget
    ip_mac_mapping.config(state="normal")
    ip_mac_mapping.delete(1.0, END)

    # Track if any ARP attacks are detected
    attack_detected = False

    # Check for ARP attacks (multiple MACs for an IP)
    for ip, mac_set in ip_mac.items():
        if len(mac_set) > 1:
            attack_detected = True
            break

    # Add a status message at the top
    if attack_detected:
        status_message = "Status: ARP attack detected: Multiple MAC addresses associated with an IP!"
        ip_mac_mapping.insert(END, status_message + "\n\n")
        ip_mac_mapping.tag_add("status", "1.0", "1.end")
        ip_mac_mapping.tag_config("status", font=(font_style, font_size, "bold"), foreground="red")
    else:
        status_message = "Status: No ARP attacks detected."
        ip_mac_mapping.insert(END, status_message + "\n\n")
        ip_mac_mapping.tag_add("status", "1.0", "1.end")
        ip_mac_mapping.tag_config("status", font=(font_style, font_size, "bold"), foreground="green")

    # Prepare the header and separator for the table
    table_header = f"{'IP Address':<20} {'MAC Address':<20} {'Vendor':<20}\n"
    table_separator = "-" * 80 + "\n"

    # Insert the header and separator
    ip_mac_mapping.insert(END, table_header)
    ip_mac_mapping.insert(END, table_separator)

    # Populate the table with IP-MAC mappings
    for ip, mac_set in ip_mac.items():
        for mac in mac_set:
            vendor = get_vendor_from_mac(mac)  # Function to fetch vendor details from MAC
            row_text = f"{ip:<20} {mac:<20} {vendor:<20}\n"
            ip_mac_mapping.insert(END, row_text)

            # Highlight duplicate MAC addresses in red
            if len(mac_set) > 1:
                ip_mac_mapping.tag_add(f"ip_{ip}", f"{ip_mac_mapping.index('end')}-2l", f"{ip_mac_mapping.index('end')}-1l")
                ip_mac_mapping.tag_config(f"ip_{ip}", foreground="red")

    ip_mac_mapping.config(font=(font_style, font_size))
    ip_mac_mapping.config(state="disabled")



def process_packet(packet):
    """
    Handle incoming packets and create a clickable Label for each packet summary.
    """
    # Create a new Label for the packet summary
    packet_summary_label = Label(
        packet_summary_frame,
        text=packet.summary()[:1000],
        bg="#D9D9D9",
        fg="#000716",
        justify="left",
        anchor='w',
        font=(font_style, font_size)
    )
    packet_summary_label.pack(anchor='w', fill='x')

    # Bind a click event to show detailed packet information
    def show_packet_details(event):
        detailed_packet_view.config(state="normal", font=(font_style, font_size))
        detailed_packet_view.delete(1.0, END)
        detailed_packet_view.insert(END, str(packet.show(dump=True)))
        detailed_packet_view.config(state="disabled")

    packet_summary_label.bind("<Button-1>", show_packet_details)
    packet_summary_canvas.yview_scroll(1000, "units")  # Scroll down by 1 unit
    packet_summary_canvas.config(scrollregion=packet_summary_canvas.bbox("all"))
    captured_packets.append(packet)


    if(packet.haslayer(ARP)):
        arp_layer = packet[ARP]
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc
        if(arp_layer.op == 2):
            if  ip in ip_mac:
                prev = len(ip_mac[ip])
                ip_mac[ip].add(mac)
                if(len(ip_mac[ip]) != prev):
                    update_ip_mac_mapping()
            else:
                ip_mac[ip] = set()
                ip_mac[ip].add(mac)
                update_ip_mac_mapping()


def stop_sniffing(packet):
    return stop_tracker

def is_valid_bpf_filter(bpf_filter: str) -> bool:
    try:
        sniff(filter=bpf_filter, count=1, timeout=0.1)
        return True
    except Exception as e:
        print(f"Invalid BPF filter. Filter set to `None`")
        return False


def start_sniffing():
    global stop_tracker
    stop_tracker = False

    ip_mac_mapping.config(state="normal")
    ip_mac_mapping.delete(1.0, END)
    ip_mac_mapping.insert(END, "Status : No ARP attacks detected." + "\n\n")
    ip_mac_mapping.tag_add("status", "1.0", "1.end")
    ip_mac_mapping.tag_config("status", font=(font_style, font_size, "bold"), foreground="green")
    ip_mac_mapping.config(state="disabled")

    interface_selected = selected_interface_option.get()
    
    packet_count = count.get()
    if(packet_count == "" or (not str.isdigit(packet_count))):
        packet_count = 0
    packet_count = int(packet_count)



    bpf_filter = filter.get()
    if(bpf_filter == "Enter BPF Filter (Optional).."):
        bpf_filter = None
    elif(not is_valid_bpf_filter(bpf_filter)):
        bpf_filter = None
    print("Sniffer Started")
    sniff(iface=interface_selected, prn=process_packet, stop_filter=stop_sniffing, filter=bpf_filter, count=packet_count)
    print("Sniffer Stopped")

def on_start_sniff():
    if(stop_tracker == True):
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()

def on_stop_sniff():
    global stop_tracker
    if(stop_tracker == False):
        stop_tracker = True

def on_click_export_as_txt():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S%f")
    filename = f"packets_{timestamp}"
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             initialfile=filename,
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            for packet in captured_packets:
                file.write(repr(packet) + "\n\n")  
        print(f"Data exported successfully to {file_path}")

def on_click_export_as_pcap():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S%f")
    filename = f"packets_{timestamp}"
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                             initialfile=filename,
                                             filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if file_path:
        for packet in captured_packets:
            wrpcap(file_path, packet, append=True)
        print(f"Data exported successfully to {file_path}")

style = ttk.Style()
style.configure("RoundedButton.TButton",
                borderwidth=2,
                relief="solid",  # Visible border line
                highlightthickness=0,
                font=(font_style, font_size),
                foreground="#000716",
                background="#D9D9D9",
                )

start_sniff = ttk.Button(text="Start", command=on_start_sniff, style="RoundedButton.TButton")
start_sniff.place(x=20.0,y=225.0,width=82.0,height=48.0)

stop_sniff = ttk.Button(text="Stop", command=on_stop_sniff, style="RoundedButton.TButton")
stop_sniff.place(x=119.0,y=225.0,width=82.0,height=48.0)

stop_sniff = ttk.Button(text="Stop", command=on_stop_sniff, style="RoundedButton.TButton")
stop_sniff.place(x=119.0,y=225.0,width=82.0,height=48.0)

export_txt_button = ttk.Button(text="Export as .txt", command=on_click_export_as_txt, style="RoundedButton.TButton")
export_txt_button.place(x = 48.0, y=667.0,width=122.0,height=48.0)

export_txt_button = ttk.Button(text="Export as .pcap", command=on_click_export_as_pcap, style="RoundedButton.TButton")
export_txt_button.place(x = 48.0, y=725.0,width=122.0,height=48.0)

window.resizable(False, False)
window.mainloop()
